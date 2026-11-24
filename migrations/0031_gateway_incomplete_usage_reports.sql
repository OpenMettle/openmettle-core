-- ADR 0044, proxy increment 3a: a dispatched request that ends without usage is closed by a
-- final usage report that says why. Until now such a request kept its hold: the only final
-- report the fold acted on was one with both token counts, and a final report without counts
-- marked the request settled while its hold stayed in place.

-- `incomplete` is the one place the reason is stored. A report that carries it is final and
-- carries no count, cost or unit of its own: a reason next to usage would contradict it. The
-- vocabulary is closed and has two groups, so the database can tell them apart by value:
--   * nothing was sent upstream: `model_not_served`, `model_mismatch`, `request_body`,
--     `upstream_connect`;
--   * the request was or may have been sent upstream and its usage is unknown: every other
--     reason.
-- The gateway role writes the column with the rest of the report.
ALTER TABLE openmettle.gateway_usage_reports
    ADD COLUMN incomplete text,
    ADD CONSTRAINT gateway_usage_reports_incomplete_check CHECK (
        incomplete IS NULL OR (final
            AND num_nonnulls(prompt_tokens,completion_tokens,reasoning_tokens,
                             reasoning_included,cost,unit) = 0
            AND incomplete IN (
            'model_not_served','model_mismatch','request_body','upstream_connect',
            'upstream_transport','upstream_timeout','upstream_status','upstream_encoding',
            'incomplete','caller_disconnected','no_usage','unparsable')));
GRANT INSERT (incomplete) ON openmettle.gateway_usage_reports TO openmettle_gateway;

-- Migration 24's fold, with one more rule: a report that carries `incomplete` closes the hold.
-- It adds no charge of its own: the hold settles at what earlier accepted reports measured,
-- which is nothing when none carried a count, and the rest is released. A later final report
-- with counts still corrects the charge.
-- This is the only place that decides the charge. It applies one rule to every reason; a
-- different charge for the reasons of the second group is a change to the `incomplete` branch
-- alone (ADR 0044, amendment of 24 November 2026: the owner decided this rule for now, to be
-- revisited).
-- The signature, volatility, search path and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.quota_gateway_fold(p_request uuid,p_kind text,p_units bigint,p_through bigint)
RETURNS TABLE(rev bigint,source uuid,report uuid,state text,settled numeric,held bigint)
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE
    step record; prompt numeric:=0; completion numeric:=0; reasoning numeric:=0;
    included boolean:=true; separate_seen boolean:=false; last_k bigint:=-1; last_r bigint:=-1;
    measured numeric; complete boolean;
BEGIN
    state:='handoff_committed'; settled:=0; held:=p_units;
    FOR step IN SELECT g.* FROM openmettle.quota_accepted_gateway_reports a
        JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
        WHERE a.request_id=p_request AND a.revision<=p_through ORDER BY a.revision
    LOOP
        rev:=step.revision; source:=step.source; report:=step.report_id;
        IF p_kind='usage_cost_micros' THEN
            measured:=ceil(step.cost); complete:=step.cost IS NOT NULL;
        ELSE
            IF step.prompt_tokens IS NOT NULL THEN prompt:=step.prompt_tokens; END IF;
            IF step.completion_tokens IS NOT NULL THEN completion:=step.completion_tokens; last_k:=rev; END IF;
            IF step.reasoning_tokens IS NOT NULL THEN
                reasoning:=step.reasoning_tokens; included:=step.reasoning_included; last_r:=rev;
                separate_seen:=separate_seen OR NOT included;
            END IF;
            complete:=step.prompt_tokens IS NOT NULL AND step.completion_tokens IS NOT NULL
                AND (step.reasoning_tokens IS NOT NULL OR NOT separate_seen);
            measured:=CASE WHEN num_nonnulls(step.prompt_tokens,step.completion_tokens,step.reasoning_tokens)=0 THEN NULL
                WHEN NOT included THEN prompt+completion+reasoning
                WHEN last_r>=last_k THEN prompt+greatest(reasoning,completion)
                ELSE prompt+completion END;
        END IF;
        IF step.incomplete IS NOT NULL THEN
            state:='settled'; held:=0;
        ELSIF measured IS NOT NULL THEN
            settled:=CASE WHEN complete THEN measured ELSE greatest(measured,settled) END;
            IF complete AND step.final THEN state:='settled'; END IF;
            held:=CASE WHEN state='settled' THEN 0 ELSE greatest(0,p_units-settled)::bigint END;
        END IF;
        RETURN NEXT;
    END LOOP;
END
$$;

-- The rules the settlement library applies, enforced for every writer that holds the gateway
-- role's grants. They are checked at commit, because a settlement is written before its quota
-- fold runs in the same transaction.
--   * No accepted report with a reason may settle a request this proxy did not dispatch:
--     the request must have no binding and `dispatched_at` set. A request handed off under
--     ADR 0037 has none to give.
--   * A final settlement of a request without a binding must close it: the fold of its accepted
--     reports ends `settled`, and its token hold, when it has one, is `settled` too. A final
--     report without both counts and without a reason does not, also when its one count empties
--     the hold; neither does a settlement whose quota fold was never run. Accepted, either
--     would mark the request settled, hide it from the scan of outstanding requests and keep
--     the hold. When any accepted report carries a reason, any cost hold is `settled` too;
--     otherwise a cost hold is left unchecked, because a report with usage carries no cost
--     (issue #166).
-- A request handed off with a binding keeps migration 23's behaviour.
CREATE FUNCTION openmettle.enforce_gateway_final_settlement_closes() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
    latest openmettle.gateway_settlements%ROWTYPE;
    has_reason boolean;
    folded text;
BEGIN
    -- The final settlement as the transaction leaves it; accepted reasons are checked across
    -- every accepted revision of the request.
    SELECT * INTO latest FROM openmettle.gateway_settlements s WHERE s.request_id=NEW.request_id;
    IF NOT FOUND OR NOT latest.final THEN RETURN NULL; END IF;
    SELECT * INTO STRICT req FROM openmettle.gateway_requests q WHERE q.id=latest.request_id;
    SELECT EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
         WHERE a.request_id=latest.request_id AND g.incomplete IS NOT NULL
    ) INTO has_reason;
    IF has_reason AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NULL) THEN
        RAISE EXCEPTION 'an incomplete report needs a dispatched request without a binding'
            USING ERRCODE='23514';
    END IF;
    IF req.binding_id IS NOT NULL THEN RETURN NULL; END IF;
    SELECT f.state INTO folded
      FROM openmettle.quota_gateway_fold(latest.request_id,'usage_tokens',req.units,latest.revision) f
     ORDER BY f.rev DESC LIMIT 1;
    IF folded IS DISTINCT FROM 'settled' OR EXISTS (
        SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=latest.request_id
           AND h.state<>'settled'
           AND (h.resource_kind='usage_tokens'
                OR (has_reason AND h.resource_kind='usage_cost_micros'))) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_final_settlement_closes() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER gateway_final_settlement_closes
    AFTER INSERT OR UPDATE ON openmettle.gateway_settlements
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.final)
    EXECUTE FUNCTION openmettle.enforce_gateway_final_settlement_closes();
