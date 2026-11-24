-- ADR 0044, proxy increment 3a: a dispatched request that ends without usage is closed by a
-- final usage report that says why. Until now such a request kept its hold: the only final
-- report the fold acted on was one with both token counts, and a final report without counts
-- marked the request settled while its hold stayed in place.

-- `incomplete` is the one place the reason is stored. A report that carries it is final. The
-- vocabulary is closed and has two groups, so the database can tell them apart by value:
--   * nothing was sent upstream: `model_not_served`, `model_mismatch`, `request_body`,
--     `upstream_connect`;
--   * the request was or may have been sent upstream and its usage is unknown: every other
--     reason.
-- The gateway role writes the column with the rest of the report.
ALTER TABLE openmettle.gateway_usage_reports
    ADD COLUMN incomplete text,
    ADD CONSTRAINT gateway_usage_reports_incomplete_check CHECK (
        incomplete IS NULL OR (final AND incomplete IN (
            'model_not_served','model_mismatch','request_body','upstream_connect',
            'upstream_transport','upstream_timeout','upstream_status','upstream_encoding',
            'incomplete','caller_disconnected','no_usage','unparsable')));
GRANT INSERT (incomplete) ON openmettle.gateway_usage_reports TO openmettle_gateway;

-- Migration 24's fold, with one more rule: a report that carries `incomplete` closes the hold.
-- It charges what the accepted reports measured so far, which is nothing when none carried a
-- count, and releases the rest. A later final report with counts still corrects the charge.
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
            settled:=greatest(settled,coalesce(measured,0));
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
