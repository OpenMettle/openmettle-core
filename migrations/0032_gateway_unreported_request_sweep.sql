-- ADR 0044, proxy increment 3b: a bounded worker sweep closes handed-off requests without a
-- binding that the proxy cannot report:
--   * never dispatched (`dispatched_at IS NULL`) once `gateway_dispatch` can no longer grant
--     them (`not_dispatched`, Group 1 — nothing was sent upstream);
--   * dispatched (`dispatched_at IS NOT NULL`) with no settlement 15 minutes past the run's
--     execution deadline (`unreported`, Group 2 — the request was or may have been sent, and
--     its usage is unknown).
-- The sweep writes a final incomplete usage report at revision 0 and settles the request and
-- its quota holds through the existing settlement and fold mechanics, keeping `state =
-- 'handed_off'`. Revision 1 remains open for a late proxy report to supersede `unreported`.

-- Fail closed on upgrade if an unsettled unbound request already has an accepted revision-0
-- report or revision-0 settlement; historical schema 29–30 requests that already settled at
-- revision 0 (`settled_final = true`) stay intact.
DO $$
BEGIN
    IF EXISTS (
        SELECT FROM openmettle.gateway_requests q
         WHERE q.binding_id IS NULL
           AND NOT q.settled_final
           AND (EXISTS (SELECT FROM openmettle.gateway_settlements s
                         WHERE s.request_id = q.id AND s.revision = 0)
                OR EXISTS (SELECT FROM openmettle.quota_accepted_gateway_reports a
                            WHERE a.request_id = q.id AND a.revision = 0))
    ) THEN
        RAISE EXCEPTION 'migration 32 cannot proceed with an accepted revision-0 report on an unsettled unbound request'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- Remove unaccepted raw revision-0 reports on unbound unsettled requests so the sweep's
-- revision-0 insert cannot collide with a pre-existing dangling row after upgrade.
DELETE FROM openmettle.gateway_usage_reports g
 USING openmettle.gateway_requests q
 WHERE g.request_id = q.id
   AND q.binding_id IS NULL
   AND NOT q.settled_final
   AND g.revision = 0
   AND NOT EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = q.id)
   AND NOT EXISTS (
       SELECT FROM openmettle.quota_accepted_gateway_reports a
        WHERE a.request_id = q.id AND a.revision = 0
   );

-- Extend migration 31's closed vocabulary with the two sweep-only revision-0 reasons:
--   * Group 1 (nothing was sent upstream): `model_not_served`, `model_mismatch`,
--     `request_body`, `upstream_connect`, `not_dispatched`;
--   * Group 2 (the request was or may have been sent upstream and its usage is unknown):
--     `upstream_transport`, `upstream_timeout`, `upstream_status`, `upstream_encoding`,
--     `incomplete`, `caller_disconnected`, `no_usage`, `unparsable`, `unreported`.
ALTER TABLE openmettle.gateway_usage_reports
    DROP CONSTRAINT gateway_usage_reports_incomplete_check,
    ADD CONSTRAINT gateway_usage_reports_incomplete_check CHECK (
        incomplete IS NULL OR (final
            AND num_nonnulls(prompt_tokens,completion_tokens,reasoning_tokens,
                             reasoning_included,cost,unit) = 0
            AND (incomplete IN (
                'model_not_served','model_mismatch','request_body','upstream_connect',
                'upstream_transport','upstream_timeout','upstream_status','upstream_encoding',
                'incomplete','caller_disconnected','no_usage','unparsable')
                OR (revision = 0 AND incomplete IN ('not_dispatched','unreported')))));

-- Only `openmettle_owner` (and its `SECURITY DEFINER` sweep function) may write the two
-- sweep-only reasons or revision 0 on an unbound request; `openmettle_gateway` cannot forge
-- sweep reasons or occupy revision 0 to block the sweep. Bound ADR 0037 requests keep
-- revision 0 available to `openmettle_gateway`.
CREATE FUNCTION openmettle.enforce_gateway_report_sweep_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        RETURN NEW;
    END IF;
    IF NEW.incomplete IN ('not_dispatched', 'unreported') THEN
        RAISE EXCEPTION 'sweep-only incomplete reason requires openmettle_owner'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.revision = 0 AND EXISTS (
        SELECT FROM openmettle.gateway_requests q
         WHERE q.id = NEW.request_id AND q.binding_id IS NULL
    ) THEN
        RAISE EXCEPTION 'revision 0 on an unbound request requires openmettle_owner'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_report_sweep_only() FROM PUBLIC;
CREATE TRIGGER gateway_usage_reports_sweep_only_guard
    BEFORE INSERT OR UPDATE ON openmettle.gateway_usage_reports
    FOR EACH ROW
    WHEN (NEW.incomplete IN ('not_dispatched', 'unreported') OR NEW.revision = 0)
    EXECUTE FUNCTION openmettle.enforce_gateway_report_sweep_only();

-- Update migration 31's deferred final-settlement check for the two sweep reasons and
-- post-sweep revision-1 corrections:
--   * `not_dispatched` requires an undispatched request without a binding, at revision 0 only,
--     with no measured usage and no other accepted revision (a never-dispatched request can
--     never receive a proxy report).
--   * Every other incomplete reason (the 12 proxy reasons and `unreported`) requires a
--     dispatched request without a binding.
--   * On an unbound request, every accepted final report must carry either an incomplete
--     reason or both prompt and completion counts (so a bare or partial final report cannot
--     replace `unreported`), every quota hold must have folded `latest.revision`
--     (`accepted_source_revision = latest.revision`), `latest.outstanding` must be 0,
--     `quota_gateway_fold` must end `settled`, and its token hold (and any cost hold when any
--     accepted report carries a reason) must be `settled`.
-- Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.enforce_gateway_final_settlement_closes() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
    latest openmettle.gateway_settlements%ROWTYPE;
    has_not_dispatched boolean;
    has_other_reason boolean;
    has_reason boolean;
    folded text;
BEGIN
    SELECT * INTO latest FROM openmettle.gateway_settlements s WHERE s.request_id=NEW.request_id;
    IF NOT FOUND OR NOT latest.final THEN RETURN NULL; END IF;
    SELECT * INTO STRICT req FROM openmettle.gateway_requests q WHERE q.id=latest.request_id;
    SELECT EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
         WHERE a.request_id=latest.request_id AND g.incomplete='not_dispatched'
    ), EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
         WHERE a.request_id=latest.request_id AND g.incomplete IS NOT NULL
           AND g.incomplete<>'not_dispatched'
    ) INTO has_not_dispatched, has_other_reason;
    has_reason := has_not_dispatched OR has_other_reason;
    IF has_not_dispatched AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NOT NULL
        OR latest.revision<>0 OR latest.measured IS NOT NULL
        OR EXISTS (SELECT FROM openmettle.quota_accepted_gateway_reports a
                    WHERE a.request_id=latest.request_id AND a.revision<>0)) THEN
        RAISE EXCEPTION 'a not_dispatched report needs an undispatched request without a binding'
            USING ERRCODE='23514';
    END IF;
    IF has_other_reason AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NULL) THEN
        RAISE EXCEPTION 'an incomplete report needs a dispatched request without a binding'
            USING ERRCODE='23514';
    END IF;
    IF req.binding_id IS NOT NULL THEN RETURN NULL; END IF;
    IF EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
         WHERE a.request_id=latest.request_id AND a.final
           AND g.incomplete IS NULL
           AND (g.prompt_tokens IS NULL OR g.completion_tokens IS NULL)
    ) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE='23514';
    END IF;
    SELECT f.state INTO folded
      FROM openmettle.quota_gateway_fold(latest.request_id,'usage_tokens',req.units,latest.revision) f
     ORDER BY f.rev DESC LIMIT 1;
    IF latest.outstanding<>0 OR folded IS DISTINCT FROM 'settled' OR EXISTS (
        SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=latest.request_id
           AND (h.accepted_source_revision IS DISTINCT FROM latest.revision
                OR (h.state<>'settled'
                    AND (h.resource_kind='usage_tokens'
                         OR (has_reason AND h.resource_kind='usage_cost_micros'))))) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END
$$;

-- Index unbound outstanding handed-off requests for the worker sweep without touching bound
-- ADR 0037 rows.
CREATE INDEX gateway_requests_unbound_outstanding_idx
    ON openmettle.gateway_requests (created_at, id)
    WHERE state = 'handed_off' AND binding_id IS NULL AND NOT settled_final;

-- Bounded, cursor-paged candidate discovery for the worker sweep. Materializing at most
-- `p_limit` raw index entries first keeps every scan O(p_limit) and returns each key with its
-- `eligible` flag so callers advance the pass cursor across in-grace or still-live prefixes
-- without unbounded scans or head-of-line starvation. The fixed upper bound prevents a
-- continuous stream of arrivals from starving older rows across passes.
CREATE FUNCTION openmettle.gateway_unreported_candidates(
    p_after_created_at timestamptz,
    p_after_id uuid,
    p_upper_created_at timestamptz,
    p_upper_id uuid,
    p_limit integer)
RETURNS TABLE (created_at timestamptz, id uuid, eligible boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RAISE EXCEPTION 'gateway unreported sweep requires openmettle_worker' USING ERRCODE = '42501';
    END IF;
    IF p_after_created_at IS NULL OR p_after_id IS NULL
       OR p_upper_created_at IS NULL OR p_upper_id IS NULL
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'invalid gateway unreported page' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    WITH page AS MATERIALIZED (
        SELECT q.created_at, q.id, q.run_id, q.dispatched_at, q.claim_hash
          FROM openmettle.gateway_requests q
         WHERE q.state = 'handed_off'
           AND q.binding_id IS NULL
           AND NOT q.settled_final
           AND (q.created_at, q.id) > (p_after_created_at, p_after_id)
           AND (q.created_at, q.id) <= (p_upper_created_at, p_upper_id)
         ORDER BY q.created_at, q.id
         LIMIT p_limit
    ),
    clock AS MATERIALIZED (SELECT clock_timestamp() AS t)
    SELECT p.created_at,
           p.id,
           (NOT EXISTS (
                SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = p.id
            )
            AND (
                (p.dispatched_at IS NULL AND (
                    r.state <> 'running'
                    OR r.cancel_reason IS NOT NULL
                    OR r.claim_token IS NULL
                    OR sha256(uuid_send(r.claim_token)) <> p.claim_hash
                    OR r.lease_expires_at IS NULL
                    OR r.lease_expires_at <= clock.t
                    OR r.execution_expires_at IS NULL
                    OR r.execution_expires_at <= clock.t
                ))
                OR (p.dispatched_at IS NOT NULL AND
                    coalesce(r.execution_expires_at, a.resume_execution_expires_at, p.dispatched_at)
                        + interval '15 minutes' <= clock.t)
            )) AS eligible
      FROM page p
      JOIN openmettle.runs r ON r.id = p.run_id
      LEFT JOIN openmettle.run_approvals a ON a.id = r.approval_wait_id
      CROSS JOIN clock
     ORDER BY p.created_at, p.id;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_unreported_candidates(timestamptz,uuid,timestamptz,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_unreported_candidates(timestamptz,uuid,timestamptz,uuid,integer) TO openmettle_worker;

-- Close one eligible unbound handed-off request in its own short transaction so budget locks
-- are never held across multiple requests.
-- Lock order (ADR 0040 / ADR 0044):
--   1. openmettle.runs FOR SHARE SKIP LOCKED
--   2. openmettle.gateway_requests FOR UPDATE SKIP LOCKED
--   3. openmettle.quota_reservations (ORDER BY resource_kind, id FOR NO KEY UPDATE)
--   4. openmettle.quota_budgets (ORDER BY scope_id NULLS LAST, resource_kind, window_start, id)
-- Returns `'not_dispatched'`, `'unreported'`, or NULL when the request is ineligible, locked,
-- or already has a settlement.
CREATE FUNCTION openmettle.gateway_close_unreported(p_request uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_run uuid;
    r openmettle.runs%ROWTYPE;
    q openmettle.gateway_requests%ROWTYPE;
    v_deadline timestamptz;
    v_now timestamptz;
    v_reason text;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway unreported sweep requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RAISE EXCEPTION 'gateway unreported sweep requires openmettle_worker' USING ERRCODE = '42501';
    END IF;
    SELECT q0.run_id INTO v_run
      FROM openmettle.gateway_requests q0
     WHERE q0.id = p_request
       AND q0.state = 'handed_off'
       AND q0.binding_id IS NULL
       AND NOT q0.settled_final;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO r
      FROM openmettle.runs r0
     WHERE r0.id = v_run
       FOR SHARE SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO q
      FROM openmettle.gateway_requests q0
     WHERE q0.id = p_request
       AND q0.state = 'handed_off'
       AND q0.binding_id IS NULL
       AND NOT q0.settled_final
       FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = q.id) THEN
        RETURN NULL;
    END IF;
    v_now := clock_timestamp();
    IF q.dispatched_at IS NULL THEN
        IF r.state = 'running'
           AND r.cancel_reason IS NULL
           AND r.claim_token IS NOT NULL
           AND sha256(uuid_send(r.claim_token)) = q.claim_hash
           AND r.lease_expires_at > v_now
           AND r.execution_expires_at > v_now THEN
            RETURN NULL;
        END IF;
        v_reason := 'not_dispatched';
    ELSE
        v_deadline := coalesce(
            r.execution_expires_at,
            (SELECT a.resume_execution_expires_at
               FROM openmettle.run_approvals a
              WHERE a.id = r.approval_wait_id),
            q.dispatched_at
        );
        IF v_deadline + interval '15 minutes' > v_now THEN
            RETURN NULL;
        END IF;
        v_reason := 'unreported';
    END IF;
    INSERT INTO openmettle.gateway_usage_reports
        (request_id, source, report_id, revision, final, incomplete)
    VALUES (q.id, q.report_source, q.id, 0, true, v_reason);
    INSERT INTO openmettle.gateway_settlements
        (request_id, revision, final, measured, outstanding)
    VALUES (q.id, 0, true, NULL, 0);
    PERFORM openmettle.quota_settle_gateway_usage(q.id, q.report_source, q.id, 0);
    RETURN v_reason;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_close_unreported(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_close_unreported(uuid) TO openmettle_worker;
