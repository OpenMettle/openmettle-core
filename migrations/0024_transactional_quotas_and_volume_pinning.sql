-- ADR 0040. Runtime writers use bounded transitions on owner-managed quota ledgers.
ALTER TABLE openmettle.storage_instance
    ADD COLUMN warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    ADD COLUMN warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    ADD COLUMN config_revision bigint NOT NULL DEFAULT 1 CHECK (config_revision >= 1);

CREATE TABLE openmettle.storage_volume_control (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    volume_id uuid,
    bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false,
    adoption_run_id uuid,
    CONSTRAINT storage_volume_control_auto_pin_check
        CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed)
);
INSERT INTO openmettle.storage_volume_control (id) VALUES (true);
GRANT SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;

ALTER TABLE openmettle.storage_reservations
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN adoption_unverified boolean NOT NULL DEFAULT false,
    ADD COLUMN stage_claimed boolean NOT NULL DEFAULT false,
    ADD COLUMN payload_ino numeric(20, 0),
    ADD COLUMN publish_pending boolean NOT NULL DEFAULT false,
    ADD COLUMN reclaim_state text NOT NULL DEFAULT 'none'
        CONSTRAINT storage_reservations_reclaim_value_check CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink')),
    ADD COLUMN reclaim_claim_token uuid,
    ADD COLUMN reclaim_lease_until timestamptz,
    ADD CONSTRAINT storage_reservations_lease_check
        CHECK (lease_expires_at IS NULL OR lease_expires_at > created_at),
    ADD CONSTRAINT storage_reservations_adoption_unverified_check
        CHECK (NOT adoption_unverified OR state = 'reserved'),
    ADD CONSTRAINT storage_reservations_payload_ino_nonneg_check
        CHECK (payload_ino IS NULL OR payload_ino >= 0),
    ADD CONSTRAINT storage_reservations_stage_claimed_check
        CHECK (payload_ino IS NULL OR stage_claimed),
    ADD CONSTRAINT storage_reservations_publish_pending_check
        CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL)),
    ADD CONSTRAINT storage_reservations_reclaim_state_check
        CHECK (
            (state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated'))
            OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink'))
            OR (state = 'settled' AND reclaim_state = 'none')
        ),
    ADD CONSTRAINT storage_reservations_reclaim_lease_check
        CHECK (
            (reclaim_state IN ('claiming', 'truncated')
                AND reclaim_claim_token IS NOT NULL
                AND reclaim_lease_until IS NOT NULL)
            OR (reclaim_state IN ('none', 'anchor_pending_unlink')
                AND reclaim_claim_token IS NULL
                AND reclaim_lease_until IS NULL)
        ),
    ADD CONSTRAINT storage_reservations_reclaim_truncated_publish_check
        CHECK (reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending);

GRANT INSERT (lease_expires_at, stage_claimed)
    ON openmettle.storage_reservations TO openmettle_api, openmettle_worker;
GRANT UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino,
              publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)
    ON openmettle.storage_reservations TO openmettle_api, openmettle_worker;

CREATE INDEX storage_reservations_run_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL
      AND lease_expires_at IS NOT NULL AND NOT adoption_unverified
      AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%');
CREATE INDEX storage_reservations_run_legacy_expiry_idx
    ON openmettle.storage_reservations (created_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL
      AND lease_expires_at IS NULL AND NOT adoption_unverified
      AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%');
CREATE INDEX storage_reservations_upload_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NULL
      AND lease_expires_at IS NOT NULL AND NOT adoption_unverified;
CREATE INDEX storage_reservations_upload_legacy_expiry_idx
    ON openmettle.storage_reservations (created_at, id)
    WHERE state = 'reserved' AND run_id IS NULL
      AND lease_expires_at IS NULL AND NOT adoption_unverified;
CREATE INDEX storage_reservations_reclaim_anchor_idx
    ON openmettle.storage_reservations (closed_at, id)
    WHERE state = 'released' AND reclaim_state = 'anchor_pending_unlink';

ALTER TABLE openmettle.artifact_revisions
    ADD COLUMN purge_stage text NOT NULL DEFAULT 'none',
    ADD CONSTRAINT artifact_revisions_purge_stage_check
        CHECK (
            purge_stage IN ('none', 'anchor_pending_unlink')
            AND (purge_stage = 'none' OR state = 'purged')
        );
CREATE INDEX artifact_revisions_purge_anchor_idx
    ON openmettle.artifact_revisions (purged_at, id)
    WHERE state = 'purged' AND purge_stage = 'anchor_pending_unlink';
GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO openmettle_worker;

ALTER TABLE openmettle.gateway_settlements
    ALTER COLUMN measured TYPE numeric(38, 0);

CREATE TABLE openmettle.quota_accepted_gateway_reports (
    request_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 0),
    final boolean NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (request_id, revision),
    UNIQUE (request_id, revision, final),
    FOREIGN KEY (request_id, revision, final)
        REFERENCES openmettle.gateway_usage_reports (request_id, revision, final)
);
INSERT INTO openmettle.quota_accepted_gateway_reports (request_id, revision, final)
SELECT request_id, revision, final FROM openmettle.gateway_settlements
ON CONFLICT (request_id, revision) DO NOTHING;

CREATE FUNCTION openmettle.record_accepted_gateway_settlement()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    INSERT INTO openmettle.quota_accepted_gateway_reports (
        request_id, revision, final
    ) VALUES (
        NEW.request_id, NEW.revision, NEW.final
    ) ON CONFLICT (request_id, revision) DO NOTHING;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.record_accepted_gateway_settlement() FROM PUBLIC;
CREATE TRIGGER quota_record_accepted_gateway_settlement
    AFTER INSERT OR UPDATE OF revision, final ON openmettle.gateway_settlements
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.record_accepted_gateway_settlement();

CREATE TABLE openmettle.quota_defaults (
    scope_kind text NOT NULL CHECK (scope_kind IN ('instance', 'personal', 'project')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros',
        'live_runs_per_actor', 'live_runs_per_scope',
        'executing_runs_per_actor', 'executing_runs_per_scope',
        'round_cap', 'device_reservations'
    )),
    hard_limit bigint CHECK (hard_limit >= 0),
    window_seconds integer CHECK (window_seconds IS NULL OR window_seconds BETWEEN 60 AND 2678400),
    cost_denomination text
        CHECK (cost_denomination IS NULL OR octet_length(cost_denomination) BETWEEN 1 AND 32),
    warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    config_revision bigint NOT NULL DEFAULT 1 CHECK (config_revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, resource_kind),
    CHECK (resource_kind <> 'round_cap' OR hard_limit IS NULL OR hard_limit BETWEEN 1 AND 1000),
    CHECK (resource_kind NOT IN ('live_runs_per_actor', 'executing_runs_per_actor')
        OR scope_kind = 'personal'),
    CHECK (resource_kind NOT IN ('live_runs_per_scope', 'executing_runs_per_scope', 'round_cap')
        OR scope_kind IN ('personal', 'project')),
    CHECK (resource_kind NOT IN (
            'live_runs_per_actor', 'live_runs_per_scope',
            'executing_runs_per_actor', 'executing_runs_per_scope',
            'round_cap', 'device_reservations'
        ) OR window_seconds IS NULL),
    CHECK ((resource_kind = 'usage_cost_micros' AND scope_kind = 'instance')
        OR cost_denomination IS NULL)
);
INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, cost_denomination)
VALUES ('instance', 'usage_cost_micros', NULL);

CREATE TABLE openmettle.quota_cost_unit_lock (
    id boolean PRIMARY KEY DEFAULT true CHECK (id)
);
INSERT INTO openmettle.quota_cost_unit_lock (id) VALUES (true);

CREATE TABLE openmettle.quota_enforcement (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    metering_enforced boolean NOT NULL,
    metering_enforced_at timestamptz,
    CHECK (NOT metering_enforced OR metering_enforced_at IS NOT NULL)
);
WITH fresh AS (
    SELECT coalesce(pg_catalog.current_setting('openmettle.bootstrap_from_zero', true), 'false') = 'true'
           AND NOT EXISTS (SELECT 1 FROM openmettle.users)
           AND NOT EXISTS (SELECT 1 FROM openmettle.scopes)
           AND NOT EXISTS (SELECT 1 FROM openmettle.projects)
           AND NOT EXISTS (SELECT 1 FROM openmettle.runs)
           AND NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)
           AND NOT EXISTS (SELECT 1 FROM openmettle.artifact_revisions)
           AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_bindings)
           AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_reservations)
           AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_requests) AS is_fresh_bootstrap
),
seed_enforcement AS (
    INSERT INTO openmettle.quota_enforcement (id, metering_enforced, metering_enforced_at)
    SELECT true, is_fresh_bootstrap, CASE WHEN is_fresh_bootstrap THEN clock_timestamp() END
      FROM fresh
)
UPDATE openmettle.storage_volume_control svc
   SET bootstrap_auto_pin_allowed = fresh.is_fresh_bootstrap
  FROM fresh
 WHERE svc.id;

CREATE TABLE openmettle.quota_gateway_handoffs (
    gateway_request_id uuid PRIMARY KEY
        REFERENCES openmettle.gateway_requests (id) ON DELETE CASCADE,
    metering_enforced boolean NOT NULL,
    cost_required boolean NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE openmettle.quota_overrides (
    scope_id uuid NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind IN ('personal', 'project')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'storage_bytes', 'usage_tokens', 'usage_cost_micros',
        'live_runs_per_actor', 'live_runs_per_scope',
        'executing_runs_per_actor', 'executing_runs_per_scope',
        'round_cap', 'device_reservations'
    )),
    hard_limit bigint NOT NULL CHECK (hard_limit >= 0),
    expires_at timestamptz,
    revoked_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 256),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, resource_kind),
    FOREIGN KEY (scope_id, scope_kind) REFERENCES openmettle.scopes (id, kind),
    CHECK (resource_kind <> 'round_cap' OR hard_limit BETWEEN 1 AND 1000),
    CHECK (resource_kind NOT IN ('live_runs_per_actor', 'executing_runs_per_actor')
        OR scope_kind = 'personal')
);

CREATE TABLE openmettle.quota_budgets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_kind text NOT NULL CHECK (target_kind IN ('scope', 'instance')),
    scope_id uuid REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    window_kind text NOT NULL CHECK (window_kind IN ('windowed', 'static', 'concurrent')),
    window_start timestamptz NOT NULL,
    window_end timestamptz,
    active_used numeric(38, 0) NOT NULL DEFAULT 0 CHECK (active_used >= 0),
    reserved_held numeric(38, 0) NOT NULL DEFAULT 0 CHECK (reserved_held >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE NULLS NOT DISTINCT (target_kind, scope_id, resource_kind, window_kind, window_start),
    CHECK ((target_kind = 'scope' AND scope_id IS NOT NULL)
        OR (target_kind = 'instance' AND scope_id IS NULL)),
    CHECK (
        (resource_kind = 'device_reservations' AND window_kind = 'concurrent'
            AND window_start = '1970-01-01T00:00:00Z'::timestamptz AND window_end IS NULL
            AND active_used = 0)
        OR (resource_kind IN ('usage_tokens', 'usage_cost_micros')
            AND window_kind = 'windowed' AND window_end IS NOT NULL AND window_end > window_start)
        OR (resource_kind IN ('usage_tokens', 'usage_cost_micros')
            AND window_kind = 'static'
            AND window_start = '1970-01-01T00:00:00Z'::timestamptz AND window_end IS NULL)
    )
);

CREATE TABLE openmettle.quota_reservations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    actor_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    actor_scope_id uuid NOT NULL,
    origin_role text NOT NULL CHECK (origin_role IN ('api', 'worker')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) <= 1024),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    parent_reservation_id uuid REFERENCES openmettle.quota_reservations (id),
    allocating_claim_token uuid,
    run_id uuid,
    operation_id uuid,
    gateway_request_id uuid,
    device_grant_id uuid,
    reserved_units bigint NOT NULL CHECK (reserved_units > 0),
    allocated_units bigint NOT NULL DEFAULT 0
        CHECK (allocated_units >= 0 AND allocated_units <= reserved_units),
    held_units bigint NOT NULL
        CHECK (held_units >= 0 AND held_units <= reserved_units - allocated_units),
    settled_units numeric(38, 0) NOT NULL DEFAULT 0 CHECK (settled_units >= 0),
    accepted_source_revision bigint
        CHECK (accepted_source_revision IS NULL OR accepted_source_revision >= 0),
    state text NOT NULL DEFAULT 'held'
        CHECK (state IN ('held', 'handoff_committed', 'settled', 'released')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    lease_expires_at timestamptz NOT NULL,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (scope_id, actor_user_id, resource_kind, idempotency_key),
    UNIQUE (id, gateway_request_id),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES openmettle.scopes (id, personal_user_id),
    FOREIGN KEY (scope_id, gateway_request_id)
        REFERENCES openmettle.gateway_requests (scope_id, id),
    FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id),
    FOREIGN KEY (scope_id, run_id, operation_id)
        REFERENCES openmettle.operations (scope_id, run_id, id),
    CHECK (operation_id IS NULL OR run_id IS NOT NULL),
    CHECK (parent_reservation_id IS NULL OR (run_id IS NOT NULL AND allocated_units = 0)),
    CHECK (parent_reservation_id IS NULL OR allocating_claim_token IS NOT NULL),
    CHECK (allocated_units = 0
        OR (run_id IS NOT NULL AND gateway_request_id IS NULL AND settled_units = 0)),
    CHECK (gateway_request_id IS NULL OR resource_kind IN ('usage_tokens', 'usage_cost_micros')),
    CHECK (device_grant_id IS NULL OR resource_kind = 'device_reservations'),
    CHECK (
        (state = 'held' AND settled_units = 0 AND accepted_source_revision IS NULL
            AND closed_at IS NULL)
        OR (state = 'handoff_committed' AND closed_at IS NULL
            AND ((accepted_source_revision IS NULL AND settled_units = 0)
                 OR accepted_source_revision IS NOT NULL))
        OR (state = 'settled' AND held_units = 0 AND allocated_units = 0
            AND closed_at IS NOT NULL AND closed_at >= created_at
            AND (gateway_request_id IS NULL OR accepted_source_revision IS NOT NULL))
        OR (state = 'released' AND held_units = 0 AND settled_units = 0
            AND accepted_source_revision IS NULL
            AND closed_at IS NOT NULL AND closed_at >= created_at)
    )
);
CREATE INDEX quota_reservations_held_expiry_idx
    ON openmettle.quota_reservations (lease_expires_at, id) WHERE state = 'held';
CREATE INDEX quota_reservations_overdue_handoff_idx
    ON openmettle.quota_reservations (lease_expires_at, id) WHERE state = 'handoff_committed';
CREATE INDEX quota_reservations_run_idx
    ON openmettle.quota_reservations (scope_id, run_id) WHERE run_id IS NOT NULL;
CREATE INDEX quota_reservations_parent_idx
    ON openmettle.quota_reservations (parent_reservation_id)
    WHERE parent_reservation_id IS NOT NULL;
CREATE UNIQUE INDEX quota_reservations_gateway_request_kind_uidx
    ON openmettle.quota_reservations (gateway_request_id, resource_kind)
    WHERE gateway_request_id IS NOT NULL;
CREATE UNIQUE INDEX quota_reservations_device_grant_uidx
    ON openmettle.quota_reservations (device_grant_id)
    WHERE device_grant_id IS NOT NULL;

CREATE TABLE openmettle.quota_reservation_charges (
    reservation_id uuid NOT NULL REFERENCES openmettle.quota_reservations (id),
    budget_id uuid NOT NULL REFERENCES openmettle.quota_budgets (id),
    charge_role text NOT NULL CHECK (charge_role IN ('primary_scope', 'actor_scope', 'instance')),
    PRIMARY KEY (reservation_id, budget_id),
    UNIQUE (reservation_id, charge_role)
);
CREATE INDEX quota_reservation_charges_budget_idx
    ON openmettle.quota_reservation_charges (budget_id, reservation_id);

CREATE TABLE openmettle.quota_reconciliations (
    reservation_id uuid NOT NULL REFERENCES openmettle.quota_reservations (id),
    transition_revision bigint NOT NULL CHECK (transition_revision >= 1),
    source_key text NOT NULL CHECK (octet_length(source_key) BETWEEN 1 AND 128),
    gateway_request_id uuid,
    gateway_report_source uuid,
    gateway_report_id uuid,
    source_revision bigint CHECK (source_revision IS NULL OR source_revision >= 0),
    kind text NOT NULL CHECK (kind IN (
        'partial_settle', 'partial_correction', 'final_settle', 'final_correction', 'release'
    )),
    cumulative_units numeric(38, 0) NOT NULL CHECK (cumulative_units >= 0),
    delta_active numeric(38, 0) NOT NULL,
    delta_reserved numeric(38, 0) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (reservation_id, transition_revision),
    UNIQUE (reservation_id, source_key),
    FOREIGN KEY (reservation_id, gateway_request_id)
        REFERENCES openmettle.quota_reservations (id, gateway_request_id),
    FOREIGN KEY (gateway_request_id, source_revision)
        REFERENCES openmettle.quota_accepted_gateway_reports (request_id, revision),
    FOREIGN KEY (gateway_report_source, gateway_report_id, source_revision)
        REFERENCES openmettle.gateway_usage_reports (source, report_id, revision),
    CHECK (
        (kind = 'release'
            AND gateway_request_id IS NULL
            AND gateway_report_source IS NULL
            AND gateway_report_id IS NULL
            AND source_revision IS NULL
            AND delta_active = 0 AND delta_reserved <= 0)
        OR (kind IN ('partial_settle', 'partial_correction', 'final_settle', 'final_correction')
            AND gateway_request_id IS NOT NULL
            AND gateway_report_source IS NOT NULL
            AND gateway_report_id IS NOT NULL
            AND source_revision IS NOT NULL)
    )
);

CREATE TABLE openmettle.quota_warning_events (
    target_kind text NOT NULL CHECK (target_kind IN ('scope', 'instance')),
    scope_id uuid REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'storage_bytes', 'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    dedupe_bucket timestamptz NOT NULL,
    threshold_pct smallint NOT NULL CHECK (threshold_pct BETWEEN 1 AND 100),
    limit_revision bigint NOT NULL CHECK (limit_revision >= 0),
    config_revision bigint NOT NULL CHECK (config_revision >= 1),
    triggered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    emitted_at timestamptz,
    UNIQUE NULLS NOT DISTINCT (
        target_kind, scope_id, resource_kind, dedupe_bucket,
        threshold_pct, limit_revision, config_revision
    ),
    CHECK ((target_kind = 'scope' AND scope_id IS NOT NULL)
        OR (target_kind = 'instance' AND scope_id IS NULL))
);

-- Each committed crossing is eligible for a single telemetry delivery by a worker.
CREATE INDEX quota_warnings_pending_idx ON openmettle.quota_warning_events(triggered_at)
    WHERE emitted_at IS NULL;
CREATE FUNCTION openmettle.quota_take_warnings(p_limit integer)
RETURNS TABLE(target_kind text,scope_kind text,resource_kind text,threshold_pct smallint,dedupe_bucket bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    WITH pending AS MATERIALIZED (
        SELECT w.ctid AS tid FROM openmettle.quota_warning_events w WHERE w.emitted_at IS NULL
        ORDER BY w.triggered_at LIMIT greatest(0,least(p_limit,1000)) FOR UPDATE SKIP LOCKED
    ), emitted AS (
        UPDATE openmettle.quota_warning_events w SET emitted_at=clock_timestamp()
        FROM pending WHERE w.ctid=pending.tid RETURNING w.*
    )
    SELECT e.target_kind,coalesce(s.kind,'instance'),e.resource_kind,e.threshold_pct,
        extract(epoch FROM e.dedupe_bucket)::bigint
    FROM emitted e LEFT JOIN openmettle.scopes s ON s.id=e.scope_id
$$;
REVOKE ALL ON FUNCTION openmettle.quota_take_warnings(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_take_warnings(integer) TO openmettle_worker;

CREATE FUNCTION openmettle.enforce_quota_reservation_gateway_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.gateway_request_id IS DISTINCT FROM OLD.gateway_request_id THEN
        RAISE EXCEPTION 'quota_reservations.gateway_request_id is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.gateway_request_id IS NOT NULL THEN
        SELECT * INTO req
          FROM openmettle.gateway_requests q
         WHERE q.scope_id = NEW.scope_id
           AND q.id = NEW.gateway_request_id;
        IF NOT FOUND
           OR req.actor_user_id <> NEW.actor_user_id
           OR req.run_id IS DISTINCT FROM NEW.run_id
           OR (TG_OP = 'INSERT' AND req.state <> 'reserved') THEN
            RAISE EXCEPTION 'quota reservation gateway_request binding violates ownership or state'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.accepted_source_revision IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1
                  FROM openmettle.quota_accepted_gateway_reports a
                 WHERE a.request_id = req.id
                   AND a.revision = NEW.accepted_source_revision
            ) THEN
                RAISE EXCEPTION 'quota reservation accepted_source_revision must exist in quota_accepted_gateway_reports'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        IF NEW.resource_kind = 'usage_tokens' THEN
            IF NEW.reserved_units <> req.units THEN
                RAISE EXCEPTION 'usage_tokens reservation reserved_units must match gateway_requests.units'
                    USING ERRCODE = '23514';
            END IF;
            IF TG_OP = 'INSERT'
               OR NEW.state = 'held'
               OR (NEW.state = 'handoff_committed' AND NEW.accepted_source_revision IS NULL) THEN
                IF NEW.settled_units <> 0
                   OR NEW.accepted_source_revision IS NOT NULL
                   OR NEW.held_units <> req.units THEN
                    RAISE EXCEPTION 'pre-settlement usage_tokens reservation must hold exact gateway_requests.units with zero settled_units'
                        USING ERRCODE = '23514';
                END IF;
            ELSIF NEW.state = 'handoff_committed' AND NEW.accepted_source_revision IS NOT NULL THEN
                IF NEW.held_units <> greatest(0::numeric(38, 0), req.units::numeric(38, 0) - NEW.settled_units)::bigint THEN
                    RAISE EXCEPTION 'partially settled usage_tokens reservation must match remaining held_units'
                        USING ERRCODE = '23514';
                END IF;
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_quota_reservation_gateway_binding() FROM PUBLIC;
CREATE TRIGGER quota_reservations_gateway_binding_guard
    BEFORE INSERT OR UPDATE ON openmettle.quota_reservations
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_quota_reservation_gateway_binding();

CREATE FUNCTION openmettle.enforce_cost_denomination_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.scope_kind = 'instance' AND NEW.resource_kind = 'usage_cost_micros' THEN
            RAISE EXCEPTION 'instance usage_cost_micros default row is UPDATE-only after migration'
                USING ERRCODE = 'OMQ02';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.scope_kind = 'instance' AND OLD.resource_kind = 'usage_cost_micros' THEN
        IF TG_OP = 'DELETE'
           OR NEW.scope_kind <> OLD.scope_kind
           OR NEW.resource_kind <> OLD.resource_kind THEN
            RAISE EXCEPTION 'instance usage_cost_micros default row cannot be deleted or renamed'
                USING ERRCODE = 'OMQ02';
        ELSIF NEW.cost_denomination IS DISTINCT FROM OLD.cost_denomination THEN
            PERFORM FROM openmettle.quota_cost_unit_lock WHERE id FOR UPDATE;
            IF OLD.cost_denomination IS NOT NULL
               OR NEW.cost_denomination IS NULL
               OR EXISTS (SELECT 1 FROM openmettle.quota_overrides
                           WHERE resource_kind = 'usage_cost_micros')
               OR EXISTS (SELECT 1 FROM openmettle.quota_budgets
                           WHERE resource_kind = 'usage_cost_micros')
               OR EXISTS (SELECT 1 FROM openmettle.quota_reservations
                           WHERE resource_kind = 'usage_cost_micros')
               OR EXISTS (SELECT 1 FROM openmettle.gateway_usage_reports
                           WHERE cost IS NOT NULL AND unit <> NEW.cost_denomination) THEN
                RAISE EXCEPTION 'cost_denomination is immutable once configured or used'
                    USING ERRCODE = 'OMQ02';
            END IF;
        END IF;
    ELSIF TG_OP = 'UPDATE'
          AND NEW.scope_kind = 'instance' AND NEW.resource_kind = 'usage_cost_micros' THEN
        RAISE EXCEPTION 'cannot rename another quota_defaults row to instance usage_cost_micros'
            USING ERRCODE = 'OMQ02';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_cost_denomination_immutability() FROM PUBLIC;
CREATE TRIGGER quota_defaults_cost_denomination_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON openmettle.quota_defaults
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_cost_denomination_immutability();

CREATE FUNCTION openmettle.enforce_gateway_report_cost_unit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_denom text;
BEGIN
    SELECT cost_denomination INTO v_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    IF v_denom IS NOT NULL THEN
        IF NEW.unit <> v_denom THEN
            RAISE EXCEPTION 'gateway usage report unit mismatches cost_denomination'
                USING ERRCODE = 'OMQ02';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM FROM openmettle.quota_cost_unit_lock WHERE id FOR UPDATE;

    SELECT cost_denomination INTO v_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    IF v_denom IS NOT NULL THEN
        IF NEW.unit <> v_denom THEN
            RAISE EXCEPTION 'gateway usage report unit mismatches cost_denomination'
                USING ERRCODE = 'OMQ02';
        END IF;
    ELSIF EXISTS (
        SELECT 1 FROM openmettle.gateway_usage_reports
         WHERE cost IS NOT NULL AND unit <> NEW.unit
    ) THEN
        RAISE EXCEPTION 'gateway usage report unit conflicts with existing cost reports'
            USING ERRCODE = 'OMQ02';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_report_cost_unit() FROM PUBLIC;
CREATE TRIGGER gateway_usage_reports_cost_unit_guard
    BEFORE INSERT ON openmettle.gateway_usage_reports
    FOR EACH ROW WHEN (NEW.cost IS NOT NULL)
    EXECUTE FUNCTION openmettle.enforce_gateway_report_cost_unit();

CREATE FUNCTION openmettle.enforce_quota_enforcement_write_once()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'DELETE')
       OR (OLD.metering_enforced AND (NOT NEW.metering_enforced
           OR NEW.metering_enforced_at IS DISTINCT FROM OLD.metering_enforced_at)) THEN
        RAISE EXCEPTION 'quota_enforcement.metering_enforced is write-once (false -> true)'
            USING ERRCODE = 'OMQ04';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_quota_enforcement_write_once() FROM PUBLIC;
CREATE TRIGGER quota_enforcement_write_once
    BEFORE INSERT OR UPDATE OR DELETE ON openmettle.quota_enforcement
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_quota_enforcement_write_once();

CREATE FUNCTION openmettle.enforce_gateway_handoff_holds()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_enforced boolean;
    v_scope_kind text;
    v_actor_scope_id uuid;
    v_cost_denom text;
    v_cost_required boolean := false;
BEGIN
    IF EXISTS (
        SELECT 1
          FROM openmettle.quota_reservations qr
         WHERE qr.gateway_request_id = NEW.id
           AND qr.state <> 'handoff_committed'
    ) THEN
        RAISE EXCEPTION 'bound quota reservations must be handoff_committed on gateway handoff'
            USING ERRCODE = 'OMQ04';
    END IF;

    SELECT cost_denomination INTO v_cost_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    IF v_cost_denom IS NOT NULL THEN
        SELECT kind INTO v_scope_kind
          FROM openmettle.scopes
         WHERE id = NEW.scope_id;
        SELECT id INTO v_actor_scope_id
          FROM openmettle.scopes
         WHERE personal_user_id = NEW.actor_user_id;

        v_cost_required := EXISTS (
            SELECT 1
              FROM openmettle.quota_defaults qd
             WHERE qd.resource_kind = 'usage_cost_micros'
               AND qd.hard_limit IS NOT NULL
               AND qd.scope_kind IN ('instance', 'personal', v_scope_kind)
        ) OR EXISTS (
            SELECT 1
              FROM openmettle.quota_overrides qo
             WHERE qo.resource_kind = 'usage_cost_micros'
               AND qo.scope_id IN (NEW.scope_id, v_actor_scope_id)
               AND qo.revoked_at IS NULL
               AND (qo.expires_at IS NULL OR qo.expires_at > clock_timestamp())
        );
    END IF;

    INSERT INTO openmettle.quota_gateway_handoffs (
        gateway_request_id, metering_enforced, cost_required
    ) VALUES (
        NEW.id, false, v_cost_required
    );

    SELECT metering_enforced INTO STRICT v_enforced
      FROM openmettle.quota_enforcement
     WHERE id
       FOR SHARE;

    IF v_enforced THEN
        IF NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_tokens'
               AND qr.state = 'handoff_committed'
               AND qr.reserved_units = NEW.units
               AND qr.held_units = NEW.units
               AND qr.settled_units = 0
               AND qr.accepted_source_revision IS NULL
               AND qr.scope_id = NEW.scope_id
               AND qr.actor_user_id = NEW.actor_user_id
               AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
        ) THEN
            RAISE EXCEPTION 'missing or mismatched handoff_committed usage_tokens reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        IF v_cost_required AND NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_cost_micros'
               AND qr.state = 'handoff_committed'
               AND qr.settled_units = 0
               AND qr.accepted_source_revision IS NULL
               AND qr.scope_id = NEW.scope_id
               AND qr.actor_user_id = NEW.actor_user_id
               AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
        ) THEN
            RAISE EXCEPTION 'missing or mismatched handoff_committed usage_cost_micros reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        UPDATE openmettle.quota_gateway_handoffs
           SET metering_enforced = true
         WHERE gateway_request_id = NEW.id;
    END IF;

    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_handoff_holds() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds
    AFTER UPDATE OF state ON openmettle.gateway_requests
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (OLD.state = 'reserved' AND NEW.state = 'handed_off')
    EXECUTE FUNCTION openmettle.enforce_gateway_handoff_holds();

CREATE FUNCTION openmettle.quota_lock_gateway_request_for_settlement(
    p_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_has_role(session_user, 'openmettle_gateway', 'USAGE') THEN
        RAISE EXCEPTION 'quota_lock_gateway_request_for_settlement requires openmettle_gateway role'
            USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM openmettle.gateway_requests
     WHERE id = p_request_id
       FOR NO KEY UPDATE;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid) TO openmettle_gateway;

CREATE FUNCTION openmettle.enforce_tool_spill_reservation_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.idempotency_key LIKE 'tool-spill:%'
       AND (NEW.run_id IS NULL OR NEW.operation_id IS NULL) THEN
        RAISE EXCEPTION 'tool-spill storage reservations require non-null run_id and operation_id'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_tool_spill_reservation_binding() FROM PUBLIC;
CREATE TRIGGER storage_reservations_tool_spill_binding_guard
    BEFORE INSERT OR UPDATE OF idempotency_key, run_id, operation_id
    ON openmettle.storage_reservations
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_tool_spill_reservation_binding();

CREATE FUNCTION openmettle.storage_lock_pinned_volume()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_vol uuid;
    v_adopt uuid;
BEGIN
    SELECT volume_id, adoption_run_id
      INTO v_vol, v_adopt
      FROM openmettle.storage_volume_control
     WHERE id
       FOR SHARE;
    IF NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL THEN
        RAISE EXCEPTION 'runtime storage operations require pinned, non-adopting storage_volume_control.volume_id'
            USING ERRCODE = 'OMQ03';
    END IF;
    RETURN v_vol;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.storage_lock_pinned_volume() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.storage_lock_pinned_volume() TO openmettle_api, openmettle_worker;

CREATE FUNCTION openmettle.storage_pin_volume_id(p_volume_id uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_vol uuid;
    v_auto boolean;
    v_adopt uuid;
BEGIN
    IF p_volume_id IS NULL THEN
        RAISE EXCEPTION 'storage_pin_volume_id requires non-null volume_id'
            USING ERRCODE = 'OMQ03';
    END IF;
    SELECT volume_id, bootstrap_auto_pin_allowed, adoption_run_id
      INTO v_vol, v_auto, v_adopt
      FROM openmettle.storage_volume_control
     WHERE id
       FOR UPDATE;
    IF NOT FOUND OR v_adopt IS NOT NULL THEN
        RAISE EXCEPTION 'storage_volume_control is missing or undergoing adoption'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF v_vol IS NOT NULL THEN
        IF v_vol = p_volume_id THEN
            RETURN v_vol;
        END IF;
        RAISE EXCEPTION 'storage_volume_control.volume_id is already pinned to a different volume'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF NOT v_auto
       OR EXISTS (SELECT 1 FROM openmettle.storage_reservations)
       OR EXISTS (SELECT 1 FROM openmettle.artifact_revisions) THEN
        RAISE EXCEPTION 'bootstrap auto-pin requires bootstrap_auto_pin_allowed = true and empty storage ledger'
            USING ERRCODE = 'OMQ03';
    END IF;
    UPDATE openmettle.storage_volume_control
       SET volume_id = p_volume_id,
           bootstrap_auto_pin_allowed = false
     WHERE id;
    RETURN p_volume_id;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.storage_pin_volume_id(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.storage_pin_volume_id(uuid) TO openmettle_api;

CREATE FUNCTION openmettle.enforce_runtime_storage_volume_pinned()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        PERFORM openmettle.storage_lock_pinned_volume();
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_runtime_storage_volume_pinned() FROM PUBLIC;
CREATE TRIGGER storage_reservations_runtime_volume_pin_guard
    BEFORE UPDATE ON openmettle.storage_reservations
    FOR EACH ROW
    WHEN (OLD.state = 'reserved' AND NEW.state = 'released')
    EXECUTE FUNCTION openmettle.enforce_runtime_storage_volume_pinned();
CREATE TRIGGER artifact_revisions_runtime_volume_pin_guard
    BEFORE UPDATE ON openmettle.artifact_revisions
    FOR EACH ROW
    WHEN (NEW.state IN ('purging', 'purged'))
    EXECUTE FUNCTION openmettle.enforce_runtime_storage_volume_pinned();

CREATE FUNCTION openmettle.enforce_storage_reservation_monotonic_guards()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        IF OLD.adoption_unverified AND NOT NEW.adoption_unverified THEN
            RAISE EXCEPTION 'only openmettle_owner may clear storage_reservations.adoption_unverified'
                USING ERRCODE = 'OMQ03';
        END IF;
        IF OLD.payload_ino IS NOT NULL AND NEW.payload_ino IS DISTINCT FROM OLD.payload_ino THEN
            RAISE EXCEPTION 'storage_reservations.payload_ino is write-once and immutable for runtime roles'
                USING ERRCODE = 'OMQ03';
        END IF;
        IF OLD.stage_claimed AND NOT NEW.stage_claimed THEN
            RAISE EXCEPTION 'storage_reservations.stage_claimed is write-once for runtime roles'
                USING ERRCODE = 'OMQ03';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_storage_reservation_monotonic_guards() FROM PUBLIC;
CREATE TRIGGER storage_reservations_monotonic_guards
    BEFORE UPDATE ON openmettle.storage_reservations
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.enforce_storage_reservation_monotonic_guards();

GRANT SELECT ON openmettle.quota_defaults, openmettle.quota_enforcement,
    openmettle.quota_overrides, openmettle.quota_budgets, openmettle.quota_reservations,
    openmettle.quota_reservation_charges, openmettle.quota_reconciliations,
    openmettle.quota_warning_events TO openmettle_api, openmettle_worker, openmettle_gateway;

CREATE FUNCTION openmettle.enforce_storage_override() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF EXISTS (SELECT FROM openmettle.quota_overrides
        WHERE scope_id=NEW.scope_id AND resource_kind='storage_bytes' AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > clock_timestamp())
          AND NEW.active_bytes::numeric + NEW.retained_bytes + NEW.reserved_bytes > hard_limit) THEN
        RAISE EXCEPTION 'scope storage limit exceeded' USING ERRCODE='OMQ01';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_storage_override() FROM PUBLIC;
CREATE TRIGGER storage_accounts_override_guard BEFORE UPDATE ON openmettle.storage_accounts
    FOR EACH ROW WHEN (NEW.active_bytes::numeric + NEW.retained_bytes + NEW.reserved_bytes
                      > OLD.active_bytes::numeric + OLD.retained_bytes + OLD.reserved_bytes)
    EXECUTE FUNCTION openmettle.enforce_storage_override();

-- Resolve the effective configuration under the lock of the entity being charged.
CREATE FUNCTION openmettle.quota_limit(p_scope uuid,p_kind text,p_resource text)
RETURNS TABLE (hard_limit bigint,window_seconds integer,warn1 smallint,warn2 smallint,
               config_revision bigint,limit_revision bigint)
LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
    SELECT coalesce(CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at>statement_timestamp())
                         THEN o.hard_limit END,d.hard_limit), d.window_seconds,
           coalesce(d.warn_pct_1,80)::smallint,coalesce(d.warn_pct_2,90)::smallint,
           coalesce(d.config_revision,1),coalesce(o.revision,0)
    FROM (VALUES (1)) AS seed(id)
    LEFT JOIN openmettle.quota_defaults d ON d.scope_kind=p_kind AND d.resource_kind=p_resource
    LEFT JOIN openmettle.quota_overrides o ON o.scope_id=p_scope AND o.resource_kind=p_resource
$$;
REVOKE ALL ON FUNCTION openmettle.quota_limit(uuid,text,text) FROM PUBLIC;

CREATE FUNCTION openmettle.quota_warn(p_target text,p_scope uuid,p_resource text,p_bucket timestamptz,
    p_before numeric,p_after numeric,p_limit bigint,p_warn1 smallint,p_warn2 smallint,p_config bigint,p_revision bigint)
RETURNS void LANGUAGE sql SET search_path=pg_catalog AS $$
    INSERT INTO openmettle.quota_warning_events (target_kind,scope_id,resource_kind,dedupe_bucket,
        threshold_pct,config_revision,limit_revision)
    SELECT p_target,p_scope,p_resource,p_bucket,pct,p_config,p_revision
    FROM unnest(ARRAY[p_warn1,p_warn2,100::smallint]) pct
    WHERE (p_limit>0 AND p_before*100 < p_limit::numeric*pct AND p_after*100 >= p_limit::numeric*pct)

    ON CONFLICT DO NOTHING
$$;
REVOKE ALL ON FUNCTION openmettle.quota_warn(text,uuid,text,timestamptz,numeric,numeric,bigint,smallint,smallint,bigint,bigint) FROM PUBLIC;

-- Caller identity is derived from the login. Untrusted callers cannot select another origin.
CREATE FUNCTION openmettle.quota_reserve(p_scope uuid,p_actor uuid,p_resource text,p_units bigint,
    p_key text,p_run uuid,p_request uuid,p_dispatch bytea,p_lease timestamptz)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    actor_scope uuid; primary_kind text; origin text; identity_bytes bytea;
    hold openmettle.quota_reservations%ROWTYPE;
    req openmettle.gateway_requests%ROWTYPE;
    target record; cfg record; budget openmettle.quota_budgets%ROWTYPE;
    stamp timestamptz := clock_timestamp(); start_at timestamptz; win text;
BEGIN
    origin := CASE WHEN pg_has_role(session_user,'openmettle_api','USAGE') THEN 'api'
                   WHEN pg_has_role(session_user,'openmettle_worker','USAGE') THEN 'worker' END;
    IF origin IS NULL OR p_lease IS NULL OR p_lease <= stamp OR p_units IS NULL OR p_units <= 0 THEN
        RAISE EXCEPTION 'invalid quota reservation' USING ERRCODE='23514';
    END IF;
    SELECT id INTO STRICT actor_scope FROM openmettle.scopes WHERE personal_user_id=p_actor;
    SELECT kind INTO STRICT primary_kind FROM openmettle.scopes WHERE id=p_scope;
    IF p_run IS NOT NULL THEN
        PERFORM FROM openmettle.runs WHERE id=p_run AND scope_id=p_scope AND actor_user_id=p_actor FOR NO KEY UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'invalid run' USING ERRCODE='23514'; END IF;
    END IF;
    IF p_request IS NOT NULL THEN
        SELECT * INTO req FROM openmettle.gateway_requests WHERE id=p_request AND state='reserved'
            AND scope_id=p_scope AND actor_user_id=p_actor AND run_id IS NULL
            AND octet_length(p_dispatch)=32 AND dispatch_hash=sha256(p_dispatch) FOR KEY SHARE;
        IF NOT FOUND OR origin <> 'api' OR p_run IS NOT NULL
           OR (p_resource='usage_tokens' AND req.units<>p_units) THEN
            RAISE EXCEPTION 'invalid gateway hold' USING ERRCODE='23514';
        END IF;
    END IF;
    IF p_resource='usage_cost_micros' AND NOT EXISTS (SELECT FROM openmettle.quota_defaults
        WHERE scope_kind='instance' AND resource_kind=p_resource AND cost_denomination IS NOT NULL) THEN
        RAISE EXCEPTION 'cost denomination unconfigured' USING ERRCODE='OMQ02';
    END IF;
    identity_bytes := convert_to(jsonb_build_array(p_scope,p_actor,p_resource,p_units,p_key,p_run,p_request,origin)::text,'UTF8');
    INSERT INTO openmettle.quota_reservations (scope_id,actor_user_id,actor_scope_id,origin_role,resource_kind,
        idempotency_key,request_identity,request_digest,run_id,gateway_request_id,reserved_units,held_units,lease_expires_at)
    VALUES (p_scope,p_actor,actor_scope,origin,p_resource,p_key,identity_bytes,sha256(identity_bytes),
        p_run,p_request,p_units,p_units,p_lease)
    ON CONFLICT (scope_id,actor_user_id,resource_kind,idempotency_key) DO NOTHING RETURNING * INTO hold;
    IF NOT FOUND THEN
        SELECT * INTO STRICT hold FROM openmettle.quota_reservations WHERE scope_id=p_scope
            AND actor_user_id=p_actor AND resource_kind=p_resource AND idempotency_key=p_key;
        IF hold.request_identity <> identity_bytes THEN RAISE EXCEPTION 'quota replay conflict' USING ERRCODE='23505'; END IF;
        RETURN hold.id;
    END IF;
    FOR target IN SELECT * FROM (VALUES (p_scope,primary_kind,'primary_scope'),
        (actor_scope,'personal','actor_scope'),(NULL::uuid,'instance','instance')) t(scope,kind,charge)
        WHERE charge <> 'actor_scope' OR actor_scope<>p_scope ORDER BY scope NULLS LAST
    LOOP
        SELECT * INTO cfg FROM openmettle.quota_limit(target.scope,target.kind,p_resource);
        IF cfg.hard_limit IS NULL THEN
            IF target.kind IN ('instance','project') THEN CONTINUE; END IF;
            RAISE EXCEPTION 'quota limit unconfigured' USING ERRCODE='OMQ05';
        END IF;
        win := CASE WHEN p_resource='device_reservations' THEN 'concurrent'
                    WHEN cfg.window_seconds IS NULL THEN 'static' ELSE 'windowed' END;
        start_at := CASE WHEN win='windowed' THEN date_bin(make_interval(secs=>cfg.window_seconds),stamp,'epoch')
                         ELSE 'epoch'::timestamptz END;
        INSERT INTO openmettle.quota_budgets (target_kind,scope_id,resource_kind,window_kind,window_start,window_end)
        VALUES (CASE WHEN target.scope IS NULL THEN 'instance' ELSE 'scope' END,target.scope,p_resource,win,
            start_at,CASE WHEN win='windowed' THEN start_at+make_interval(secs=>cfg.window_seconds) END)
        ON CONFLICT DO NOTHING;
        SELECT * INTO STRICT budget FROM openmettle.quota_budgets WHERE scope_id IS NOT DISTINCT FROM target.scope
            AND resource_kind=p_resource AND window_kind=win AND window_start=start_at FOR NO KEY UPDATE;
        SELECT * INTO cfg FROM openmettle.quota_limit(target.scope,target.kind,p_resource);
        IF cfg.hard_limit IS NULL THEN RAISE EXCEPTION 'quota configuration changed' USING ERRCODE='40001'; END IF;
        IF budget.active_used+budget.reserved_held+p_units>cfg.hard_limit THEN
            RAISE EXCEPTION 'quota limit exceeded' USING ERRCODE='OMQ01';
        END IF;
        INSERT INTO openmettle.quota_reservation_charges VALUES (hold.id,budget.id,target.charge);
        UPDATE openmettle.quota_budgets SET reserved_held=reserved_held+p_units,revision=revision+1,
            updated_at=stamp WHERE id=budget.id;
        PERFORM openmettle.quota_warn(budget.target_kind,target.scope,p_resource,
            CASE WHEN win='windowed' THEN start_at ELSE date_trunc('day',stamp,'UTC') END,
            budget.active_used+budget.reserved_held,budget.active_used+budget.reserved_held+p_units,
            cfg.hard_limit,cfg.warn1,cfg.warn2,cfg.config_revision,cfg.limit_revision);
    END LOOP;
    RETURN hold.id;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_reserve(uuid,uuid,text,bigint,text,uuid,uuid,bytea,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_reserve(uuid,uuid,text,bigint,text,uuid,uuid,bytea,timestamptz) TO openmettle_api, openmettle_worker;

-- In the absence of a smaller caller-supplied dispatch ceiling, bound a legacy call by the
-- smallest applicable configured cost limit. Token units never enter this calculation.
CREATE FUNCTION openmettle.quota_cost_ceiling(p_scope uuid,p_actor uuid)
RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT min(cfg.hard_limit) FROM (
        SELECT id,kind FROM openmettle.scopes WHERE id=p_scope OR personal_user_id=p_actor
        UNION ALL SELECT NULL::uuid,'instance') target
    CROSS JOIN LATERAL openmettle.quota_limit(target.id,target.kind,'usage_cost_micros') cfg
    WHERE EXISTS (SELECT FROM openmettle.quota_defaults WHERE scope_kind='instance'
        AND resource_kind='usage_cost_micros' AND cost_denomination IS NOT NULL)
$$;
REVOKE ALL ON FUNCTION openmettle.quota_cost_ceiling(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_cost_ceiling(uuid,uuid) TO openmettle_api,openmettle_worker;

CREATE FUNCTION openmettle.quota_ensure_legacy_run_holds(p_scope uuid,p_run uuid,p_claim uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    r openmettle.runs%ROWTYPE; g openmettle.gateway_reservations%ROWTYPE; cost_max bigint;
BEGIN
    SELECT * INTO STRICT r FROM openmettle.runs WHERE scope_id=p_scope AND id=p_run AND state='running'
        AND cancel_reason IS NULL AND claim_token=p_claim AND lease_expires_at>clock_timestamp() FOR NO KEY UPDATE;
    SELECT * INTO STRICT g FROM openmettle.gateway_reservations WHERE run_id=p_run FOR NO KEY UPDATE;
    IF g.units>g.allocated AND NOT EXISTS (SELECT FROM openmettle.quota_reservations WHERE scope_id=p_scope
        AND run_id=p_run AND gateway_request_id IS NULL AND resource_kind='usage_tokens') THEN
        PERFORM openmettle.quota_reserve(p_scope,r.actor_user_id,'usage_tokens',g.units-g.allocated,
            'run:'||p_run,p_run,NULL,NULL,r.lease_expires_at);
    END IF;
    cost_max:=openmettle.quota_cost_ceiling(p_scope,r.actor_user_id);
    IF g.units>g.allocated AND cost_max IS NOT NULL AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE scope_id=p_scope AND run_id=p_run AND gateway_request_id IS NULL AND resource_kind='usage_cost_micros') THEN
        IF cost_max=0 THEN RAISE EXCEPTION 'cost limit exceeded' USING ERRCODE='OMQ01'; END IF;
        PERFORM openmettle.quota_reserve(p_scope,r.actor_user_id,'usage_cost_micros',cost_max,
            'run:'||p_run,p_run,NULL,NULL,r.lease_expires_at);
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_ensure_legacy_run_holds(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_ensure_legacy_run_holds(uuid,uuid,uuid) TO openmettle_worker;

CREATE FUNCTION openmettle.quota_allocate_round(p_request uuid,p_dispatch bytea,p_claim uuid,p_kind text,p_units bigint)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE; parent openmettle.quota_reservations%ROWTYPE;
    child uuid; identity_bytes bytea;
BEGIN
    SELECT * INTO STRICT req FROM openmettle.gateway_requests WHERE id=p_request AND state='reserved'
        AND run_id IS NOT NULL AND octet_length(p_dispatch)=32 AND dispatch_hash=sha256(p_dispatch);
    PERFORM FROM openmettle.runs WHERE id=req.run_id AND scope_id=req.scope_id AND claim_token=p_claim
        AND state='running' AND cancel_reason IS NULL AND lease_expires_at>clock_timestamp() FOR NO KEY UPDATE;
    IF NOT FOUND OR p_kind NOT IN ('usage_tokens','usage_cost_micros') OR p_units<=0
        OR (p_kind='usage_tokens' AND req.units<>p_units) THEN
        RAISE EXCEPTION 'invalid round allocation' USING ERRCODE='23514';
    END IF;
    PERFORM FROM openmettle.gateway_requests WHERE id=p_request AND state='reserved' FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'round unavailable' USING ERRCODE='23514'; END IF;
    SELECT * INTO STRICT parent FROM openmettle.quota_reservations WHERE scope_id=req.scope_id
        AND run_id=req.run_id AND actor_user_id=req.actor_user_id AND gateway_request_id IS NULL
        AND resource_kind=p_kind AND state='held' FOR NO KEY UPDATE;
    IF parent.held_units < p_units THEN RAISE EXCEPTION 'run allowance exhausted' USING ERRCODE='OMQ01'; END IF;
    identity_bytes := uuid_send(req.id)||int8send(p_units);
    INSERT INTO openmettle.quota_reservations (scope_id,actor_user_id,actor_scope_id,origin_role,resource_kind,
        idempotency_key,request_identity,request_digest,parent_reservation_id,allocating_claim_token,run_id,
        gateway_request_id,reserved_units,held_units,lease_expires_at)
    VALUES (parent.scope_id,parent.actor_user_id,parent.actor_scope_id,'worker',p_kind,'round:'||req.id,
        identity_bytes,sha256(identity_bytes),parent.id,p_claim,req.run_id,req.id,p_units,p_units,parent.lease_expires_at)
    RETURNING id INTO child;
    UPDATE openmettle.quota_reservations SET held_units=held_units-p_units,allocated_units=allocated_units+p_units,
        revision=revision+1 WHERE id=parent.id;
    INSERT INTO openmettle.quota_reservation_charges SELECT child,budget_id,charge_role
        FROM openmettle.quota_reservation_charges WHERE reservation_id=parent.id;
    RETURN child;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_allocate_round(uuid,bytea,uuid,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_allocate_round(uuid,bytea,uuid,text,bigint) TO openmettle_worker;

CREATE FUNCTION openmettle.quota_commit_handoff(p_request uuid,p_dispatch bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE req openmettle.gateway_requests%ROWTYPE;
BEGIN
    SELECT * INTO STRICT req FROM openmettle.gateway_requests WHERE id=p_request AND state='handed_off'
        AND octet_length(p_dispatch)=32 AND dispatch_hash=sha256(p_dispatch)
        AND pg_has_role(session_user, CASE WHEN run_id IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END,'USAGE')
        FOR NO KEY UPDATE;
    UPDATE openmettle.quota_reservations SET state='handoff_committed',revision=revision+1
        WHERE gateway_request_id=req.id AND state='held'
          AND origin_role=CASE WHEN req.run_id IS NULL THEN 'api' ELSE 'worker' END;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_commit_handoff(uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_commit_handoff(uuid,bytea) TO openmettle_api,openmettle_worker;

ALTER TABLE openmettle.authorization_audit
    DROP CONSTRAINT authorization_audit_action_check,
    ADD CONSTRAINT authorization_audit_action_check CHECK (action IN (
        'account_admin.grant', 'account_admin.revoke',
        'user.disable', 'user.enable',
        'local_group.create', 'local_group.rename', 'local_group.disable', 'local_group.enable',
        'local_group.member_add', 'local_group.member_remove',
        'project.create', 'project.settings_update', 'project.archive', 'project.restore',
        'project.delete', 'project.member_grant', 'project.member_revoke',
        'resource.share', 'resource.unshare',
        'capability.platform_deny', 'capability.platform_allow',
        'capability.user_deny', 'capability.user_allow',
        'capability.user_grant', 'capability.user_revoke',
        'conversation.create', 'branch.create','quota.override.set','quota.override.revoke')),
    DROP CONSTRAINT authorization_audit_target_kind_check,
    ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN
        ('user', 'project', 'conversation', 'artifact', 'local_group', 'capability', 'scope', 'branch','quota_scope'));

-- Fold accepted evidence alone. Reuse the same calculation for settlement and drift replay.
CREATE FUNCTION openmettle.quota_gateway_fold(p_request uuid,p_kind text,p_units bigint,p_through bigint)
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
        IF measured IS NOT NULL THEN
            settled:=CASE WHEN complete THEN measured ELSE greatest(measured,settled) END;
            IF complete AND step.final THEN state:='settled'; END IF;
            held:=CASE WHEN state='settled' THEN 0 ELSE greatest(0,p_units-settled)::bigint END;
        END IF;
        RETURN NEXT;
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_gateway_fold(uuid,text,bigint,bigint) FROM PUBLIC;

CREATE FUNCTION openmettle.quota_adjust(p_hold uuid,p_active numeric,p_reserved numeric) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE b openmettle.quota_budgets%ROWTYPE; cfg record;
BEGIN
    FOR b IN SELECT b1.* FROM openmettle.quota_budgets b1 JOIN openmettle.quota_reservation_charges c
        ON c.budget_id=b1.id WHERE c.reservation_id=p_hold
        ORDER BY b1.scope_id NULLS LAST,b1.resource_kind,b1.window_start,b1.id FOR NO KEY UPDATE OF b1
    LOOP
        UPDATE openmettle.quota_budgets SET active_used=active_used+p_active,reserved_held=reserved_held+p_reserved,
            revision=revision+1,updated_at=clock_timestamp() WHERE id=b.id;
        SELECT * INTO cfg FROM openmettle.quota_limit(b.scope_id,
            coalesce((SELECT kind FROM openmettle.scopes WHERE id=b.scope_id),'instance'),b.resource_kind);
        PERFORM openmettle.quota_warn(b.target_kind,b.scope_id,b.resource_kind,
            CASE WHEN b.window_kind='windowed' THEN b.window_start ELSE date_trunc('day',now(),'UTC') END,
            b.active_used+b.reserved_held,b.active_used+b.reserved_held+p_active+p_reserved,
            cfg.hard_limit,cfg.warn1,cfg.warn2,cfg.config_revision,cfg.limit_revision);
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_adjust(uuid,numeric,numeric) FROM PUBLIC;

CREATE FUNCTION openmettle.quota_settle_gateway_usage(p_request uuid,p_report_source uuid,p_report_id uuid,p_source_revision bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE h openmettle.quota_reservations%ROWTYPE; step record; delta numeric; released numeric;
BEGIN
    PERFORM FROM openmettle.gateway_requests WHERE id=p_request AND state='handed_off' FOR KEY SHARE;
    IF NOT FOUND OR NOT EXISTS (SELECT FROM openmettle.quota_accepted_gateway_reports a
        JOIN openmettle.gateway_usage_reports g USING(request_id,revision,final)
        WHERE a.request_id=p_request AND a.revision=p_source_revision
          AND g.source=p_report_source AND g.report_id=p_report_id) THEN
        RAISE EXCEPTION 'unknown accepted report' USING ERRCODE='23514';
    END IF;
    FOR h IN SELECT * FROM openmettle.quota_reservations WHERE gateway_request_id=p_request
        AND state IN ('handoff_committed','settled') ORDER BY resource_kind FOR UPDATE
    LOOP
        FOR step IN SELECT * FROM openmettle.quota_gateway_fold(p_request,h.resource_kind,h.reserved_units,p_source_revision)
            WHERE rev>coalesce(h.accepted_source_revision,-1) ORDER BY rev
        LOOP
            IF (step.state,step.settled,step.held) IS DISTINCT FROM (h.state,h.settled_units,h.held_units) THEN
                delta:=step.settled-h.settled_units; released:=step.held::numeric-h.held_units;
                PERFORM openmettle.quota_adjust(h.id,delta,released);
                h.revision:=h.revision+1;
                INSERT INTO openmettle.quota_reconciliations (reservation_id,transition_revision,source_key,
                    gateway_request_id,gateway_report_source,gateway_report_id,source_revision,kind,cumulative_units,
                    delta_active,delta_reserved)
                VALUES(h.id,h.revision,'gateway:'||step.rev,p_request,step.source,step.report,step.rev,
                    CASE WHEN h.state='settled' THEN 'final_correction' WHEN step.state='settled' THEN 'final_settle'
                         WHEN delta<0 THEN 'partial_correction' ELSE 'partial_settle' END,step.settled,delta,released);
                h.state:=step.state; h.settled_units:=step.settled; h.held_units:=step.held;
            END IF;
            UPDATE openmettle.quota_reservations SET state=h.state,settled_units=h.settled_units,
                held_units=h.held_units,revision=h.revision,accepted_source_revision=step.rev,
                closed_at=CASE WHEN h.state='settled' THEN coalesce(closed_at,clock_timestamp()) END WHERE id=h.id;
        END LOOP;
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_settle_gateway_usage(uuid,uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_settle_gateway_usage(uuid,uuid,uuid,bigint) TO openmettle_gateway;

-- Caller already holds the run and gateway locks. Return a slice to a live parent, or credit budgets.
CREATE FUNCTION openmettle.quota_unwind_hold(p_id uuid,p_source text DEFAULT 'release') RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE h openmettle.quota_reservations%ROWTYPE; parent openmettle.quota_reservations%ROWTYPE;
    credit numeric;
BEGIN
    SELECT p.* INTO parent FROM openmettle.quota_reservations q JOIN openmettle.quota_reservations p
        ON p.id=q.parent_reservation_id WHERE q.id=p_id FOR NO KEY UPDATE OF p;
    SELECT * INTO STRICT h FROM openmettle.quota_reservations WHERE id=p_id FOR NO KEY UPDATE;
    IF h.state<>'held' THEN RETURN; END IF;
    credit:=-h.held_units;
    IF parent.state='held' AND EXISTS (SELECT FROM openmettle.runs WHERE id=h.run_id
        AND state NOT IN ('succeeded','failed','cancelled','interrupted')) THEN
        UPDATE openmettle.quota_reservations SET held_units=held_units+h.held_units,
            allocated_units=allocated_units-h.held_units,revision=revision+1 WHERE id=parent.id;
        credit:=0;
    END IF;
    UPDATE openmettle.quota_reservations SET held_units=0,state='released',revision=revision+1,
        closed_at=clock_timestamp() WHERE id=h.id;
    INSERT INTO openmettle.quota_reconciliations(reservation_id,transition_revision,source_key,kind,cumulative_units,
        delta_active,delta_reserved) VALUES(h.id,h.revision+1,p_source,'release',0,0,credit);
    IF credit<>0 THEN PERFORM openmettle.quota_adjust(h.id,0,credit); END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_unwind_hold(uuid,text) FROM PUBLIC;

CREATE FUNCTION openmettle.quota_unwind_request(p_id uuid,p_source text DEFAULT 'release') RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE q openmettle.gateway_requests%ROWTYPE; h openmettle.quota_reservations%ROWTYPE;
BEGIN
    SELECT * INTO STRICT q FROM openmettle.gateway_requests WHERE id=p_id FOR NO KEY UPDATE;
    IF q.state='handed_off' THEN RETURN; END IF;
    IF q.state='reserved' THEN
        UPDATE openmettle.gateway_requests SET state='released' WHERE id=q.id;
        UPDATE openmettle.gateway_reservations SET allocated=allocated-q.units WHERE id=q.reservation_id;
    END IF;
    FOR h IN SELECT * FROM openmettle.quota_reservations WHERE gateway_request_id=q.id ORDER BY resource_kind LOOP
        IF (h.scope_id,h.actor_user_id,h.run_id) IS DISTINCT FROM (q.scope_id,q.actor_user_id,q.run_id) THEN
            RAISE EXCEPTION 'gateway quota ownership mismatch' USING ERRCODE='23514';
        END IF;
        PERFORM openmettle.quota_unwind_hold(h.id,p_source);
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_unwind_request(uuid,text) FROM PUBLIC;

CREATE FUNCTION openmettle.quota_recover_lost_handoff(p_id uuid,p_dispatch bytea,p_scope uuid,p_actor uuid,p_run uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q openmettle.gateway_requests%ROWTYPE; receipt openmettle.quota_gateway_handoffs%ROWTYPE;
BEGIN
    SELECT * INTO q FROM openmettle.gateway_requests WHERE id=p_id AND scope_id=p_scope AND actor_user_id=p_actor
        AND run_id IS NOT DISTINCT FROM p_run AND octet_length(p_dispatch)=32 AND dispatch_hash=sha256(p_dispatch)
        AND pg_has_role(session_user,CASE WHEN p_run IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END,'USAGE');
    IF NOT FOUND THEN RAISE EXCEPTION 'invalid recovery authority' USING ERRCODE='42501'; END IF;
    PERFORM FROM openmettle.runs WHERE id=p_run FOR NO KEY UPDATE;
    PERFORM FROM openmettle.gateway_reservations WHERE id=q.reservation_id FOR NO KEY UPDATE;
    SELECT * INTO STRICT q FROM openmettle.gateway_requests WHERE id=p_id FOR NO KEY UPDATE;
    IF q.state<>'handed_off' THEN
        PERFORM openmettle.quota_unwind_request(q.id);
        RETURN 'unwound_unsent';
    END IF;
    SELECT * INTO receipt FROM openmettle.quota_gateway_handoffs WHERE gateway_request_id=q.id;
    IF EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=q.id AND
        (state NOT IN ('handoff_committed','settled') OR (scope_id,actor_user_id,run_id) IS DISTINCT FROM
        (q.scope_id,q.actor_user_id,q.run_id) OR (resource_kind='usage_tokens' AND reserved_units<>q.units)))
      OR (receipt.metering_enforced AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE gateway_request_id=q.id AND resource_kind='usage_tokens'))
      OR (receipt.metering_enforced AND receipt.cost_required AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE gateway_request_id=q.id AND resource_kind='usage_cost_micros')) THEN
        RAISE EXCEPTION 'gateway handoff invariant failed' USING ERRCODE='OMQ04';
    END IF;
    IF NOT EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=q.id) THEN
        RETURN 'unmetered_legacy_handoff';
    END IF;
    RETURN 'handoff_committed';
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_recover_lost_handoff(uuid,bytea,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_recover_lost_handoff(uuid,bytea,uuid,uuid,uuid) TO openmettle_api,openmettle_worker;

CREATE FUNCTION openmettle.quota_unwind_superseded_round(p_scope uuid,p_run uuid,p_claim uuid,p_round integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE allocation uuid; req uuid;
BEGIN
    PERFORM FROM openmettle.runs WHERE id=p_run AND scope_id=p_scope AND claim_token=p_claim
        AND state IN ('running','cancelling','reconciling') AND lease_expires_at>clock_timestamp() FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'stale run lease' USING ERRCODE='42501'; END IF;
    SELECT id INTO allocation FROM openmettle.gateway_reservations WHERE run_id=p_run FOR NO KEY UPDATE;
    SELECT id INTO req FROM openmettle.gateway_requests WHERE reservation_id=allocation AND round=p_round
        AND state='reserved' FOR NO KEY UPDATE;
    IF NOT FOUND OR EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=req
        AND allocating_claim_token=p_claim) THEN RETURN false; END IF;
    PERFORM openmettle.quota_unwind_request(req);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_unwind_superseded_round(uuid,uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_unwind_superseded_round(uuid,uuid,uuid,integer) TO openmettle_worker;

CREATE FUNCTION openmettle.quota_release_orphan_gateway_requests(p_max_reserved_age interval,p_after_created_at timestamptz,
    p_after_id uuid,p_pass_upper_created_at timestamptz,p_pass_upper_id uuid,p_page_size integer)
RETURNS TABLE(next_created_at timestamptz,next_id uuid,raw_keys_scanned integer,released_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    cutoff timestamptz:=clock_timestamp()-p_max_reserved_age;
    upper_at timestamptz:=least(p_pass_upper_created_at,cutoff);
    upper_id uuid:=CASE WHEN p_pass_upper_created_at>cutoff THEN 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid
        ELSE p_pass_upper_id END;
    q record;
BEGIN
    IF p_page_size IS NULL OR p_page_size NOT BETWEEN 1 AND 1000 OR p_max_reserved_age IS NULL
        OR p_max_reserved_age<=interval '0' THEN RAISE EXCEPTION 'invalid orphan page' USING ERRCODE='22023'; END IF;
    raw_keys_scanned:=0; released_count:=0; next_created_at:=p_after_created_at; next_id:=p_after_id;
    FOR q IN WITH page AS MATERIALIZED (
        SELECT created_at,id,reservation_id,run_id FROM openmettle.gateway_requests WHERE state='reserved'
            AND (created_at,id)>(p_after_created_at,p_after_id) AND (created_at,id)<=(upper_at,upper_id)
            ORDER BY created_at,id LIMIT p_page_size)
        SELECT p.*,NOT EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=p.id) AS orphan
            FROM page p ORDER BY p.created_at,p.id
    LOOP
        raw_keys_scanned:=raw_keys_scanned+1; next_created_at:=q.created_at; next_id:=q.id;
        IF NOT q.orphan THEN CONTINUE; END IF;
        IF q.run_id IS NOT NULL THEN
            PERFORM FROM openmettle.runs r WHERE id=q.run_id AND state IN ('succeeded','failed','cancelled','interrupted')
                AND NOT EXISTS (SELECT FROM openmettle.operations WHERE run_id=r.id AND outcome IN ('intent','outcome_unknown'))
                FOR NO KEY UPDATE SKIP LOCKED;
            IF NOT FOUND THEN CONTINUE; END IF;
        END IF;
        PERFORM FROM openmettle.gateway_reservations WHERE id=q.reservation_id FOR NO KEY UPDATE SKIP LOCKED;
        IF NOT FOUND THEN CONTINUE; END IF;
        PERFORM FROM openmettle.gateway_requests WHERE id=q.id AND state='reserved' FOR NO KEY UPDATE SKIP LOCKED;
        IF NOT FOUND OR EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=q.id) THEN CONTINUE; END IF;
        PERFORM openmettle.quota_unwind_request(q.id);
        released_count:=1; EXIT;
    END LOOP;
    RETURN NEXT;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_release_orphan_gateway_requests(interval,timestamptz,uuid,timestamptz,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_release_orphan_gateway_requests(interval,timestamptz,uuid,timestamptz,uuid,integer) TO openmettle_worker;

CREATE FUNCTION openmettle.quota_renew_lease(p_id uuid,p_run uuid,p_claim uuid,p_until timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE deadline timestamptz;
BEGIN
    SELECT execution_expires_at INTO deadline FROM openmettle.runs WHERE id=p_run AND claim_token=p_claim
        AND state='running' AND cancel_reason IS NULL AND lease_expires_at>clock_timestamp() FOR NO KEY UPDATE;
    IF NOT FOUND OR p_until IS NULL OR p_until<=clock_timestamp() THEN RETURN false; END IF;
    UPDATE openmettle.quota_reservations SET lease_expires_at=least(deadline,p_until)
        WHERE id=p_id AND run_id=p_run AND state='held';
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_renew_lease(uuid,uuid,uuid,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_renew_lease(uuid,uuid,uuid,timestamptz) TO openmettle_worker;

-- Runs are always locked before their holds. The same transaction that parks or renews
-- the run extends its outstanding reservations, including storage spills.
CREATE FUNCTION openmettle.quota_follow_run_deadline() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE deadline timestamptz;
BEGIN
    IF NEW.state='running' AND NEW.cancel_reason IS NULL THEN
        deadline:=NEW.execution_expires_at;
    ELSIF NEW.state='waiting' AND NEW.wait_reason='approval' THEN
        SELECT resume_execution_expires_at INTO deadline FROM openmettle.run_approvals
         WHERE scope_id=NEW.scope_id AND run_id=NEW.id AND id=NEW.approval_wait_id;
    END IF;
    IF deadline IS NOT NULL THEN
        UPDATE openmettle.quota_reservations SET lease_expires_at=deadline
         WHERE run_id=NEW.id AND scope_id=NEW.scope_id AND state='held'
           AND lease_expires_at IS DISTINCT FROM deadline;
        UPDATE openmettle.storage_reservations SET lease_expires_at=deadline
         WHERE run_id=NEW.id AND scope_id=NEW.scope_id AND state='reserved'
           AND NOT adoption_unverified AND reclaim_state='none' AND lease_expires_at IS DISTINCT FROM deadline;
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_follow_run_deadline() FROM PUBLIC;
CREATE TRIGGER quota_run_deadline_guard AFTER UPDATE OF state,lease_expires_at,approval_wait_id ON openmettle.runs
    FOR EACH ROW WHEN (NEW.state IN ('running','waiting')) EXECUTE FUNCTION openmettle.quota_follow_run_deadline();

CREATE FUNCTION openmettle.quota_release_unsent(p_id uuid,p_dispatch bytea DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE h openmettle.quota_reservations%ROWTYPE; q openmettle.gateway_requests%ROWTYPE;
    sweep boolean:=p_dispatch IS NULL AND pg_has_role(session_user,'openmettle_worker','USAGE');
BEGIN
    SELECT * INTO h FROM openmettle.quota_reservations WHERE id=p_id AND state='held';
    IF NOT FOUND THEN RETURN false; END IF;
    IF NOT sweep AND NOT pg_has_role(session_user,'openmettle_'||h.origin_role,'USAGE') THEN
        RAISE EXCEPTION 'invalid release authority' USING ERRCODE='42501'; END IF;
    IF h.run_id IS NOT NULL THEN
        PERFORM FROM openmettle.runs r WHERE id=h.run_id AND (NOT sweep OR (r.state IN ('succeeded','failed','cancelled','interrupted')
            AND NOT EXISTS (SELECT FROM openmettle.operations WHERE run_id=r.id AND outcome IN ('intent','outcome_unknown'))))
            FOR NO KEY UPDATE SKIP LOCKED;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    IF h.gateway_request_id IS NOT NULL THEN
        SELECT * INTO STRICT q FROM openmettle.gateway_requests WHERE id=h.gateway_request_id;
        IF NOT sweep AND (p_dispatch IS NULL OR octet_length(p_dispatch)<>32 OR q.dispatch_hash<>sha256(p_dispatch)) THEN
            RAISE EXCEPTION 'invalid release authority' USING ERRCODE='42501'; END IF;
        PERFORM FROM openmettle.gateway_reservations WHERE id=q.reservation_id FOR NO KEY UPDATE SKIP LOCKED;
        IF NOT FOUND THEN RETURN false; END IF;
        SELECT * INTO q FROM openmettle.gateway_requests WHERE id=h.gateway_request_id FOR NO KEY UPDATE SKIP LOCKED;
        IF NOT FOUND OR q.state='handed_off' OR (NOT sweep AND q.state<>'released') THEN RETURN false; END IF;
    END IF;
    IF h.parent_reservation_id IS NOT NULL THEN
        PERFORM FROM openmettle.quota_reservations WHERE id=h.parent_reservation_id FOR NO KEY UPDATE SKIP LOCKED;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    SELECT * INTO h FROM openmettle.quota_reservations WHERE id=p_id AND state='held'
        AND (NOT sweep OR lease_expires_at<=clock_timestamp()) FOR NO KEY UPDATE SKIP LOCKED;
    IF NOT FOUND THEN RETURN false; END IF;
    IF h.gateway_request_id IS NOT NULL THEN
        IF (h.scope_id,h.actor_user_id,h.run_id) IS DISTINCT FROM (q.scope_id,q.actor_user_id,q.run_id) THEN
            RAISE EXCEPTION 'gateway quota ownership mismatch' USING ERRCODE='23514';
        END IF;
        IF q.state='reserved' THEN
            UPDATE openmettle.gateway_requests SET state='released' WHERE id=q.id;
            UPDATE openmettle.gateway_reservations SET allocated=allocated-q.units WHERE id=q.reservation_id;
        END IF;
    END IF;
    PERFORM openmettle.quota_unwind_hold(h.id,CASE WHEN sweep THEN 'stale_sweep' ELSE 'release' END);
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_release_unsent(uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_release_unsent(uuid,bytea) TO openmettle_api,openmettle_worker;

CREATE FUNCTION openmettle.quota_commit_device_handoff(p_hold uuid,p_scope uuid,p_run uuid,p_claim uuid,p_grant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM FROM openmettle.runs WHERE scope_id=p_scope AND id=p_run AND state='running' AND cancel_reason IS NULL
        AND claim_token=p_claim AND lease_expires_at>clock_timestamp() FOR NO KEY UPDATE;
    IF NOT FOUND OR p_grant IS NULL THEN RAISE EXCEPTION 'invalid device handoff' USING ERRCODE='42501'; END IF;
    UPDATE openmettle.quota_reservations SET state='handoff_committed',device_grant_id=p_grant,revision=revision+1
        WHERE id=p_hold AND scope_id=p_scope AND run_id=p_run AND state='held' AND resource_kind='device_reservations';
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_commit_device_handoff(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_commit_device_handoff(uuid,uuid,uuid,uuid,uuid) TO openmettle_worker;

CREATE FUNCTION openmettle.quota_lock_override(p_scope uuid,p_actor uuid,p_resource text)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE sc openmettle.scopes%ROWTYPE;
BEGIN
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR NO KEY UPDATE;
    IF NOT EXISTS (SELECT FROM openmettle.account_admins a JOIN openmettle.users u ON u.id=a.user_id
        WHERE a.user_id=p_actor AND a.active AND u.disabled_at IS NULL) THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE='42501';
    END IF;
    IF p_resource IN ('executing_runs_per_actor','executing_runs_per_scope') THEN
        PERFORM FROM openmettle.run_dispatch_lock WHERE id FOR NO KEY UPDATE;
    END IF;
    SELECT * INTO STRICT sc FROM openmettle.scopes WHERE id=p_scope;
    IF sc.kind='project' THEN PERFORM FROM openmettle.projects WHERE id=sc.project_id FOR NO KEY UPDATE;
    ELSE PERFORM FROM openmettle.users WHERE id=sc.personal_user_id FOR NO KEY UPDATE; END IF;
    IF p_resource='storage_bytes' THEN
        INSERT INTO openmettle.storage_accounts (scope_id) VALUES(p_scope) ON CONFLICT DO NOTHING;
        PERFORM FROM openmettle.storage_accounts WHERE scope_id=p_scope FOR UPDATE;
    ELSE
        PERFORM FROM openmettle.quota_budgets WHERE scope_id=p_scope AND resource_kind=p_resource
            ORDER BY window_start,id FOR NO KEY UPDATE;
    END IF;
    RETURN sc.kind;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_lock_override(uuid,uuid,text) FROM PUBLIC;

CREATE FUNCTION openmettle.quota_upsert_scope_override(p_scope uuid,p_actor uuid,p_resource text,p_limit bigint,
    p_expires timestamptz,p_reason text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; ver bigint; prior bigint;
BEGIN
    kind:=openmettle.quota_lock_override(p_scope,p_actor,p_resource);
    IF p_resource='usage_cost_micros' AND NOT EXISTS (SELECT FROM openmettle.quota_defaults
        WHERE scope_kind='instance' AND resource_kind=p_resource AND cost_denomination IS NOT NULL) THEN
        RAISE EXCEPTION 'cost denomination required' USING ERRCODE='OMQ02';
    END IF;
    SELECT hard_limit INTO prior FROM openmettle.quota_overrides WHERE scope_id=p_scope AND resource_kind=p_resource
        AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp());
    INSERT INTO openmettle.quota_overrides AS o(scope_id,scope_kind,resource_kind,hard_limit,expires_at,reason,updated_by_user_id)
        VALUES(p_scope,kind,p_resource,p_limit,p_expires,p_reason,p_actor)
        ON CONFLICT(scope_id,resource_kind) DO UPDATE SET hard_limit=excluded.hard_limit,expires_at=excluded.expires_at,
        revoked_at=NULL,reason=excluded.reason,updated_by_user_id=p_actor,updated_at=clock_timestamp(),revision=o.revision+1
        RETURNING revision INTO ver;
    INSERT INTO openmettle.authorization_audit(actor_user_id,action,target_kind,target_id,request_key,reason,details)
        VALUES(p_actor,'quota.override.set','quota_scope',p_scope::text,gen_random_uuid()::text,p_reason,
            jsonb_build_object('scope_id',p_scope,'resource_kind',p_resource,'old_limit',prior,'new_limit',p_limit,
                'expires_at',p_expires,'revision',ver));
    RETURN ver;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_upsert_scope_override(uuid,uuid,text,bigint,timestamptz,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_upsert_scope_override(uuid,uuid,text,bigint,timestamptz,text) TO openmettle_api;

CREATE FUNCTION openmettle.quota_revoke_scope_override(p_scope uuid,p_actor uuid,p_resource text,p_reason text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE ver bigint; prior bigint;
BEGIN
    PERFORM openmettle.quota_lock_override(p_scope,p_actor,p_resource);
    UPDATE openmettle.quota_overrides SET revoked_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp(),
        updated_by_user_id=p_actor,reason=p_reason WHERE scope_id=p_scope AND resource_kind=p_resource AND revoked_at IS NULL
        RETURNING revision,hard_limit INTO ver,prior;
    IF FOUND THEN
        INSERT INTO openmettle.authorization_audit(actor_user_id,action,target_kind,target_id,request_key,reason,details)
            VALUES(p_actor,'quota.override.revoke','quota_scope',p_scope::text,gen_random_uuid()::text,p_reason,
                jsonb_build_object('scope_id',p_scope,'resource_kind',p_resource,'old_limit',prior,'new_limit',NULL,
                    'expires_at',NULL,'revision',ver));
    END IF;
    RETURN ver;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_revoke_scope_override(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_revoke_scope_override(uuid,uuid,text,text) TO openmettle_api;

CREATE FUNCTION openmettle.quota_record_storage_warning(p_scope uuid,p_added bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a openmettle.storage_accounts%ROWTYPE; i openmettle.storage_instance%ROWTYPE;
    charged numeric; lim bigint; rev bigint; bucket timestamptz:=date_trunc('day',clock_timestamp(),'UTC');
BEGIN
    SELECT * INTO STRICT a FROM openmettle.storage_accounts WHERE scope_id=p_scope FOR UPDATE;
    SELECT * INTO STRICT i FROM openmettle.storage_instance WHERE id FOR NO KEY UPDATE;
    SELECT coalesce(CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at>statement_timestamp()) THEN o.hard_limit END,CASE WHEN s.kind='personal' THEN i.personal_limit_bytes ELSE i.project_limit_bytes END),
        coalesce(o.revision,0) INTO STRICT lim,rev FROM openmettle.scopes s LEFT JOIN openmettle.quota_overrides o
        ON o.scope_id=s.id AND o.resource_kind='storage_bytes'
        WHERE s.id=p_scope;
    charged:=a.active_bytes::numeric+a.retained_bytes+a.reserved_bytes;
    PERFORM openmettle.quota_warn('scope',p_scope,'storage_bytes',bucket,charged-p_added,charged,lim,i.warn_pct_1,i.warn_pct_2,i.config_revision,rev);
    charged:=i.active_bytes::numeric+i.retained_bytes+i.reserved_bytes;
    PERFORM openmettle.quota_warn('instance',NULL,'storage_bytes',bucket,charged-p_added,charged,i.instance_budget_bytes,
        i.warn_pct_1,i.warn_pct_2,i.config_revision,0);
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_record_storage_warning(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_record_storage_warning(uuid,bigint) TO openmettle_api,openmettle_worker;

CREATE FUNCTION openmettle.quota_verify_accounting_drift()
RETURNS TABLE(storage_mismatches bigint,budget_mismatches bigint,settlement_mismatches bigint,
              pending_gateway_reconciliations bigint,oldest_pending_age interval)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    WITH storage AS (
        SELECT a.scope_id,a.active_bytes,a.retained_bytes,a.reserved_bytes,
            coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions
                WHERE scope_id=a.scope_id AND state='active'),0) AS active,
            coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions
                WHERE scope_id=a.scope_id AND state IN ('retained','purging')),0) AS retained,
            coalesce((SELECT sum(max_bytes) FROM openmettle.storage_reservations
                WHERE scope_id=a.scope_id AND state='reserved'),0) AS reserved FROM openmettle.storage_accounts a
    ), storage_errors AS (
        SELECT FROM storage WHERE (active_bytes,retained_bytes,reserved_bytes)<>(active,retained,reserved)
        UNION ALL SELECT FROM openmettle.storage_instance i WHERE
            (i.active_bytes,i.retained_bytes,i.reserved_bytes)<>(SELECT coalesce(sum(active),0),coalesce(sum(retained),0),
                coalesce(sum(reserved),0) FROM storage)
    ), applied AS (
        SELECT h.* FROM openmettle.quota_reservations h WHERE gateway_request_id IS NOT NULL
            AND state IN ('handoff_committed','settled')
    ), gateway_errors AS (
        SELECT FROM applied h LEFT JOIN LATERAL (SELECT * FROM openmettle.quota_gateway_fold(
            h.gateway_request_id,h.resource_kind,h.reserved_units,h.accepted_source_revision)
            ORDER BY rev DESC LIMIT 1) f ON true
            WHERE (h.state,h.settled_units,h.held_units) IS DISTINCT FROM
            (coalesce(f.state,'handoff_committed'),coalesce(f.settled,0),coalesce(f.held,h.reserved_units))
        UNION ALL SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id IS NOT NULL
            AND h.state='held' AND (h.accepted_source_revision IS NOT NULL OR h.settled_units<>0 OR h.held_units<>h.reserved_units)
        UNION ALL SELECT FROM openmettle.quota_gateway_handoffs receipt JOIN openmettle.gateway_requests q
            ON q.id=receipt.gateway_request_id WHERE q.state<>'handed_off'
            OR EXISTS (SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=q.id AND
                (h.state NOT IN ('handoff_committed','settled') OR (h.scope_id,h.actor_user_id,h.run_id) IS DISTINCT FROM
                (q.scope_id,q.actor_user_id,q.run_id) OR (h.resource_kind='usage_tokens' AND h.reserved_units<>q.units)))
            OR (receipt.metering_enforced AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                WHERE h.gateway_request_id=q.id AND h.resource_kind='usage_tokens'))
            OR (receipt.metering_enforced AND receipt.cost_required AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                WHERE h.gateway_request_id=q.id AND h.resource_kind='usage_cost_micros'))
        UNION ALL SELECT FROM openmettle.gateway_settlements gs JOIN openmettle.gateway_usage_reports gr
            USING(request_id,revision,final) WHERE gs.measured IS DISTINCT FROM CASE
            WHEN num_nonnulls(gr.prompt_tokens,gr.completion_tokens,gr.reasoning_tokens)=0 THEN NULL
            ELSE coalesce(gr.prompt_tokens,0)::numeric+CASE WHEN gr.reasoning_included THEN
            greatest(coalesce(gr.completion_tokens,0),coalesce(gr.reasoning_tokens,0))::numeric
            ELSE coalesce(gr.completion_tokens,0)::numeric+coalesce(gr.reasoning_tokens,0) END END
    ), pending AS (
        SELECT h.id,min(a.accepted_at) AS oldest FROM applied h
        JOIN openmettle.quota_accepted_gateway_reports a ON a.request_id=h.gateway_request_id
            AND a.revision>coalesce(h.accepted_source_revision,-1) GROUP BY h.id
    )
    SELECT (SELECT count(*) FROM storage_errors),
        (SELECT count(*) FROM openmettle.quota_budgets b WHERE b.reserved_held<>(SELECT coalesce(sum(h.held_units),0)
             FROM openmettle.quota_reservation_charges c JOIN openmettle.quota_reservations h ON h.id=c.reservation_id
             WHERE c.budget_id=b.id AND h.state IN ('held','handoff_committed'))
         OR b.active_used<>(SELECT coalesce(sum(rec.delta_active),0) FROM openmettle.quota_reservation_charges c
             JOIN openmettle.quota_reconciliations rec USING(reservation_id) WHERE c.budget_id=b.id)),
        (SELECT count(*) FROM gateway_errors),(SELECT count(*) FROM pending),(SELECT now()-min(oldest) FROM pending)
$$;
REVOKE ALL ON FUNCTION openmettle.quota_verify_accounting_drift() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_verify_accounting_drift() TO openmettle_worker;

-- Only V1-18 can attest that the device backend released a grant or never allocated it.
-- Until that durable record exists, timeouts and worker assertions cannot credit a slot.
CREATE FUNCTION openmettle.quota_release_device_slot(p_hold uuid,p_grant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF EXISTS (SELECT FROM openmettle.quota_reservations WHERE id=p_hold AND device_grant_id=p_grant
            AND resource_kind='device_reservations' AND state='handoff_committed') THEN
        RAISE EXCEPTION 'durable device release evidence required' USING ERRCODE='OMQ06';
    END IF;
    RETURN false;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_release_device_slot(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_release_device_slot(uuid,uuid) TO openmettle_worker;

-- A standalone device hold has no gateway request. A run-owned slot must use the fenced worker function.
CREATE FUNCTION openmettle.quota_commit_handoff(p_hold uuid,p_grant uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE h openmettle.quota_reservations%ROWTYPE;
BEGIN
    SELECT * INTO STRICT h FROM openmettle.quota_reservations WHERE id=p_hold FOR NO KEY UPDATE;
    IF h.run_id IS NOT NULL OR h.resource_kind<>'device_reservations' OR p_grant IS NULL
            OR NOT pg_has_role(session_user,'openmettle_'||h.origin_role,'USAGE') THEN
        RAISE EXCEPTION 'invalid device handoff' USING ERRCODE='42501';
    END IF;
    IF h.state<>'held' THEN RETURN false; END IF;
    UPDATE openmettle.quota_reservations SET device_grant_id=p_grant,state='handoff_committed',revision=revision+1
        WHERE id=h.id;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_commit_handoff(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_commit_handoff(uuid,uuid) TO openmettle_api,openmettle_worker;


CREATE FUNCTION openmettle.quota_bump_config_revision()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    NEW.config_revision:=OLD.config_revision+1;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_bump_config_revision() FROM PUBLIC;
CREATE TRIGGER quota_defaults_config_revision BEFORE UPDATE ON openmettle.quota_defaults
    FOR EACH ROW WHEN ((OLD.hard_limit,OLD.window_seconds,OLD.cost_denomination,OLD.warn_pct_1,OLD.warn_pct_2)
    IS DISTINCT FROM (NEW.hard_limit,NEW.window_seconds,NEW.cost_denomination,NEW.warn_pct_1,NEW.warn_pct_2))
    EXECUTE FUNCTION openmettle.quota_bump_config_revision();
CREATE TRIGGER storage_instance_config_revision BEFORE UPDATE ON openmettle.storage_instance
    FOR EACH ROW WHEN ((OLD.instance_budget_bytes,OLD.personal_limit_bytes,OLD.project_limit_bytes,OLD.warn_pct_1,OLD.warn_pct_2)
    IS DISTINCT FROM (NEW.instance_budget_bytes,NEW.personal_limit_bytes,NEW.project_limit_bytes,NEW.warn_pct_1,NEW.warn_pct_2))
    EXECUTE FUNCTION openmettle.quota_bump_config_revision();
