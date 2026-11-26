-- V1-18 migration 40: API capacity visibility, dispatch/release fencing and cardinality bounds (ADR 0042, PR3).
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- openmettle_owner configures capacity_profiles. openmettle_api reads capacity_profiles directly
-- and inspects group/device observations only through openmettle.capacity_group_observations(),
-- a STABLE SECURITY DEFINER read helper that never exposes controller_token_hash or per-tenant
-- capacity_grants rows.
--
-- capacity_groups gains backend_unknown (default false) so takeover reconciliation durably closes
-- the group in PostgreSQL before contacting the backend and keeps bursts closed while any backend
-- rogue allocation remains unresolved.
--
-- capacity_grants gains dispatch_state ('pending' | 'in_flight' | 'confirmed' |
-- 'release_in_flight', default 'pending'), dispatch_epoch and extra_devices (default '{}') so
-- low-level capacity_grant rows never masquerade as confirmed dispatches, two-phase
-- commit-before-dispatch and release-in-flight close bursts during adapter calls, and backend-only
-- extra ranks cannot be lost across later release attempts.

ALTER TABLE openmettle.capacity_groups
    ADD COLUMN backend_unknown boolean NOT NULL DEFAULT false;

ALTER TABLE openmettle.capacity_grants
    ADD COLUMN dispatch_state text NOT NULL DEFAULT 'pending'
        CHECK (dispatch_state IN ('pending', 'in_flight', 'confirmed', 'release_in_flight')),
    ADD COLUMN dispatch_epoch bigint
        CHECK (dispatch_epoch IS NULL OR dispatch_epoch >= granted_epoch),
    ADD COLUMN extra_devices uuid[] NOT NULL DEFAULT '{}'::uuid[];

UPDATE openmettle.capacity_grants
   SET dispatch_state = 'confirmed'
 WHERE state = 'released';

ALTER TABLE openmettle.capacity_grants
    ADD CONSTRAINT capacity_grants_released_settled_check
        CHECK (state <> 'released' OR (dispatch_state = 'confirmed' AND cardinality(extra_devices) = 0));

CREATE TABLE openmettle.capacity_profiles (
    profile text PRIMARY KEY
        CHECK (octet_length(profile) BETWEEN 1 AND 128 AND btrim(profile) = profile),
    group_id uuid NOT NULL REFERENCES openmettle.capacity_groups (id),
    per_device_bytes bigint NOT NULL CHECK (per_device_bytes > 0),
    required_devices integer NOT NULL CHECK (required_devices BETWEEN 1 AND 64),
    required_capability text
        CHECK (required_capability IS NULL
               OR (octet_length(required_capability) BETWEEN 1 AND 128
                   AND required_capability ~ '^[a-z0-9._-]+$')),
    capability_gate text NOT NULL DEFAULT 'on_by_default'
        CHECK (capability_gate IN ('on_by_default', 'opt_in')),
    CHECK (capability_gate <> 'opt_in' OR required_capability IS NOT NULL),
    model_id text
        CHECK (model_id IS NULL
               OR (octet_length(model_id) BETWEEN 1 AND 128 AND btrim(model_id) = model_id)),
    estimated_wait_seconds integer
        CHECK (estimated_wait_seconds IS NULL OR estimated_wait_seconds BETWEEN 1 AND 86400)
);
GRANT SELECT ON openmettle.capacity_profiles TO openmettle_api;

-- OpenAPI v1 cardinality ceilings: <= 256 profiles, <= 64 groups, <= 64 devices per group.
-- All three triggers require READ COMMITTED so concurrent transactions cannot bypass the count
-- check via repeatable-read snapshots.
CREATE FUNCTION openmettle.capacity_enforce_profile_limit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'capacity configuration writes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM pg_advisory_xact_lock(729401, 1);
    IF (SELECT count(*) FROM openmettle.capacity_profiles) >= 256 THEN
        RAISE EXCEPTION 'capacity profile limit exceeded' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_enforce_profile_limit() FROM PUBLIC;
CREATE TRIGGER capacity_profiles_enforce_limit
    BEFORE INSERT ON openmettle.capacity_profiles
    FOR EACH ROW EXECUTE FUNCTION openmettle.capacity_enforce_profile_limit();

CREATE FUNCTION openmettle.capacity_enforce_group_limit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'capacity configuration writes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM pg_advisory_xact_lock(729401, 2);
    IF (SELECT count(*) FROM openmettle.capacity_groups) >= 64 THEN
        RAISE EXCEPTION 'capacity group limit exceeded' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_enforce_group_limit() FROM PUBLIC;
CREATE TRIGGER capacity_groups_enforce_limit
    BEFORE INSERT ON openmettle.capacity_groups
    FOR EACH ROW EXECUTE FUNCTION openmettle.capacity_enforce_group_limit();

CREATE FUNCTION openmettle.capacity_enforce_device_limit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'capacity configuration writes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF (SELECT count(*) FROM openmettle.capacity_devices WHERE group_id = NEW.group_id) >= 64 THEN
        RAISE EXCEPTION 'capacity group device limit exceeded' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_enforce_device_limit() FROM PUBLIC;
-- Runs alphabetically after capacity_devices_lock_group so the owning group row is locked first.
CREATE TRIGGER capacity_devices_z_enforce_limit
    BEFORE INSERT ON openmettle.capacity_devices
    FOR EACH ROW EXECUTE FUNCTION openmettle.capacity_enforce_device_limit();

-- Shared readiness predicate parameterized by an optional grant to exclude during that grant's
-- own in-flight prepare/retry check. Any unresolved backend_unknown, unknown_allocation,
-- in_flight/release_in_flight coordinator phase, or unattested grant closes the group to bursts.
CREATE FUNCTION openmettle.capacity_admits_excluding(
    p_group uuid,
    p_resuming boolean,
    p_exclude_grant uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
    WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT coalesce((
        SELECT (p_resuming OR g.ready_epoch = g.controller_epoch)
           AND NOT g.backend_unknown
           AND g.lease_expires_at > t.now
           AND g.observation_epoch = g.controller_epoch
           AND g.observed_at + g.observation_ttl_ms * interval '1 millisecond' > t.now
           AND EXISTS (SELECT FROM openmettle.capacity_devices d WHERE d.group_id = g.id)
           AND NOT EXISTS (
               SELECT
                 FROM openmettle.capacity_grants c
                WHERE c.group_id = g.id
                  AND c.state <> 'released'
                  AND (p_exclude_grant IS NULL OR c.id <> p_exclude_grant)
                  AND (c.state = 'unknown_allocation'
                       OR c.dispatch_state IN ('in_flight', 'release_in_flight')
                       OR c.reconciled_epoch < g.controller_epoch))
           AND NOT EXISTS (
               SELECT
                 FROM openmettle.capacity_devices d
                 LEFT JOIN openmettle.capacity_observations o
                   ON o.group_id = g.id AND o.device_id = d.id
                  AND o.revision = g.observation_revision
                WHERE d.group_id = g.id
                  AND (o.device_id IS NULL OR o.active_chat_floor_bytes < d.chat_floor_bytes))
          FROM openmettle.capacity_groups g
         WHERE g.id = p_group), false)
      FROM t
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_admits_excluding(uuid, boolean, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_admits_excluding(uuid, boolean, uuid) TO openmettle_worker;

CREATE OR REPLACE FUNCTION openmettle.capacity_admits(p_group uuid, p_resuming boolean)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
    SELECT openmettle.capacity_admits_excluding(p_group, p_resuming, NULL::uuid)
$$;

-- Durable backend-unknown fence toggled around takeover inventory reconciliation. Setting
-- p_unknown = true also clears ready_epoch so bursts remain closed until recovery finishes cleanly.
CREATE FUNCTION openmettle.capacity_set_backend_unknown(
    p_group uuid,
    p_secret bytea,
    p_epoch bigint,
    p_unknown boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_unknown IS NULL THEN
        RAISE EXCEPTION 'invalid backend state' USING ERRCODE = '22023';
    END IF;
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    IF p_unknown THEN
        UPDATE openmettle.capacity_groups
           SET backend_unknown = true,
               ready_epoch = NULL
         WHERE id = p_group;
    ELSE
        UPDATE openmettle.capacity_groups
           SET backend_unknown = false
         WHERE id = p_group;
    END IF;
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_set_backend_unknown(uuid, bytea, bigint, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_set_backend_unknown(uuid, bytea, bigint, boolean) TO openmettle_worker;

-- Verify the controller holds a committed, live lease for p_epoch before sending a fenced backend
-- command such as reclaim_kv.
CREATE FUNCTION openmettle.capacity_check_controller(
    p_group uuid,
    p_secret bytea,
    p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_check_controller(uuid, bytea, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_check_controller(uuid, bytea, bigint) TO openmettle_worker;

-- Prepare fenced release of a grant before contacting the backend: closes bursts via
-- dispatch_state = 'release_in_flight' and durably merges any extra backend-only devices so later
-- release attempts cannot settle the grant while an extra rank remains unconfirmed.
CREATE FUNCTION openmettle.capacity_prepare_release(
    p_group uuid,
    p_secret bytea,
    p_epoch bigint,
    p_grant uuid,
    p_extra_devices uuid[]
)
RETURNS TABLE (
    grant_state text,
    unreleased_devices uuid[],
    extra_devices uuid[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v openmettle.capacity_grants%ROWTYPE;
    v_next_state text;
    v_extra uuid[];
    v_unreleased uuid[];
BEGIN
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    SELECT * INTO v
      FROM openmettle.capacity_grants
     WHERE id = p_grant AND group_id = p_group
       FOR NO KEY UPDATE;
    IF NOT FOUND
       OR (p_extra_devices IS NOT NULL
           AND EXISTS (SELECT FROM unnest(p_extra_devices) AS x WHERE x IS NULL)) THEN
        RAISE EXCEPTION 'invalid capacity release preparation' USING ERRCODE = '22023';
    END IF;
    IF v.state = 'released' THEN
        PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
        RETURN QUERY SELECT 'released'::text, '{}'::uuid[], '{}'::uuid[];
        RETURN;
    END IF;
    SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{}'::uuid[])
      INTO v_extra
      FROM unnest(v.extra_devices || coalesce(p_extra_devices, '{}'::uuid[])) AS x
     WHERE NOT EXISTS (
         SELECT FROM openmettle.capacity_grant_devices gd
          WHERE gd.grant_id = p_grant AND gd.device_id = x AND gd.released_at IS NULL
     );
    v_next_state := CASE WHEN v.state = 'granted' THEN 'releasing' ELSE v.state END;
    UPDATE openmettle.capacity_grants
       SET state = v_next_state,
           dispatch_state = 'release_in_flight',
           extra_devices = v_extra
     WHERE id = p_grant;
    SELECT coalesce(array_agg(gd.device_id ORDER BY gd.device_id), '{}'::uuid[])
      INTO v_unreleased
      FROM openmettle.capacity_grant_devices gd
     WHERE gd.grant_id = p_grant AND gd.released_at IS NULL;
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    RETURN QUERY SELECT v_next_state, v_unreleased, v_extra;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_prepare_release(uuid, bytea, bigint, uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_prepare_release(uuid, bytea, bigint, uuid, uuid[]) TO openmettle_worker;

-- Extend migration 27's capacity_reconcile so attesting 'allocated' requires zero persisted
-- extra_devices and marks dispatch_state = 'confirmed', and release evidence settles the grant
-- only once every durable device AND every persisted extra device has confirmed.
CREATE OR REPLACE FUNCTION openmettle.capacity_reconcile(
    p_group uuid,
    p_secret bytea,
    p_epoch bigint,
    p_grant uuid,
    p_evidence text,
    p_devices uuid[]
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
    v openmettle.capacity_grants%ROWTYPE;
    v_state text;
    v_rem_extra uuid[];
BEGIN
    g := openmettle.capacity_fence(p_group, p_secret, p_epoch);
    SELECT * INTO v
      FROM openmettle.capacity_grants
     WHERE id = p_grant AND group_id = p_group
       FOR NO KEY UPDATE;
    IF NOT FOUND OR p_evidence IS NULL OR p_evidence NOT IN (
           'allocated', 'releasing', 'unknown_allocation', 'released', 'not_allocated') THEN
        RAISE EXCEPTION 'invalid capacity reconciliation' USING ERRCODE = '22023';
    END IF;
    v_state := v.state;
    IF v.state = 'released' THEN
        NULL;
    ELSIF p_evidence = 'allocated' THEN
        IF v.state = 'unknown_allocation' OR cardinality(v.extra_devices) > 0 THEN
            RAISE EXCEPTION 'an unknown allocation resolves only through release evidence'
                USING ERRCODE = '22023';
        END IF;
        UPDATE openmettle.capacity_grants
           SET reconciled_epoch = g.controller_epoch,
               dispatch_state = 'confirmed'
         WHERE id = p_grant;
    ELSIF p_evidence = 'releasing' THEN
        IF v.state = 'granted' THEN
            UPDATE openmettle.capacity_grants SET state = 'releasing' WHERE id = p_grant;
            v_state := 'releasing';
        END IF;
    ELSIF p_evidence = 'unknown_allocation' THEN
        UPDATE openmettle.capacity_grants SET state = 'unknown_allocation' WHERE id = p_grant;
        v_state := 'unknown_allocation';
    ELSE
        IF coalesce(cardinality(p_devices), 0) = 0 OR EXISTS (
            SELECT FROM unnest(p_devices) AS d(device_id)
             WHERE d.device_id IS NULL
                OR (NOT EXISTS (
                        SELECT FROM openmettle.capacity_grant_devices gd
                         WHERE gd.grant_id = p_grant AND gd.device_id = d.device_id
                    )
                    AND NOT (d.device_id = ANY (v.extra_devices)))
        ) THEN
            RAISE EXCEPTION 'invalid capacity reconciliation' USING ERRCODE = '22023';
        END IF;
        UPDATE openmettle.capacity_grant_devices
           SET release_evidence = p_evidence,
               released_epoch = g.controller_epoch,
               released_at = clock_timestamp()
         WHERE grant_id = p_grant AND device_id = ANY (p_devices) AND released_at IS NULL;
        SELECT coalesce(array_agg(x ORDER BY x), '{}'::uuid[])
          INTO v_rem_extra
          FROM unnest(v.extra_devices) AS x
         WHERE NOT (x = ANY (p_devices));
        IF EXISTS (
            SELECT FROM openmettle.capacity_grant_devices
             WHERE grant_id = p_grant AND released_at IS NULL
        ) OR cardinality(v_rem_extra) > 0 THEN
            UPDATE openmettle.capacity_grants
               SET state = 'unknown_allocation',
                   extra_devices = v_rem_extra
             WHERE id = p_grant;
            v_state := 'unknown_allocation';
        ELSE
            UPDATE openmettle.capacity_grants
               SET state = 'released',
                   dispatch_state = 'confirmed',
                   extra_devices = '{}'::uuid[],
                   released_epoch = g.controller_epoch,
                   released_at = clock_timestamp()
             WHERE id = p_grant;
            v_state := 'released';
            IF v.quota_hold_id IS NOT NULL THEN
                PERFORM openmettle.quota_release_device_slot(v.quota_hold_id, v.id);
            END IF;
        END IF;
    END IF;
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    RETURN v_state;
END;
$$;

-- Two-phase grant preparation for adapter dispatch: commits a new grant with
-- dispatch_state = 'in_flight' and dispatch_epoch = g.controller_epoch (blocking concurrent bursts
-- until confirmed or reconciled). Replaying an already-settled or dispatch-confirmed grant returns
-- action = 'already_settled' without touching the backend; retrying an unconfirmed ('pending' or
-- 'in_flight') grant re-verifies the run's active claim, readiness, watermark and per-device fit
-- before authorizing dispatch.
CREATE FUNCTION openmettle.capacity_prepare_dispatch(
    p_group uuid,
    p_secret bytea,
    p_epoch bigint,
    p_scope uuid,
    p_run uuid,
    p_claim uuid,
    p_request_key text,
    p_profile text,
    p_footprint jsonb
)
RETURNS TABLE (
    grant_ref uuid,
    outcome text,
    action text,
    is_replay boolean,
    observation_stale boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
    v_existing openmettle.capacity_grants%ROWTYPE;
    v_digest bytea;
    v_holds uuid[];
    v_enforced boolean;
    v_seq bigint;
    v_id uuid;
    v_stale boolean;
BEGIN
    IF p_request_key IS NULL OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR p_profile IS NULL OR octet_length(p_profile) NOT BETWEEN 1 AND 128
       OR jsonb_typeof(p_footprint) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_footprint) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'invalid capacity request' USING ERRCODE = '22023';
    END IF;
    SELECT sha256(convert_to(jsonb_build_array(
               p_group, p_run, p_profile,
               jsonb_agg(jsonb_build_array(f.device_id, f.bytes) ORDER BY f.device_id))::text, 'UTF8'))
      INTO v_digest
      FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint);

    -- Lock order: runs -> capacity_groups -> capacity_grants -> quota_reservations -> quota_enforcement.
    PERFORM FROM openmettle.runs WHERE scope_id = p_scope AND id = p_run FOR NO KEY UPDATE;
    g := openmettle.capacity_fence(p_group, p_secret, p_epoch);

    SELECT * INTO v_existing
      FROM openmettle.capacity_grants c
     WHERE c.scope_id = p_scope AND c.request_key = p_request_key
       FOR NO KEY UPDATE;
    IF FOUND THEN
        IF v_existing.request_digest <> v_digest THEN
            RAISE EXCEPTION 'capacity request identity conflict' USING ERRCODE = '23505';
        END IF;
        IF v_existing.state <> 'granted' OR v_existing.dispatch_state = 'confirmed' THEN
            RETURN QUERY SELECT v_existing.id, v_existing.state, 'already_settled'::text, true, false;
            RETURN;
        END IF;
        -- Prior reservation was never confirmed on the backend ('pending' or 'in_flight'):
        -- require an active run claim, current epoch readiness, an unwatermarked commit_seq and
        -- fresh per-device fit before dispatching.
        PERFORM openmettle.capacity_lock_run(p_scope, p_run, p_claim);
        v_stale := g.observed_at IS NOT NULL
                   AND g.observed_at + g.observation_ttl_ms * interval '1 millisecond' <= clock_timestamp();
        IF v_existing.reconciled_epoch IS DISTINCT FROM g.controller_epoch
           OR NOT openmettle.capacity_admits_excluding(p_group, false, v_existing.id)
           OR v_existing.commit_seq <= g.commit_watermark THEN
            RETURN QUERY SELECT NULL::uuid, 'unavailable'::text, 'none'::text, true, v_stale;
            RETURN;
        END IF;
        IF EXISTS (
            SELECT
              FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint)
              LEFT JOIN openmettle.capacity_observations o
                ON o.group_id = p_group AND o.device_id = f.device_id
               AND o.revision = g.observation_revision
             WHERE o.device_id IS NULL
                OR f.bytes > o.grantable_bytes - coalesce((
                       SELECT sum(gd.bytes)
                         FROM openmettle.capacity_grant_devices gd
                         JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
                        WHERE gd.group_id = p_group
                          AND gd.device_id = f.device_id
                          AND c.state <> 'released'
                          AND c.commit_seq > g.commit_watermark
                          AND c.id <> v_existing.id), 0)
        ) THEN
            RETURN QUERY SELECT NULL::uuid, 'insufficient'::text, 'none'::text, true, false;
            RETURN;
        END IF;
        UPDATE openmettle.capacity_grants
           SET dispatch_state = 'in_flight',
               dispatch_epoch = g.controller_epoch
         WHERE id = v_existing.id;
        PERFORM openmettle.capacity_lock_run(p_scope, p_run, p_claim);
        IF NOT openmettle.capacity_admits_excluding(p_group, false, v_existing.id) THEN
            PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
            RAISE EXCEPTION 'capacity decision expired' USING ERRCODE = 'OMC02';
        END IF;
        PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
        RETURN QUERY SELECT v_existing.id, 'granted'::text, 'dispatch_now'::text, true, false;
        RETURN;
    END IF;

    PERFORM openmettle.capacity_lock_run(p_scope, p_run, p_claim);
    IF EXISTS (
        SELECT
          FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint)
          LEFT JOIN openmettle.capacity_devices d ON d.group_id = p_group AND d.id = f.device_id
         WHERE d.id IS NULL OR f.bytes IS NULL OR f.bytes <= 0
    ) OR (SELECT count(DISTINCT f.device_id) FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid))
         <> jsonb_array_length(p_footprint) THEN
        RAISE EXCEPTION 'invalid capacity footprint' USING ERRCODE = '22023';
    END IF;
    v_stale := g.observed_at IS NOT NULL
               AND g.observed_at + g.observation_ttl_ms * interval '1 millisecond' <= clock_timestamp();
    IF NOT openmettle.capacity_admits(p_group, false) THEN
        RETURN QUERY SELECT NULL::uuid, 'unavailable'::text, 'none'::text, false, v_stale;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT
          FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint)
          LEFT JOIN openmettle.capacity_observations o
            ON o.group_id = p_group AND o.device_id = f.device_id
           AND o.revision = g.observation_revision
         WHERE o.device_id IS NULL
            OR f.bytes > o.grantable_bytes - coalesce((
                   SELECT sum(gd.bytes)
                     FROM openmettle.capacity_grant_devices gd
                     JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
                    WHERE gd.group_id = p_group
                      AND gd.device_id = f.device_id
                      AND c.state <> 'released'
                      AND c.commit_seq > g.commit_watermark), 0)
    ) THEN
        RETURN QUERY SELECT NULL::uuid, 'insufficient'::text, 'none'::text, false, false;
        RETURN;
    END IF;

    SELECT array_agg(h.id) INTO v_holds
      FROM openmettle.quota_reservations h
     WHERE h.scope_id = p_scope
       AND h.run_id = p_run
       AND h.gateway_request_id IS NULL
       AND h.resource_kind = 'device_reservations'
       AND h.state = 'held';
    IF cardinality(v_holds) > 1 THEN
        RAISE EXCEPTION 'ambiguous run device slot' USING ERRCODE = '23514';
    END IF;
    UPDATE openmettle.capacity_groups SET commit_seq = commit_seq + 1
     WHERE id = p_group
    RETURNING commit_seq INTO v_seq;
    INSERT INTO openmettle.capacity_grants (
        group_id, scope_id, run_id, claim_token, quota_hold_id, request_key, request_digest,
        profile, dispatch_state, dispatch_epoch, granted_epoch, reconciled_epoch, commit_seq
    ) VALUES (
        p_group, p_scope, p_run, p_claim, v_holds[1], p_request_key, v_digest,
        p_profile, 'in_flight', g.controller_epoch, g.controller_epoch, g.controller_epoch, v_seq
    )
    RETURNING id INTO v_id;
    INSERT INTO openmettle.capacity_grant_devices (grant_id, group_id, device_id, bytes)
    SELECT v_id, p_group, f.device_id, f.bytes
      FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint);
    IF v_holds[1] IS NOT NULL THEN
        IF NOT openmettle.quota_commit_device_handoff(v_holds[1], p_scope, p_run, p_claim, v_id) THEN
            RAISE EXCEPTION 'run device slot is not available for this grant' USING ERRCODE = '23505';
        END IF;
    ELSE
        SELECT metering_enforced INTO v_enforced
          FROM openmettle.quota_enforcement WHERE id FOR SHARE;
        IF v_enforced THEN
            RAISE EXCEPTION 'run device slot required' USING ERRCODE = 'OMQ04';
        END IF;
    END IF;

    PERFORM openmettle.capacity_lock_run(p_scope, p_run, p_claim);
    IF NOT openmettle.capacity_admits_excluding(p_group, false, v_id) THEN
        PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
        RAISE EXCEPTION 'capacity decision expired' USING ERRCODE = 'OMC02';
    END IF;
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    RETURN QUERY SELECT v_id, 'granted'::text, 'dispatch_now'::text, false, false;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_prepare_dispatch(uuid, bytea, bigint, uuid, uuid, uuid, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_prepare_dispatch(uuid, bytea, bigint, uuid, uuid, uuid, text, text, jsonb) TO openmettle_worker;

-- Confirm backend dispatch of an in-flight grant strictly within the same state and epoch.
-- Never advances reconciled_epoch from an older epoch and rejects non-granted or wrong-epoch rows.
CREATE FUNCTION openmettle.capacity_confirm_dispatch(
    p_group uuid,
    p_secret bytea,
    p_epoch bigint,
    p_grant uuid
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v openmettle.capacity_grants%ROWTYPE;
BEGIN
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    SELECT * INTO v
      FROM openmettle.capacity_grants
     WHERE id = p_grant AND group_id = p_group
       FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid capacity grant' USING ERRCODE = '22023';
    END IF;
    IF v.state <> 'granted'
       OR v.reconciled_epoch IS DISTINCT FROM p_epoch
       OR NOT ((v.dispatch_state = 'in_flight' AND v.dispatch_epoch = p_epoch)
               OR v.dispatch_state = 'confirmed') THEN
        RAISE EXCEPTION 'capacity grant cannot confirm dispatch in current state or epoch'
            USING ERRCODE = '23505';
    END IF;
    IF v.dispatch_state = 'in_flight' THEN
        UPDATE openmettle.capacity_grants
           SET dispatch_state = 'confirmed'
         WHERE id = p_grant;
    END IF;
    PERFORM openmettle.capacity_fence(p_group, p_secret, p_epoch);
    RETURN 'granted'::text;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_confirm_dispatch(uuid, bytea, bigint, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_confirm_dispatch(uuid, bytea, bigint, uuid) TO openmettle_worker;

-- Read-only projection of managed groups and their latest device observations for /v1 capacity
-- endpoints. Runs inside the caller's REPEATABLE READ, READ ONLY snapshot; never exposes
-- controller_token_hash, PCIe/host topology or tenant grant rows.
CREATE FUNCTION openmettle.capacity_group_observations()
RETURNS TABLE (
    group_id uuid,
    controller_epoch bigint,
    admits_bursts boolean,
    observation_stale boolean,
    observation_revision bigint,
    observed_at_us bigint,
    device_id uuid,
    total_bytes bigint,
    committed_bytes bigint,
    actual_used_bytes bigint,
    reclaimable_bytes bigint,
    safety_headroom_bytes bigint,
    active_chat_floor_bytes bigint,
    grantable_bytes bigint,
    effective_grantable_bytes bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT g.id AS group_id,
           g.controller_epoch,
           (openmettle.capacity_admits(g.id, false)
            AND NOT (g.observed_at IS NOT NULL
                     AND g.observed_at + g.observation_ttl_ms * interval '1 millisecond' <= t.now))
               AS admits_bursts,
           (g.observed_at IS NOT NULL
            AND g.observed_at + g.observation_ttl_ms * interval '1 millisecond' <= t.now)
               AS observation_stale,
           g.observation_revision,
           (extract(epoch FROM g.observed_at) * 1000000)::bigint AS observed_at_us,
           o.device_id,
           o.total_bytes,
           o.committed_bytes,
           o.actual_used_bytes,
           o.reclaimable_bytes,
           o.safety_headroom_bytes,
           o.active_chat_floor_bytes,
           o.grantable_bytes,
           CASE
               WHEN o.device_id IS NULL THEN NULL
               ELSE greatest(
                   0::numeric,
                   o.grantable_bytes::numeric - coalesce((
                       SELECT sum(gd.bytes)
                         FROM openmettle.capacity_grant_devices gd
                         JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
                        WHERE gd.group_id = g.id
                          AND gd.device_id = o.device_id
                          AND c.state <> 'released'
                          AND c.commit_seq > g.commit_watermark), 0::numeric)
               )::bigint
           END AS effective_grantable_bytes
      FROM t
      CROSS JOIN openmettle.capacity_groups g
      LEFT JOIN openmettle.capacity_observations o
        ON o.group_id = g.id AND o.revision = g.observation_revision
     ORDER BY g.id, o.device_id
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_group_observations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_group_observations() TO openmettle_api;
