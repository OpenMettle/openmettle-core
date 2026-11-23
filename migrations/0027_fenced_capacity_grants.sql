-- V1-18 migration 27: fenced GPU capacity controller store (ADR 0042, PR2).
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- openmettle_owner configures managed groups and their devices. Every runtime write goes
-- through the SECURITY DEFINER functions below, granted to openmettle_worker only. Lock order
-- extends ADR 0040: runs -> capacity_groups -> capacity_grants -> quota_reservations
-- -> quota_budgets. No capacity path locks runs after a capacity row.

CREATE TABLE openmettle.capacity_groups (
    id uuid PRIMARY KEY,
    observation_ttl_ms integer NOT NULL CHECK (observation_ttl_ms BETWEEN 1000 AND 600000),
    controller_id uuid,
    controller_epoch bigint NOT NULL DEFAULT 0 CHECK (controller_epoch >= 0),
    lease_expires_at timestamptz,
    epoch_started_at timestamptz,
    -- Bursts are admitted only while ready_epoch = controller_epoch (set by capacity_resume).
    ready_epoch bigint,
    observation_revision bigint NOT NULL DEFAULT 0 CHECK (observation_revision >= 0),
    observation_epoch bigint,
    observed_at timestamptz,
    -- The latest snapshot accounts for grants with commit_seq <= commit_watermark.
    commit_watermark bigint NOT NULL DEFAULT 0,
    commit_seq bigint NOT NULL DEFAULT 0 CHECK (commit_seq >= 0),
    CHECK ((controller_epoch = 0) = (controller_id IS NULL)),
    CHECK ((controller_id IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((controller_id IS NULL) = (epoch_started_at IS NULL)),
    CHECK (ready_epoch IS NULL OR ready_epoch BETWEEN 1 AND controller_epoch),
    CHECK ((observation_revision = 0) = (observed_at IS NULL)),
    CHECK ((observed_at IS NULL) = (observation_epoch IS NULL)),
    CHECK (observation_epoch IS NULL OR observation_epoch BETWEEN 1 AND controller_epoch),
    CHECK (commit_watermark BETWEEN 0 AND commit_seq)
);

-- A device belongs to at most one group. chat_floor_bytes is the configured minimum that every
-- published active-chat floor must cover.
CREATE TABLE openmettle.capacity_devices (
    id uuid PRIMARY KEY,
    group_id uuid NOT NULL REFERENCES openmettle.capacity_groups (id),
    chat_floor_bytes bigint NOT NULL CHECK (chat_floor_bytes >= 0),
    UNIQUE (group_id, id)
);

-- The latest published snapshot: one row per configured device at the group's revision.
CREATE TABLE openmettle.capacity_observations (
    group_id uuid NOT NULL,
    device_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    total_bytes bigint NOT NULL CHECK (total_bytes > 0),
    committed_bytes bigint NOT NULL CHECK (committed_bytes >= 0),
    actual_used_bytes bigint NOT NULL CHECK (actual_used_bytes >= 0),
    reclaimable_bytes bigint NOT NULL CHECK (reclaimable_bytes >= 0),
    safety_headroom_bytes bigint NOT NULL CHECK (safety_headroom_bytes >= 0),
    active_chat_floor_bytes bigint NOT NULL CHECK (active_chat_floor_bytes >= 0),
    grantable_bytes bigint NOT NULL CHECK (grantable_bytes >= 0),
    PRIMARY KEY (group_id, device_id),
    FOREIGN KEY (group_id, device_id) REFERENCES openmettle.capacity_devices (group_id, id),
    CHECK (reclaimable_bytes <= actual_used_bytes),
    -- Necessary bound: grantable capacity never includes headroom, measured use, outstanding
    -- commitments or the chat floor. The controller supplies the attributed fit itself.
    CHECK (grantable_bytes::numeric + safety_headroom_bytes
        + greatest(actual_used_bytes::numeric, committed_bytes::numeric + active_chat_floor_bytes)
        <= total_bytes)
);

-- A grant charges its full footprint from commit until every device confirms release.
CREATE TABLE openmettle.capacity_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id uuid NOT NULL REFERENCES openmettle.capacity_groups (id),
    scope_id uuid NOT NULL,
    run_id uuid NOT NULL,
    claim_token uuid NOT NULL,
    quota_hold_id uuid UNIQUE REFERENCES openmettle.quota_reservations (id),
    request_key text NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    profile text NOT NULL CHECK (octet_length(profile) BETWEEN 1 AND 128),
    state text NOT NULL DEFAULT 'granted'
        CHECK (state IN ('granted', 'releasing', 'unknown_allocation', 'released')),
    granted_epoch bigint NOT NULL CHECK (granted_epoch >= 1),
    commit_seq bigint NOT NULL CHECK (commit_seq >= 1),
    released_epoch bigint,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    released_at timestamptz,
    UNIQUE (scope_id, request_key),
    UNIQUE (group_id, commit_seq),
    UNIQUE (group_id, id),
    FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id),
    CHECK ((state = 'released') = (released_at IS NOT NULL)),
    CHECK ((released_at IS NULL) = (released_epoch IS NULL)),
    CHECK (released_epoch IS NULL OR released_epoch >= granted_epoch)
);
CREATE INDEX capacity_grants_charged_idx
    ON openmettle.capacity_grants (group_id, commit_seq) WHERE state <> 'released';

CREATE TABLE openmettle.capacity_grant_devices (
    grant_id uuid NOT NULL,
    group_id uuid NOT NULL,
    device_id uuid NOT NULL,
    bytes bigint NOT NULL CHECK (bytes > 0),
    release_evidence text CHECK (release_evidence IN ('released', 'not_allocated')),
    released_epoch bigint,
    released_at timestamptz,
    PRIMARY KEY (grant_id, device_id),
    FOREIGN KEY (group_id, grant_id) REFERENCES openmettle.capacity_grants (group_id, id),
    FOREIGN KEY (group_id, device_id) REFERENCES openmettle.capacity_devices (group_id, id),
    CHECK ((release_evidence IS NULL) = (released_at IS NULL)),
    CHECK ((released_at IS NULL) = (released_epoch IS NULL))
);
CREATE INDEX capacity_grant_devices_device_idx
    ON openmettle.capacity_grant_devices (group_id, device_id);

GRANT SELECT ON openmettle.capacity_groups, openmettle.capacity_devices,
    openmettle.capacity_observations, openmettle.capacity_grants,
    openmettle.capacity_grant_devices TO openmettle_worker;

-- Internal: lock the group and verify the caller's lease and epoch against database time.
CREATE FUNCTION openmettle.capacity_fence(p_group uuid, p_controller uuid, p_epoch bigint)
RETURNS openmettle.capacity_groups
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
BEGIN
    SELECT * INTO g FROM openmettle.capacity_groups WHERE id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND
       OR g.controller_id IS DISTINCT FROM p_controller
       OR g.controller_epoch IS DISTINCT FROM p_epoch
       OR g.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'capacity controller fenced' USING ERRCODE = 'OMC01';
    END IF;
    RETURN g;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_fence(uuid, uuid, bigint) FROM PUBLIC;

-- Renew the caller's live lease, or take over an absent or expired one with a new epoch. A new
-- epoch closes the group to bursts until capacity_resume succeeds.
CREATE FUNCTION openmettle.capacity_acquire_controller(p_group uuid, p_controller uuid, p_lease_ms integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
    v_now timestamptz;
    v_epoch bigint;
BEGIN
    IF p_controller IS NULL OR p_lease_ms IS NULL OR p_lease_ms NOT BETWEEN 1000 AND 600000 THEN
        RAISE EXCEPTION 'invalid controller lease' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO g FROM openmettle.capacity_groups WHERE id = p_group FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown capacity group' USING ERRCODE = '22023';
    END IF;
    v_now := clock_timestamp();
    IF g.lease_expires_at > v_now THEN
        IF g.controller_id <> p_controller THEN
            RAISE EXCEPTION 'capacity controller fenced' USING ERRCODE = 'OMC01';
        END IF;
        UPDATE openmettle.capacity_groups
           SET lease_expires_at = v_now + p_lease_ms * interval '1 millisecond'
         WHERE id = p_group;
        RETURN g.controller_epoch;
    END IF;
    UPDATE openmettle.capacity_groups
       SET controller_id = p_controller,
           controller_epoch = controller_epoch + 1,
           lease_expires_at = v_now + p_lease_ms * interval '1 millisecond',
           epoch_started_at = v_now
     WHERE id = p_group
    RETURNING controller_epoch INTO v_epoch;
    RETURN v_epoch;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_acquire_controller(uuid, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_acquire_controller(uuid, uuid, integer) TO openmettle_worker;

-- Publish one complete snapshot. An equal or older revision is ignored and never extends
-- freshness. The sample must be measured within the current epoch, after the previous sample.
CREATE FUNCTION openmettle.capacity_publish_observation(
    p_group uuid,
    p_controller uuid,
    p_epoch bigint,
    p_revision bigint,
    p_observed_at timestamptz,
    p_commit_watermark bigint,
    p_devices jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
    v_expected bigint;
BEGIN
    g := openmettle.capacity_fence(p_group, p_controller, p_epoch);
    IF p_revision IS NULL OR p_revision <= g.observation_revision THEN
        RETURN false;
    END IF;
    IF p_observed_at IS NULL
       OR p_observed_at > clock_timestamp()
       OR p_observed_at < g.epoch_started_at
       OR p_observed_at < g.observed_at
       OR p_commit_watermark IS NULL
       OR p_commit_watermark NOT BETWEEN 0 AND g.commit_seq
       OR jsonb_typeof(p_devices) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid capacity observation' USING ERRCODE = '22023';
    END IF;
    -- Exactly the configured devices, each once: a missing rank cannot be published.
    SELECT count(*) INTO v_expected FROM openmettle.capacity_devices WHERE group_id = p_group;
    IF v_expected = 0
       OR jsonb_array_length(p_devices) <> v_expected
       OR (SELECT count(DISTINCT d.id)
             FROM jsonb_to_recordset(p_devices) AS o(device_id uuid)
             JOIN openmettle.capacity_devices d ON d.group_id = p_group AND d.id = o.device_id)
          <> v_expected THEN
        RAISE EXCEPTION 'incomplete capacity observation' USING ERRCODE = '22023';
    END IF;
    INSERT INTO openmettle.capacity_observations (
        group_id, device_id, revision, total_bytes, committed_bytes, actual_used_bytes,
        reclaimable_bytes, safety_headroom_bytes, active_chat_floor_bytes, grantable_bytes
    )
    SELECT p_group, o.device_id, p_revision, o.total_bytes, o.committed_bytes,
           o.actual_used_bytes, o.reclaimable_bytes, o.safety_headroom_bytes,
           o.active_chat_floor_bytes, o.grantable_bytes
      FROM jsonb_to_recordset(p_devices) AS o(
               device_id uuid, total_bytes bigint, committed_bytes bigint,
               actual_used_bytes bigint, reclaimable_bytes bigint, safety_headroom_bytes bigint,
               active_chat_floor_bytes bigint, grantable_bytes bigint)
    ON CONFLICT (group_id, device_id) DO UPDATE
       SET revision = excluded.revision,
           total_bytes = excluded.total_bytes,
           committed_bytes = excluded.committed_bytes,
           actual_used_bytes = excluded.actual_used_bytes,
           reclaimable_bytes = excluded.reclaimable_bytes,
           safety_headroom_bytes = excluded.safety_headroom_bytes,
           active_chat_floor_bytes = excluded.active_chat_floor_bytes,
           grantable_bytes = excluded.grantable_bytes;
    -- The configured chat floor is a lower bound, and the snapshot must count every durable
    -- commitment it claims to include through the watermark.
    IF EXISTS (
        SELECT
          FROM openmettle.capacity_observations o
          JOIN openmettle.capacity_devices d ON d.group_id = o.group_id AND d.id = o.device_id
         WHERE o.group_id = p_group
           AND (o.active_chat_floor_bytes < d.chat_floor_bytes
                OR o.committed_bytes < coalesce((
                    SELECT sum(gd.bytes)
                      FROM openmettle.capacity_grant_devices gd
                      JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
                     WHERE gd.group_id = p_group
                       AND gd.device_id = o.device_id
                       AND c.state <> 'released'
                       AND c.commit_seq <= p_commit_watermark), 0))
    ) THEN
        RAISE EXCEPTION 'inconsistent capacity observation' USING ERRCODE = '22023';
    END IF;
    UPDATE openmettle.capacity_groups
       SET observation_revision = p_revision,
           observation_epoch = p_epoch,
           observed_at = p_observed_at,
           commit_watermark = p_commit_watermark
     WHERE id = p_group;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_publish_observation(uuid, uuid, bigint, bigint, timestamptz, bigint, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_publish_observation(uuid, uuid, bigint, bigint, timestamptz, bigint, jsonb) TO openmettle_worker;

-- Reopen bursts after takeover once the new epoch has a fresh sample and no unknown allocation.
CREATE FUNCTION openmettle.capacity_resume(p_group uuid, p_controller uuid, p_epoch bigint)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
BEGIN
    g := openmettle.capacity_fence(p_group, p_controller, p_epoch);
    IF g.ready_epoch = g.controller_epoch THEN
        RETURN true;
    END IF;
    IF g.observation_epoch IS DISTINCT FROM g.controller_epoch
       OR g.observed_at + g.observation_ttl_ms * interval '1 millisecond' <= clock_timestamp()
       OR EXISTS (
           SELECT FROM openmettle.capacity_grants
            WHERE group_id = p_group AND state = 'unknown_allocation'
       ) THEN
        RETURN false;
    END IF;
    UPDATE openmettle.capacity_groups SET ready_epoch = controller_epoch WHERE id = p_group;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_resume(uuid, uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_resume(uuid, uuid, bigint) TO openmettle_worker;

-- Serialized grant decision for a leased run. A replay returns the recorded grant; otherwise the
-- footprint must fit every device after commitments made since the snapshot. A granted run-level
-- device_reservations hold is committed to the grant in the same transaction.
CREATE FUNCTION openmettle.capacity_grant(
    p_group uuid,
    p_controller uuid,
    p_epoch bigint,
    p_scope uuid,
    p_run uuid,
    p_claim uuid,
    p_request_key text,
    p_profile text,
    p_footprint jsonb
)
RETURNS TABLE (grant_ref uuid, outcome text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    g openmettle.capacity_groups%ROWTYPE;
    v_existing openmettle.capacity_grants%ROWTYPE;
    v_digest bytea;
    v_holds uuid[];
    v_seq bigint;
    v_id uuid;
BEGIN
    IF p_request_key IS NULL OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR p_profile IS NULL OR octet_length(p_profile) NOT BETWEEN 1 AND 128
       OR jsonb_typeof(p_footprint) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_footprint) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'invalid capacity request' USING ERRCODE = '22023';
    END IF;
    PERFORM
       FROM openmettle.runs r
      WHERE r.scope_id = p_scope
        AND r.id = p_run
        AND r.state = 'running'
        AND r.cancel_reason IS NULL
        AND r.claim_token = p_claim
        AND r.lease_expires_at > clock_timestamp()
        FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid device handoff' USING ERRCODE = '42501';
    END IF;
    g := openmettle.capacity_fence(p_group, p_controller, p_epoch);
    IF EXISTS (
        SELECT
          FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint)
          LEFT JOIN openmettle.capacity_devices d ON d.group_id = p_group AND d.id = f.device_id
         WHERE d.id IS NULL OR f.bytes IS NULL OR f.bytes <= 0
    ) OR (SELECT count(DISTINCT f.device_id) FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid))
         <> jsonb_array_length(p_footprint) THEN
        RAISE EXCEPTION 'invalid capacity footprint' USING ERRCODE = '22023';
    END IF;
    SELECT sha256(convert_to(jsonb_build_array(
               p_group, p_run, p_profile,
               jsonb_agg(jsonb_build_array(f.device_id, f.bytes) ORDER BY f.device_id))::text, 'UTF8'))
      INTO v_digest
      FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint);

    SELECT * INTO v_existing
      FROM openmettle.capacity_grants c
     WHERE c.scope_id = p_scope AND c.request_key = p_request_key;
    IF FOUND THEN
        IF v_existing.request_digest <> v_digest THEN
            RAISE EXCEPTION 'capacity request identity conflict' USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT v_existing.id, v_existing.state;
        RETURN;
    END IF;

    -- Takeover, a stale or superseded sample, a missing rank or an unknown allocation keeps the
    -- group closed. None of them can justify a positive grant.
    IF g.ready_epoch IS DISTINCT FROM g.controller_epoch
       OR g.observation_epoch IS DISTINCT FROM g.controller_epoch
       OR g.observed_at + g.observation_ttl_ms * interval '1 millisecond' <= clock_timestamp()
       OR EXISTS (
           SELECT FROM openmettle.capacity_grants c
            WHERE c.group_id = p_group AND c.state = 'unknown_allocation'
       )
       OR EXISTS (
           SELECT
             FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid)
             LEFT JOIN openmettle.capacity_observations o
               ON o.group_id = p_group AND o.device_id = f.device_id
              AND o.revision = g.observation_revision
            WHERE o.device_id IS NULL
       ) THEN
        RETURN QUERY SELECT NULL::uuid, 'unavailable'::text;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT
          FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint)
          JOIN openmettle.capacity_observations o
            ON o.group_id = p_group AND o.device_id = f.device_id
         WHERE f.bytes > o.grantable_bytes - coalesce((
                   SELECT sum(gd.bytes)
                     FROM openmettle.capacity_grant_devices gd
                     JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
                    WHERE gd.group_id = p_group
                      AND gd.device_id = f.device_id
                      AND c.state <> 'released'
                      AND c.commit_seq > g.commit_watermark), 0)
    ) THEN
        RETURN QUERY SELECT NULL::uuid, 'insufficient'::text;
        RETURN;
    END IF;

    SELECT array_agg(h.id) INTO v_holds
      FROM openmettle.quota_reservations h
     WHERE h.scope_id = p_scope
       AND h.run_id = p_run
       AND h.gateway_request_id IS NULL
       AND h.resource_kind = 'device_reservations';
    IF cardinality(v_holds) > 1 THEN
        RAISE EXCEPTION 'ambiguous run device slot' USING ERRCODE = '23514';
    END IF;
    UPDATE openmettle.capacity_groups SET commit_seq = commit_seq + 1
     WHERE id = p_group
    RETURNING commit_seq INTO v_seq;
    INSERT INTO openmettle.capacity_grants (
        group_id, scope_id, run_id, claim_token, quota_hold_id, request_key, request_digest,
        profile, granted_epoch, commit_seq
    ) VALUES (
        p_group, p_scope, p_run, p_claim, v_holds[1], p_request_key, v_digest,
        p_profile, g.controller_epoch, v_seq
    )
    RETURNING id INTO v_id;
    INSERT INTO openmettle.capacity_grant_devices (grant_id, group_id, device_id, bytes)
    SELECT v_id, p_group, f.device_id, f.bytes
      FROM jsonb_to_recordset(p_footprint) AS f(device_id uuid, bytes bigint);
    IF v_holds[1] IS NOT NULL
       AND NOT openmettle.quota_commit_device_handoff(v_holds[1], p_scope, p_run, p_claim, v_id) THEN
        RAISE EXCEPTION 'run device slot is not available for this grant' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT v_id, 'granted'::text;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_grant(uuid, uuid, bigint, uuid, uuid, uuid, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_grant(uuid, uuid, bigint, uuid, uuid, uuid, text, text, jsonb) TO openmettle_worker;

-- Fenced release transitions. Only confirmed release or non-allocation on every device of the
-- grant releases it, returns its bytes to fresh fit and settles its device slot. Partial or lost
-- evidence leaves unknown_allocation. The run's lease is not required: a current controller may
-- clean up after the worker's claim expired without authorizing new work on it.
CREATE FUNCTION openmettle.capacity_record_release(
    p_group uuid,
    p_controller uuid,
    p_epoch bigint,
    p_grant uuid,
    p_outcome text,
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
BEGIN
    g := openmettle.capacity_fence(p_group, p_controller, p_epoch);
    SELECT * INTO v
      FROM openmettle.capacity_grants
     WHERE id = p_grant AND group_id = p_group
       FOR NO KEY UPDATE;
    IF NOT FOUND OR p_outcome IS NULL
       OR p_outcome NOT IN ('releasing', 'unknown_allocation', 'released', 'not_allocated') THEN
        RAISE EXCEPTION 'invalid capacity release' USING ERRCODE = '22023';
    END IF;
    IF v.state = 'released' THEN
        RETURN v.state;
    END IF;
    IF p_outcome = 'releasing' THEN
        IF v.state = 'granted' THEN
            UPDATE openmettle.capacity_grants SET state = 'releasing' WHERE id = p_grant;
            RETURN 'releasing';
        END IF;
        RETURN v.state;
    END IF;
    IF p_outcome = 'unknown_allocation' THEN
        UPDATE openmettle.capacity_grants SET state = 'unknown_allocation' WHERE id = p_grant;
        RETURN 'unknown_allocation';
    END IF;
    IF coalesce(cardinality(p_devices), 0) = 0 OR EXISTS (
        SELECT FROM unnest(p_devices) AS d(device_id)
         WHERE NOT EXISTS (
             SELECT FROM openmettle.capacity_grant_devices gd
              WHERE gd.grant_id = p_grant AND gd.device_id = d.device_id
         )
    ) THEN
        RAISE EXCEPTION 'invalid capacity release' USING ERRCODE = '22023';
    END IF;
    UPDATE openmettle.capacity_grant_devices
       SET release_evidence = p_outcome,
           released_epoch = g.controller_epoch,
           released_at = clock_timestamp()
     WHERE grant_id = p_grant AND device_id = ANY (p_devices) AND released_at IS NULL;
    IF EXISTS (
        SELECT FROM openmettle.capacity_grant_devices
         WHERE grant_id = p_grant AND released_at IS NULL
    ) THEN
        UPDATE openmettle.capacity_grants SET state = 'unknown_allocation' WHERE id = p_grant;
        RETURN 'unknown_allocation';
    END IF;
    UPDATE openmettle.capacity_grants
       SET state = 'released',
           released_epoch = g.controller_epoch,
           released_at = clock_timestamp()
     WHERE id = p_grant;
    IF v.quota_hold_id IS NOT NULL THEN
        PERFORM openmettle.quota_release_device_slot(v.quota_hold_id, v.id);
    END IF;
    RETURN 'released';
END;
$$;
REVOKE ALL ON FUNCTION openmettle.capacity_record_release(uuid, uuid, bigint, uuid, text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.capacity_record_release(uuid, uuid, bigint, uuid, text, uuid[]) TO openmettle_worker;

-- Replace the migration 24 stub: a committed device slot is credited once, and only against a
-- released capacity grant bound to it. Without that durable record the slot stays charged.
CREATE OR REPLACE FUNCTION openmettle.quota_release_device_slot(p_hold uuid, p_grant uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    h openmettle.quota_reservations%ROWTYPE;
BEGIN
    SELECT * INTO h
      FROM openmettle.quota_reservations
     WHERE id = p_hold
       AND device_grant_id = p_grant
       AND resource_kind = 'device_reservations'
       FOR NO KEY UPDATE;
    IF NOT FOUND OR h.state <> 'handoff_committed' THEN
        RETURN false;
    END IF;
    -- A released grant is terminal, so a non-locking read cannot invert the lock order.
    IF NOT EXISTS (
        SELECT FROM openmettle.capacity_grants c
         WHERE c.id = p_grant AND c.quota_hold_id = p_hold AND c.state = 'released'
    ) THEN
        RAISE EXCEPTION 'durable device release evidence required' USING ERRCODE = 'OMQ06';
    END IF;
    UPDATE openmettle.quota_reservations
       SET held_units = 0,
           state = 'released',
           revision = revision + 1,
           closed_at = clock_timestamp()
     WHERE id = h.id;
    INSERT INTO openmettle.quota_reconciliations (
        reservation_id, transition_revision, source_key, kind, cumulative_units,
        delta_active, delta_reserved
    ) VALUES (h.id, h.revision + 1, 'capacity_release', 'release', 0, 0, -h.held_units);
    PERFORM openmettle.quota_adjust(h.id, 0, -h.held_units);
    RETURN true;
END;
$$;
