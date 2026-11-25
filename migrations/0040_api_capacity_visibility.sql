-- V1-18 migration 40: API capacity profile catalog and read-only projection (ADR 0042, PR3).
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- openmettle_owner configures capacity_profiles. openmettle_api reads capacity_profiles directly
-- and inspects group/device observations only through openmettle.capacity_group_observations(),
-- a STABLE SECURITY DEFINER read helper that never exposes controller_token_hash or per-tenant
-- capacity_grants rows.

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
    estimated_wait_seconds integer
        CHECK (estimated_wait_seconds IS NULL OR estimated_wait_seconds BETWEEN 1 AND 86400)
);
GRANT SELECT ON openmettle.capacity_profiles TO openmettle_api;

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
