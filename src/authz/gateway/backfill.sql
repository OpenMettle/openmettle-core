WITH cursor AS (
    SELECT coalesce($2::text::timestamptz, '-infinity') AS at,
           coalesce($3::uuid, '00000000-0000-0000-0000-000000000000') AS id
), candidates AS (
    (SELECT q.created_at AS position, q.id, q.created_at
       FROM openmettle.gateway_requests q, cursor c
      WHERE q.installation = $1::uuid AND q.state = 'handed_off' AND NOT q.settled_final
        AND (q.created_at, q.id) > (c.at, c.id)
        AND NOT EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = q.id)
      ORDER BY q.created_at, q.id LIMIT $4)
    UNION ALL
    (SELECT s.updated_at, q.id, q.created_at
       FROM openmettle.gateway_settlements s
       JOIN openmettle.gateway_requests q ON q.id = s.request_id CROSS JOIN cursor c
      WHERE NOT s.final AND q.installation = $1::uuid AND (s.updated_at, s.request_id) > (c.at, c.id)
      ORDER BY s.updated_at, s.request_id LIMIT $4)
    UNION ALL
    -- Final evidence may resolve only one resource. Start from open holds and
    -- look up just their requests, even when the installation has a long history.
    (SELECT q.created_at, q.id, q.created_at
       FROM (SELECT DISTINCT gateway_request_id FROM openmettle.quota_reservations
              WHERE state = 'handoff_committed' AND gateway_request_id IS NOT NULL) h
       CROSS JOIN cursor c CROSS JOIN LATERAL (
           SELECT id, created_at FROM openmettle.gateway_requests
            WHERE id = h.gateway_request_id AND installation = $1::uuid AND settled_final
              AND (created_at, id) > (c.at, c.id) LIMIT 1
       ) q ORDER BY q.created_at, q.id LIMIT $4)
)
SELECT position::text, id::text, greatest(0, extract(epoch FROM clock_timestamp() - created_at))::bigint
  FROM candidates ORDER BY candidates.position, candidates.id LIMIT $4
