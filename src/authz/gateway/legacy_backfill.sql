-- Page over primary keys before inspecting finality. Even a fully settled
-- installation reads at most the page plus its exclusive cursor key.
WITH sample AS MATERIALIZED (
    SELECT request_id, final, outstanding FROM openmettle.gateway_settlements
     WHERE request_id >= coalesce($1::uuid, '00000000-0000-0000-0000-000000000000')
       AND request_id IS DISTINCT FROM $1::uuid
     ORDER BY request_id LIMIT $2
)
SELECT s.request_id::text, (
    SELECT greatest(0, extract(epoch FROM clock_timestamp() - q.created_at))::bigint
      FROM openmettle.gateway_requests q
     WHERE q.id = s.request_id AND q.installation = $3::uuid AND s.final AND s.outstanding > 0
       AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                        WHERE h.gateway_request_id = q.id AND h.resource_kind = 'usage_tokens')
) FROM sample s ORDER BY s.request_id
