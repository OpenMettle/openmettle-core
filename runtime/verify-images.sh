#!/usr/bin/env bash
# Linux CI only: local images and the isolated job PostgreSQL service.
set -euo pipefail
: "${POSTGRES_CONTAINER:?isolated CI PostgreSQL container ID required}"
api=""
worker=""
cleanup() {
  if [ -n "$api" ]; then docker rm -f "$api" >/dev/null; fi
  if [ -n "$worker" ]; then docker rm -f "$worker" >/dev/null; fi
  docker start "$POSTGRES_CONTAINER" >/dev/null
}
trap cleanup EXIT
wait_status() {
  local port="$1" path="$2" expected="$3" actual
  for attempt in $(seq 1 60); do
    actual=$(curl --max-time 3 --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$port/$path" || true)
    if [ "$actual" = "$expected" ]; then return; fi
    sleep 1
  done
  echo "Expected HTTP $expected on $port/$path; received $actual" >&2
  return 1
}
api=$(docker run -d --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e OPENMETTLE_API_BIND=127.0.0.1:8080 \
  -e OPENMETTLE_API_DATABASE_URL=postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable openmettle-api:test)
worker=$(docker run -d --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e OPENMETTLE_WORKER_BIND=127.0.0.1:8081 \
  -e OPENMETTLE_WORKER_DATABASE_URL=postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable openmettle-worker:test)
wait_status 8080 readyz 200
wait_status 8081 readyz 200
docker stop --time 10 "$worker" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$worker")" = 0
wait_status 8080 healthz 200
wait_status 8080 readyz 200
# Test dependency loss and recovery without restarting the API.
docker stop --time 10 "$POSTGRES_CONTAINER" >/dev/null
wait_status 8080 readyz 503
wait_status 8080 healthz 200
docker start "$POSTGRES_CONTAINER" >/dev/null
wait_status 8080 readyz 200
docker stop --time 10 "$api" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$api")" = 0
echo 'Image health, database loss/recovery, stopped-worker survival and shutdown passed.'
