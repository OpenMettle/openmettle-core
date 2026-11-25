#!/usr/bin/env bash
# Linux CI only: local images and the isolated job PostgreSQL service.
set -euo pipefail
: "${POSTGRES_CONTAINER:?isolated CI PostgreSQL container ID required}"
db_url='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
api=""
worker=""
gateway=""
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    if [ -n "$api" ]; then docker logs "$api" >&2 || true; fi
    if [ -n "$worker" ]; then docker logs "$worker" >&2 || true; fi
    if [ -n "$gateway" ]; then docker logs "$gateway" >&2 || true; fi
  fi
  if [ -n "$api" ]; then docker rm -f "$api" >/dev/null || true; fi
  if [ -n "$worker" ]; then docker rm -f "$worker" >/dev/null || true; fi
  if [ -n "$gateway" ]; then docker rm -f "$gateway" >/dev/null || true; fi
  docker start "$POSTGRES_CONTAINER" >/dev/null || true
  return "$status"
}
trap cleanup EXIT
check_image_isolation() {
  local image="$1" present="$2"
  shift 2
  test "$(docker image inspect --format '{{.Config.User}}' "$image")" = 65532:65532
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --entrypoint /bin/sh "$image" -ec '
      present="$1"
      shift
      test -x "/usr/local/bin/$present"
      for absent in "$@"; do
        test ! -e "/usr/local/bin/$absent"
      done
    ' _ "$present" "$@"
}
expect_gateway_config_error() {
  local status=0
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    "$@" openmettle-gateway:test >/dev/null 2>&1 || status=$?
  test "$status" = 78
}
wait_status() {
  local port="$1" path="$2" expected="$3" actual
  for _ in $(seq 1 60); do
    actual=$(curl --max-time 3 --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$port/$path" || true)
    if [ "$actual" = "$expected" ]; then return; fi
    sleep 1
  done
  echo "Expected HTTP $expected on $port/$path; received $actual" >&2
  return 1
}
check_image_isolation openmettle-api:test openmettle-api openmettle-worker openmettle-gateway openmettle-migrate openmettle-admin
check_image_isolation openmettle-worker:test openmettle-worker openmettle-api openmettle-gateway openmettle-migrate openmettle-admin
check_image_isolation openmettle-gateway:test openmettle-gateway openmettle-api openmettle-worker openmettle-migrate openmettle-admin
# Gateway must fail closed (exit 78) when required settings are missing or issuance URL is present.
expect_gateway_config_error \
  -e "OPENMETTLE_GATEWAY_DATABASE_URL=$db_url" \
  -e OPENMETTLE_GATEWAY_MODEL=synthetic-model
expect_gateway_config_error \
  -e "OPENMETTLE_GATEWAY_DATABASE_URL=$db_url" \
  -e OPENMETTLE_GATEWAY_UPSTREAM_URL=http://127.0.0.1:30000
expect_gateway_config_error \
  -e "OPENMETTLE_GATEWAY_DATABASE_URL=$db_url" \
  -e OPENMETTLE_GATEWAY_UPSTREAM_URL=http://127.0.0.1:30000 \
  -e OPENMETTLE_GATEWAY_MODEL=synthetic-model \
  -e "OPENMETTLE_API_ISSUANCE_DATABASE_URL=$db_url"
api=$(docker run -d --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e OPENMETTLE_API_BIND=127.0.0.1:8080 \
  -e "OPENMETTLE_API_DATABASE_URL=$db_url" openmettle-api:test)
worker=$(docker run -d --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e OPENMETTLE_WORKER_BIND=127.0.0.1:8081 \
  -e "OPENMETTLE_WORKER_DATABASE_URL=$db_url" openmettle-worker:test)
gateway=$(docker run -d --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e OPENMETTLE_GATEWAY_BIND=127.0.0.1:8082 \
  -e "OPENMETTLE_GATEWAY_DATABASE_URL=$db_url" \
  -e OPENMETTLE_GATEWAY_UPSTREAM_URL=http://127.0.0.1:30000 \
  -e OPENMETTLE_GATEWAY_MODEL=synthetic-model openmettle-gateway:test)
wait_status 8080 readyz 200
wait_status 8081 readyz 200
wait_status 8082 readyz 200
docker stop --time 10 "$worker" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$worker")" = 0
wait_status 8080 healthz 200
wait_status 8080 readyz 200
wait_status 8082 healthz 200
wait_status 8082 readyz 200
# Test dependency loss and recovery without restarting the API or gateway.
docker stop --time 10 "$POSTGRES_CONTAINER" >/dev/null
wait_status 8080 readyz 503
wait_status 8080 healthz 200
wait_status 8082 readyz 503
wait_status 8082 healthz 200
docker start "$POSTGRES_CONTAINER" >/dev/null
wait_status 8080 readyz 200
wait_status 8082 readyz 200
docker stop --time 10 "$gateway" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$gateway")" = 0
docker stop --time 10 "$api" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$api")" = 0
echo 'Image isolation, fail-closed config, health, database loss/recovery, stopped-worker survival and shutdown passed.'
