#!/usr/bin/env bash
# Linux CI only: the local migrate image against the isolated job PostgreSQL service.
# Creates synthetic roles and a dedicated database with a random per-run password.
set -euo pipefail
: "${POSTGRES_CONTAINER:?isolated CI PostgreSQL container ID required}"
image=openmettle-migrate:test
password=$(openssl rand -hex 16)
psql() {
  local database="$1"
  shift
  docker exec -i "$POSTGRES_CONTAINER" psql -v ON_ERROR_STOP=1 -q -U fixture -d "$database" "$@"
}
migrate() {
  docker run --rm --network host --read-only --cap-drop ALL --security-opt no-new-privileges "$@" "$image"
}

test "$(docker image inspect --format '{{.Config.User}}' "$image")" = 65532:65532
status=0
migrate >/dev/null 2>&1 || status=$?
test "$status" = 78

# Deployment-style provisioning (see README): externally created roles, dedicated database.
psql fixture <<SQL
CREATE ROLE openmettle_owner LOGIN PASSWORD '$password';
CREATE ROLE openmettle_api LOGIN PASSWORD '$password';
CREATE ROLE openmettle_worker LOGIN PASSWORD '$password';
CREATE DATABASE openmettle OWNER openmettle_owner;
SQL
url="postgres://openmettle_owner:$password@127.0.0.1:5432/openmettle?sslmode=disable"
for attempt in first repeat; do
  output=$(migrate -e "OPENMETTLE_MIGRATE_DATABASE_URL=$url" 2>&1)
  if grep -q "$password" <<<"$output"; then
    echo 'Migration output disclosed a credential' >&2
    exit 1
  fi
  echo "$attempt run: $output"
done
versions=$(psql openmettle -tA -c 'SELECT string_agg(version::text, $$,$$ ORDER BY version) FROM openmettle._sqlx_migrations WHERE success')
test "$versions" = 1,2,3,4,5,6,7,8,9,10,11,12,13
echo 'Migrate image: non-root user, configuration exit 78, fresh install and idempotent rerun passed.'
