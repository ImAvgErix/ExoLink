#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s /absolute/path/to/exocord-YYYYMMDDTHHMMSSZ.sha256\n' "$0" >&2
  exit 2
fi

manifest="$(realpath "$1")"
if [[ ! -f "$manifest" || "$manifest" != *.sha256 ]]; then
  printf 'backup manifest does not exist or is not a .sha256 file: %s\n' "$manifest" >&2
  exit 2
fi
backup_dir="$(dirname "$manifest")"
prefix="$(basename "$manifest" .sha256)"
dump="$backup_dir/$prefix.dump"
state="$backup_dir/$prefix.state.tar.gz"
if [[ ! -f "$dump" || ! -f "$state" ]]; then
  printf 'backup set is incomplete for prefix %s\n' "$prefix" >&2
  exit 2
fi
(
  cd "$backup_dir"
  sha256sum --check "$(basename "$manifest")"
)

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
migrations_dir="$(realpath "$deploy_dir/../../apps/exo-monolith/migrations")"
expected_migrations="$(
  find "$migrations_dir" -maxdepth 1 -type f -name '*.sql' | wc -l | tr -d ' '
)"
if [[ "$expected_migrations" -lt 1 ]]; then
  printf 'could not determine the expected migration count\n' >&2
  exit 1
fi

suffix="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
container="exocord-restore-drill-$suffix"
state_volume="exocord-restore-state-$suffix"
password="$(openssl rand -hex 24)"
cleanup() {
  docker rm --force "$container" > /dev/null 2>&1 || true
  docker volume rm --force "$state_volume" > /dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --name "$container" \
  --env POSTGRES_PASSWORD="$password" \
  --mount "type=bind,src=$dump,dst=/backup.dump,readonly" \
  postgres:17.10-alpine3.23 > /dev/null

for _ in $(seq 1 60); do
  if docker exec "$container" pg_isready --username postgres > /dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$container" pg_isready --username postgres > /dev/null
docker exec "$container" createdb --username postgres restore_drill
docker exec "$container" pg_restore --exit-on-error --no-owner --no-acl \
  --username postgres --dbname restore_drill /backup.dump

restored_migrations="$(
  docker exec "$container" psql --tuples-only --no-align \
    --username postgres --dbname restore_drill \
    --command 'SELECT COUNT(*) FROM _sqlx_migrations WHERE success'
)"
if [[ "$restored_migrations" -ne "$expected_migrations" ]]; then
  printf 'expected %s successful migrations, restored %s\n' \
    "$expected_migrations" "$restored_migrations" >&2
  exit 1
fi

docker volume create "$state_volume" > /dev/null
docker run --rm \
  --mount "type=bind,src=$state,dst=/backup/state.tar.gz,readonly" \
  --volume "$state_volume:/restore" \
  alpine:3.23 \
  tar -xzf /backup/state.tar.gz -C /restore
if ! docker run --rm --volume "$state_volume:/restore:ro" alpine:3.23 \
  test -s /restore/auth.sqlite3
then
  printf 'state archive does not contain auth.sqlite3\n' >&2
  exit 1
fi
sqlite_integrity="$(
  docker run --rm --volume "$state_volume:/restore:ro" alpine:3.23 \
    sh -Eeuc 'apk add --no-cache sqlite >/dev/null && sqlite3 /restore/auth.sqlite3 "PRAGMA integrity_check;"'
)"
if [[ "$sqlite_integrity" != "ok" ]]; then
  printf 'restored auth SQLite integrity check failed: %s\n' "$sqlite_integrity" >&2
  exit 1
fi

printf 'restore drill passed: %s PostgreSQL migrations and auth SQLite integrity\n' \
  "$restored_migrations"
