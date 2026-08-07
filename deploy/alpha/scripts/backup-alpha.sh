#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backup_dir="${1:-"$deploy_dir/backups"}"
mkdir -p "$backup_dir"
backup_dir="$(realpath "$backup_dir")"
if [[ "$backup_dir" == "/" || "$backup_dir" == "$deploy_dir" ]]; then
  printf 'refusing unsafe backup directory: %s\n' "$backup_dir" >&2
  exit 2
fi

read_env_value() {
  local name="$1"
  local value
  value="$(
    awk -F= -v name="$name" '
      $1 == name { value = substr($0, index($0, "=") + 1) }
      END { print value }
    ' "$deploy_dir/.env"
  )"
  value="${value%$'\r'}"
  printf '%s' "$value"
}

retention_sets="$(read_env_value EXOCORD_BACKUP_RETENTION_SETS)"
retention_sets="${retention_sets:-3}"
if [[ ! "$retention_sets" =~ ^[1-9][0-9]*$ || "$retention_sets" -gt 30 ]]; then
  printf 'EXOCORD_BACKUP_RETENTION_SETS must be an integer from 1 through 30\n' >&2
  exit 2
fi
postgres_user="$(read_env_value POSTGRES_USER)"
postgres_user="${postgres_user:-exocord}"
postgres_db="$(read_env_value POSTGRES_DB)"
postgres_db="${postgres_db:-exocord}"
for identifier in "$postgres_user" "$postgres_db"; do
  if [[ ! "$identifier" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]]; then
    printf 'backup database identifiers must be simple PostgreSQL names\n' >&2
    exit 2
  fi
done

exec 9>"$backup_dir/.backup.lock"
if ! flock --nonblock 9; then
  printf 'another alpha backup is already running\n' >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
prefix="exocord-$timestamp"
dump_tmp="$backup_dir/$prefix.dump.tmp"
state_tmp="$backup_dir/$prefix.state.tar.gz.tmp"
dump="$backup_dir/$prefix.dump"
state="$backup_dir/$prefix.state.tar.gz"
manifest="$backup_dir/$prefix.sha256"
api_was_running=false

cleanup() {
  rm -f -- "$dump_tmp" "$state_tmp"
  if [[ "$api_was_running" == true ]]; then
    (
      cd "$deploy_dir"
      docker compose --env-file .env start api > /dev/null
    ) || true
  fi
}
trap cleanup EXIT

cd "$deploy_dir"
if docker compose --env-file .env ps --status running --services | grep -qx api; then
  api_was_running=true
  docker compose --env-file .env stop --timeout 30 api
fi

docker compose --env-file .env exec -T postgres \
  pg_dump --format=custom --no-owner --no-acl \
  --username "$postgres_user" \
  --dbname "$postgres_db" > "$dump_tmp"
docker compose --env-file .env exec -T postgres \
  pg_restore --list < "$dump_tmp" > /dev/null

docker run --rm \
  --volume exocord-alpha-api-state:/source:ro \
  --volume "$backup_dir:/backup" \
  alpine:3.23 \
  tar --numeric-owner -C /source -czf "/backup/$(basename "$state_tmp")" .
docker run --rm \
  --volume "$backup_dir:/backup:ro" \
  alpine:3.23 \
  tar -tzf "/backup/$(basename "$state_tmp")" > /dev/null

mv -- "$dump_tmp" "$dump"
mv -- "$state_tmp" "$state"
(
  cd "$backup_dir"
  sha256sum "$(basename "$dump")" "$(basename "$state")" > "$(basename "$manifest")"
)

if [[ "$api_was_running" == true ]]; then
  docker compose --env-file .env start api > /dev/null
  for _ in $(seq 1 60); do
    if docker compose --env-file .env exec -T api \
      curl --fail --silent http://127.0.0.1:4100/ready > /dev/null 2>&1
    then
      api_was_running=false
      break
    fi
    sleep 1
  done
  if [[ "$api_was_running" == true ]]; then
    printf 'API did not become ready after backup\n' >&2
    exit 1
  fi
fi

mapfile -t expired_manifests < <(
  find "$backup_dir" -maxdepth 1 -type f -name 'exocord-*.sha256' \
    -printf '%f\n' |
    sort --reverse |
    tail -n "+$((retention_sets + 1))"
)
for expired_manifest in "${expired_manifests[@]}"; do
  if [[ ! "$expired_manifest" =~ ^(exocord-[0-9]{8}T[0-9]{6}Z)\.sha256$ ]]; then
    printf 'refusing unexpected backup manifest name: %s\n' "$expired_manifest" >&2
    exit 1
  fi
  expired_prefix="${BASH_REMATCH[1]}"
  rm -f -- \
    "$backup_dir/$expired_prefix.dump" \
    "$backup_dir/$expired_prefix.state.tar.gz" \
    "$backup_dir/$expired_prefix.sha256"
done

trap - EXIT
printf '%s\n' "$manifest"
