#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  printf 'usage: %s EXISTING_IMAGE_TAG [--r2] [--apple]\n' "$0" >&2
  exit 2
}

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage
fi
target_tag="$1"
shift
if [[ ! "$target_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  printf 'invalid Docker image tag: %s\n' "$target_tag" >&2
  exit 2
fi

apple=false
r2=false
for option in "$@"; do
  case "$option" in
    --apple) apple=true ;;
    --r2) r2=true ;;
    *) usage ;;
  esac
done

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$deploy_dir/.env"
if [[ ! -f "$env_file" ]]; then
  printf 'missing %s\n' "$env_file" >&2
  exit 2
fi
if ! docker image inspect "exocord-api:$target_tag" > /dev/null 2>&1; then
  printf 'local image does not exist: exocord-api:%s\n' "$target_tag" >&2
  exit 2
fi

exec 9>"$deploy_dir/.deploy.lock"
if ! flock --nonblock 9; then
  printf 'another alpha deployment is already running\n' >&2
  exit 1
fi

current_tag="$(
  awk -F= '/^EXOCORD_IMAGE_TAG=/{value=substr($0, index($0, "=") + 1)} END{print value}' \
    "$env_file"
)"
current_tag="${current_tag%$'\r'}"
if [[ -z "$current_tag" ]]; then
  printf 'EXOCORD_IMAGE_TAG is empty in %s\n' "$env_file" >&2
  exit 2
fi
if [[ ! "$current_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  printf 'current EXOCORD_IMAGE_TAG is invalid: %s\n' "$current_tag" >&2
  exit 2
fi
if [[ "$current_tag" == "$target_tag" ]]; then
  printf 'target tag is already configured: %s\n' "$target_tag" >&2
  exit 2
fi
if ! docker image inspect "exocord-api:$current_tag" > /dev/null 2>&1; then
  printf 'current local image does not exist: exocord-api:%s\n' "$current_tag" >&2
  exit 2
fi

write_tag() {
  local tag="$1"
  local temporary
  temporary="$(mktemp "$deploy_dir/.env.tmp.XXXXXX")"
  awk -v tag="$tag" '
    BEGIN { replaced = 0 }
    /^EXOCORD_IMAGE_TAG=/ {
      if (!replaced) {
        print "EXOCORD_IMAGE_TAG=" tag
        replaced = 1
      }
      next
    }
    { print }
    END {
      if (!replaced) {
        print "EXOCORD_IMAGE_TAG=" tag
      }
    }
  ' "$env_file" > "$temporary"
  chmod --reference="$env_file" "$temporary"
  mv -- "$temporary" "$env_file"
}

compose=(docker compose --env-file "$env_file" -f "$deploy_dir/compose.yaml")
if [[ "$r2" == true ]]; then
  compose+=(-f "$deploy_dir/compose.r2.yaml")
fi
if [[ "$apple" == true ]]; then
  compose+=(-f "$deploy_dir/compose.apple.yaml")
fi

write_tag "$target_tag"
restore_current=true
# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
  if [[ "$restore_current" == true ]]; then
    printf 'rollback target failed; restoring application tag %s\n' "$current_tag" >&2
    write_tag "$current_tag"
    "${compose[@]}" up -d --no-deps api > /dev/null || true
  fi
}
trap cleanup EXIT

"${compose[@]}" config --quiet
"${compose[@]}" up -d --no-deps api
for _ in $(seq 1 60); do
  if "${compose[@]}" exec -T api \
    curl --fail --silent http://127.0.0.1:4100/ready > /dev/null 2>&1
  then
    restore_current=false
    trap - EXIT
    printf 'rolled back from exocord-api:%s to exocord-api:%s\n' \
      "$current_tag" "$target_tag"
    exit 0
  fi
  sleep 1
done

printf 'rollback API did not become ready within 60 seconds\n' >&2
exit 1
