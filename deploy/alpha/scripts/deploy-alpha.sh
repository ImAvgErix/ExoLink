#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  printf 'usage: %s NEW_IMMUTABLE_IMAGE_TAG [--r2] [--apple] [--prebuilt]\n' "$0" >&2
  exit 2
}

if [[ $# -lt 1 || $# -gt 4 ]]; then
  usage
fi
new_tag="$1"
shift
if [[ ! "$new_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  printf 'invalid Docker image tag: %s\n' "$new_tag" >&2
  exit 2
fi

apple=false
prebuilt=false
r2=false
for option in "$@"; do
  case "$option" in
    --apple) apple=true ;;
    --prebuilt) prebuilt=true ;;
    --r2) r2=true ;;
    *) usage ;;
  esac
done

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$deploy_dir/.env"
if [[ ! -f "$env_file" ]]; then
  printf 'missing %s; copy .env.example and configure it first\n' "$env_file" >&2
  exit 2
fi

exec 9>"$deploy_dir/.deploy.lock"
if ! flock --nonblock 9; then
  printf 'another alpha deployment is already running\n' >&2
  exit 1
fi

read_tag() {
  local value
  value="$(
    awk -F= '/^EXOCORD_IMAGE_TAG=/{value=substr($0, index($0, "=") + 1)} END{print value}' \
      "$env_file"
  )"
  value="${value%$'\r'}"
  printf '%s' "$value"
}

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

old_tag="$(read_tag)"
if [[ -z "$old_tag" ]]; then
  printf 'EXOCORD_IMAGE_TAG is empty in %s\n' "$env_file" >&2
  exit 2
fi
if [[ ! "$old_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  printf 'current EXOCORD_IMAGE_TAG is invalid: %s\n' "$old_tag" >&2
  exit 2
fi
if [[ "$old_tag" == "$new_tag" ]]; then
  printf 'new tag must differ from the currently configured tag (%s)\n' "$old_tag" >&2
  exit 2
fi
old_image_available=false
if docker image inspect "exocord-api:$old_tag" > /dev/null 2>&1; then
  old_image_available=true
fi

EXOCORD_IMAGE_TAG="$new_tag" "${compose[@]}" config --quiet
if [[ "$prebuilt" == true ]]; then
  if ! docker image inspect "exocord-api:$new_tag" > /dev/null 2>&1; then
    printf 'prebuilt image is unavailable: exocord-api:%s\n' "$new_tag" >&2
    exit 2
  fi
else
  EXOCORD_IMAGE_TAG="$new_tag" "${compose[@]}" build --pull api
fi

write_tag "$new_tag"
rollback_required=true
# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
  if [[ "$rollback_required" == true ]]; then
    printf 'deployment failed; restoring application tag %s\n' "$old_tag" >&2
    write_tag "$old_tag"
    if [[ "$old_image_available" == true ]]; then
      "${compose[@]}" up -d --no-deps api > /dev/null || true
    else
      "${compose[@]}" rm --stop --force api > /dev/null || true
    fi
  fi
}
trap cleanup EXIT

if [[ "$old_image_available" == true ]]; then
  "${compose[@]}" up -d --no-deps api
else
  # The bootstrap deployment must also create PostgreSQL and the HTTPS edge.
  "${compose[@]}" up -d
fi
for _ in $(seq 1 60); do
  if "${compose[@]}" exec -T api \
    curl --fail --silent http://127.0.0.1:4100/ready > /dev/null 2>&1
  then
    rollback_required=false
    trap - EXIT
    printf 'deployed exocord-api:%s (previous tag: %s)\n' "$new_tag" "$old_tag"
    exit 0
  fi
  sleep 1
done

printf 'new API did not become ready within 60 seconds\n' >&2
exit 1
