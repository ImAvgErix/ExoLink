#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

deploy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
secrets_dir="$deploy_dir/secrets"
api_uid=10001
api_gid=10001
mkdir -p "$secrets_dir"

write_if_missing() {
  local path="$1"
  local value="$2"
  if [[ ! -s "$path" ]]; then
    printf '%s' "$value" > "$path"
  fi
  chown "$api_uid:$api_gid" "$path"
  chmod 400 "$path"
}

random_base64url() {
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\r\n'
}

write_if_missing "$secrets_dir/postgres-password" "$(openssl rand -hex 32)"
write_if_missing "$secrets_dir/attachment-capability-key" "$(random_base64url)"
write_if_missing "$secrets_dir/attachment-object-key" "$(random_base64url)"
write_if_missing "$secrets_dir/franking-key" "$(random_base64url)"
write_if_missing "$secrets_dir/operator-token" "exo_op_$(random_base64url)"
write_if_missing "$secrets_dir/provider-token-key" "$(random_base64url)"

for name in \
  r2-access-key-id \
  r2-secret-access-key \
  livekit-api-key \
  livekit-api-secret \
  apple-private-key.p8
do
  path="$secrets_dir/$name"
  if [[ ! -e "$path" ]]; then
    : > "$path"
  fi
  chown "$api_uid:$api_gid" "$path"
  chmod 400 "$path"
done

printf '%s\n' \
  "Secret files initialized in $secrets_dir." \
  "Fill the two LiveKit credential files before starting the base deployment." \
  "Fill the R2 credential files only when enabling the optional R2 overlay." \
  "Fill apple-private-key.p8 only when enabling the Apple overlay."
