#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# -ne 2 ]]; then
  printf 'usage: %s PRIMARY_DOMAIN TURN_DOMAIN\n' "$0" >&2
  exit 2
fi
primary_domain="${1,,}"
turn_domain="${2,,}"
domain_pattern='^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}$'
if [[ ! "$primary_domain" =~ $domain_pattern ]] ||
  [[ ! "$turn_domain" =~ $domain_pattern ]] ||
  [[ "$primary_domain" == "$turn_domain" ]]
then
  printf 'primary and TURN domains must be distinct public DNS hostnames\n' >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  printf 'generate-livekit.sh must run as root\n' >&2
  exit 2
fi

output_root="/var/lib/exocord-livekit"
generated_dir="$output_root/$primary_domain"
credential_key="$output_root/api-key"
credential_secret="$output_root/api-secret"
voice_installer="$output_root/voice-init.sh"
install -d -m 0700 -o root -g root "$output_root"

if [[ ! -s "$generated_dir/init_script.sh" ]]; then
  first_generated_entry="$(
    find "$generated_dir" -mindepth 1 -print -quit 2>/dev/null || true
  )"
  if [[ -n "$first_generated_entry" ]]; then
    printf 'incomplete LiveKit generator output already exists at %s\n' \
      "$generated_dir" >&2
    exit 1
  fi
  docker pull livekit/generate > /dev/null
  export LIVEKIT_PRIMARY_DOMAIN="$primary_domain"
  export LIVEKIT_TURN_DOMAIN="$turn_domain"
  expect <<'EXPECT_EOF'
set timeout 900
log_user 0
set primary $env(LIVEKIT_PRIMARY_DOMAIN)
set turn $env(LIVEKIT_TURN_DOMAIN)
spawn docker run --rm -it -v /var/lib/exocord-livekit:/output livekit/generate
expect -re {What to deploy}
send -- "\r"
expect -re {Primary domain name}
send -- "$primary\r"
expect -re {TURN domain name}
send -- "$turn\r"
expect -re {Which SSL issuers to use}
send -- "\r"
expect -re {LiveKit version}
send -- "\r"
expect -re {Use external Redis}
send -- "\r"
expect -re {Generate a startup script}
send -- "\r"
expect eof
set result [wait]
exit [lindex $result 3]
EXPECT_EOF
fi

for generated_file in \
  caddy.yaml \
  docker-compose.yaml \
  init_script.sh \
  livekit.yaml \
  redis.conf
do
  if [[ ! -s "$generated_dir/$generated_file" ]]; then
    printf 'LiveKit generator did not create %s\n' "$generated_file" >&2
    exit 1
  fi
done

credential="$(
  awk '
    /^keys:[[:space:]]*$/ { in_keys = 1; next }
    in_keys && /^[^[:space:]]/ { exit }
    in_keys && /^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*[^[:space:]]/ {
      sub(/^[[:space:]]+/, "")
      print
      exit
    }
  ' "$generated_dir/livekit.yaml"
)"
api_key="${credential%%:*}"
api_secret="${credential#*:}"
api_secret="${api_secret#"${api_secret%%[![:space:]]*}"}"
if [[ ! "$api_key" =~ ^API[A-Za-z0-9_-]{8,}$ ]] ||
  [[ ! "$api_secret" =~ ^[A-Za-z0-9_-]{16,}$ ]]
then
  printf 'could not safely extract generated LiveKit credentials\n' >&2
  exit 1
fi

printf '%s' "$api_key" > "$credential_key"
printf '%s' "$api_secret" > "$credential_secret"
install -m 0600 -o root -g root \
  "$generated_dir/init_script.sh" "$voice_installer"
chmod 0600 "$credential_key" "$credential_secret"
sha256sum "$voice_installer" > "$output_root/voice-init.sha256"
chmod 0600 "$output_root/voice-init.sha256"

printf 'Official LiveKit startup script generated for %s and %s\n' \
  "$primary_domain" "$turn_domain"
