#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  printf 'usage: %s EXPECTED_SOURCE_SHA256 IMMUTABLE_IMAGE_TAG\n' "$0" >&2
  exit 2
}

if [[ $# -ne 2 ]]; then
  usage
fi
expected_sha256="${1,,}"
image_tag="$2"
if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'expected source SHA-256 must contain 64 lowercase hexadecimal characters\n' >&2
  exit 2
fi
if [[ ! "$image_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  printf 'invalid immutable image tag: %s\n' "$image_tag" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  printf 'install-api-host.sh must run as root\n' >&2
  exit 2
fi

source_archive="/tmp/exocord-api-source.tar.gz"
environment_file="/tmp/exocord-alpha.env"
livekit_key_file="/tmp/exocord-livekit-api-key"
livekit_secret_file="/tmp/exocord-livekit-api-secret"
install_root="/opt/exocord"
deploy_dir="$install_root/deploy/alpha"
archive_list="$(mktemp /tmp/exocord-archive-list.XXXXXX)"
install_marker="$install_root/.install-source-sha256"

cleanup() {
  rm -f -- \
    "$archive_list" \
    "$source_archive" \
    "$environment_file" \
    "$livekit_key_file" \
    "$livekit_secret_file"
}
trap cleanup EXIT

for required_file in \
  "$source_archive" \
  "$environment_file" \
  "$livekit_key_file" \
  "$livekit_secret_file"
do
  if [[ ! -s "$required_file" || -L "$required_file" ]]; then
    printf 'required staged file is missing, empty, or a symlink: %s\n' \
      "$required_file" >&2
    exit 2
  fi
done

actual_sha256="$(sha256sum "$source_archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  printf 'source archive checksum mismatch: expected %s, got %s\n' \
    "$expected_sha256" "$actual_sha256" >&2
  exit 1
fi
tar -tzf "$source_archive" > "$archive_list"
if grep -Eq \
  '(^/|(^|/)\.\.(/|$)|(^|/)(target|node_modules|artifacts|work|\.git)(/|$))' \
  "$archive_list"
then
  printf 'source archive contains an unsafe or forbidden path\n' >&2
  exit 1
fi
for required_entry in \
  Cargo.lock \
  apps/desktop/src-tauri/Cargo.toml \
  deploy/alpha/compose.yaml \
  deploy/alpha/Dockerfile \
  deploy/alpha/scripts/deploy-alpha.sh
do
  if ! grep -Fxq "$required_entry" "$archive_list"; then
    printf 'source archive is missing %s\n' "$required_entry" >&2
    exit 1
  fi
done

cloud-init status --wait
if [[ ! -s /var/lib/exocord-bootstrap-ready ]]; then
  printf 'Oracle host bootstrap marker is missing\n' >&2
  exit 1
fi
docker version > /dev/null
docker compose version > /dev/null

api_domain="$(
  awk -F= '/^EXOCORD_DOMAIN=/{print substr($0, index($0, "=") + 1); exit}' \
    "$environment_file"
)"
if [[ ! "$api_domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] ||
  [[ "$api_domain" != *.* ]]
then
  printf 'staged EXOCORD_DOMAIN is missing or invalid\n' >&2
  exit 2
fi
if ! getent ahostsv4 "$api_domain" > /dev/null; then
  printf 'public DNS does not resolve yet for %s\n' "$api_domain" >&2
  exit 1
fi

if [[ -s "$install_marker" ]]; then
  installed_sha256="$(tr -d '\r\n' < "$install_marker")"
  if [[ "$installed_sha256" != "$expected_sha256" ]]; then
    printf 'the existing installation has a different source bundle; use the upgrade path\n' >&2
    exit 2
  fi
  if [[ ! -s "$deploy_dir/.env" ]]; then
    printf 'the existing installation marker has no environment file\n' >&2
    exit 1
  fi
  installed_domain="$(
    awk -F= '/^EXOCORD_DOMAIN=/{print substr($0, index($0, "=") + 1); exit}' \
      "$deploy_dir/.env"
  )"
  if [[ "$installed_domain" != "$api_domain" ]]; then
    printf 'the staged API domain does not match the existing installation\n' >&2
    exit 2
  fi
else
  first_install_entry="$(
    find "$install_root" -mindepth 1 -maxdepth 1 -print -quit
  )"
  if [[ -n "$first_install_entry" ]]; then
    printf '%s is not empty; refusing to overwrite an unknown installation\n' \
      "$install_root" >&2
    exit 2
  fi
  tar --extract --gzip --file "$source_archive" \
    --directory "$install_root" --no-same-owner --no-same-permissions
  chown -R root:root "$install_root"
  find "$install_root/deploy/alpha/scripts" -maxdepth 1 -type f -name '*.sh' \
    -exec chmod 0755 {} +
  install -m 0600 -o root -g root "$environment_file" "$deploy_dir/.env"
  bash "$deploy_dir/scripts/init-secrets.sh"
  printf '%s\n' "$expected_sha256" > "$install_marker"
  chmod 0600 "$install_marker"
fi

install -m 0400 -o 10001 -g 10001 \
  "$livekit_key_file" "$deploy_dir/secrets/livekit-api-key"
install -m 0400 -o 10001 -g 10001 \
  "$livekit_secret_file" "$deploy_dir/secrets/livekit-api-secret"

install -d -m 0700 -o root -g root /var/backups/exocord-alpha
install -m 0644 "$deploy_dir"/systemd/*.service /etc/systemd/system/
install -m 0644 "$deploy_dir"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

cd "$deploy_dir"
configured_tag="$(
  awk -F= '/^EXOCORD_IMAGE_TAG=/{print substr($0, index($0, "=") + 1); exit}' .env
)"
running_services="$(docker compose --env-file .env ps --status running --services)"
if [[ "$configured_tag" != "$image_tag" ]]; then
  bash scripts/deploy-alpha.sh "$image_tag"
elif ! grep -Fxq api <<<"$running_services"; then
  docker compose --env-file .env up -d
fi

ready=false
for _ in $(seq 1 90); do
  if curl --fail --silent --show-error --max-time 10 \
    "https://$api_domain/ready" > /dev/null 2>&1
  then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != true ]]; then
  printf 'public HTTPS readiness did not recover for %s\n' "$api_domain" >&2
  exit 1
fi

bash scripts/backup-alpha.sh /var/backups/exocord-alpha
systemctl enable --now \
  exocord-alpha-backup.timer \
  exocord-alpha-backup-freshness.timer
systemctl start exocord-alpha-backup-freshness.service

docker compose --env-file .env ps
systemctl --no-pager --full status \
  exocord-alpha-backup.timer \
  exocord-alpha-backup-freshness.timer
printf 'Exocord API host installed: https://%s (%s)\n' \
  "$api_domain" "$image_tag"
