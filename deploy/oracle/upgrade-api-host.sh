#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# -ne 4 ]]; then
  printf 'usage: %s SOURCE_ARCHIVE SHA256 IMAGE_TAG API_DOMAIN\n' "$0" >&2
  exit 2
fi

source_archive="$1"
expected_sha256="$2"
image_tag="$3"
api_domain="$4"
install_root="/opt/exocord"
deploy_dir="$install_root/deploy/alpha"

if [[ ! "$expected_sha256" =~ ^[a-f0-9]{64}$ ]] ||
   [[ ! "$image_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] ||
   [[ ! "$api_domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$ ]]
then
  printf 'invalid upgrade arguments\n' >&2
  exit 2
fi
if [[ ! -f "$source_archive" ]] || [[ ! -s "$deploy_dir/.env" ]] ||
   [[ ! -s "$install_root/.install-source-sha256" ]]
then
  printf 'the staged archive or current installation is unavailable\n' >&2
  exit 2
fi
actual_sha256="$(sha256sum "$source_archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  printf 'source archive checksum mismatch\n' >&2
  exit 1
fi

exec 9>"$install_root/.upgrade.lock"
if ! flock --nonblock 9; then
  printf 'another API upgrade is already running\n' >&2
  exit 1
fi

old_sha256="$(tr -d '\r\n' < "$install_root/.install-source-sha256")"
if [[ "$old_sha256" == "$expected_sha256" ]]; then
  printf 'source bundle is already installed\n'
  exit 0
fi

candidate="/opt/exocord.upgrade.${expected_sha256:0:12}"
previous="/opt/exocord.previous.$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -e "$candidate" ]] || [[ -e "$previous" ]]; then
  printf 'candidate or rollback path already exists\n' >&2
  exit 2
fi

bash "$deploy_dir/scripts/backup-alpha.sh" /var/backups/exocord-alpha
install -d -m 0700 -o root -g root "$candidate"
tar --extract --gzip --file "$source_archive" \
  --directory "$candidate" --no-same-owner --no-same-permissions
chown -R root:root "$candidate"
find "$candidate/deploy/alpha/scripts" -maxdepth 1 -type f -name '*.sh' \
  -exec chmod 0755 {} +
install -m 0600 -o root -g root "$deploy_dir/.env" \
  "$candidate/deploy/alpha/.env"
install -d -m 0700 -o root -g root "$candidate/deploy/alpha/secrets"
cp -a "$deploy_dir/secrets/." "$candidate/deploy/alpha/secrets/"

candidate_deploy="$candidate/deploy/alpha"
EXOCORD_IMAGE_TAG="$image_tag" \
  docker compose --env-file "$candidate_deploy/.env" \
    -f "$candidate_deploy/compose.yaml" config --quiet
EXOCORD_IMAGE_TAG="$image_tag" \
  docker compose --env-file "$candidate_deploy/.env" \
    -f "$candidate_deploy/compose.yaml" build --pull api

mv -- "$install_root" "$previous"
mv -- "$candidate" "$install_root"
rollback=true
# Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2329
rollback_upgrade() {
  if [[ "$rollback" == true ]]; then
    failed="/opt/exocord.failed.${expected_sha256:0:12}"
    mv -- "$install_root" "$failed" || true
    mv -- "$previous" "$install_root" || true
    cd "$install_root/deploy/alpha"
    docker compose --env-file .env up -d --no-deps api || true
  fi
}
trap rollback_upgrade EXIT

cd "$deploy_dir"
bash scripts/deploy-alpha.sh "$image_tag" --prebuilt
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error --max-time 10 \
    "https://$api_domain/ready" >/dev/null
  then
    rollback=false
    trap - EXIT
    printf '%s\n' "$expected_sha256" > "$install_root/.install-source-sha256"
    chmod 0600 "$install_root/.install-source-sha256"
    install -m 0644 "$deploy_dir"/systemd/*.service /etc/systemd/system/
    install -m 0644 "$deploy_dir"/systemd/*.timer /etc/systemd/system/
    systemctl daemon-reload
    systemctl restart exocord-alpha-backup.timer \
      exocord-alpha-backup-freshness.timer
    bash scripts/backup-alpha.sh /var/backups/exocord-alpha
    printf 'upgraded Exocord API to %s; rollback tree: %s\n' \
      "$image_tag" "$previous"
    exit 0
  fi
  sleep 2
done
printf 'public readiness failed after upgrade\n' >&2
exit 1
