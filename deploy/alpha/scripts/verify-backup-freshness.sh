#!/usr/bin/env bash
set -Eeuo pipefail

backup_dir="${1:-/var/backups/exocord-alpha}"
max_age_seconds="${2:-129600}"
if [[ ! "$max_age_seconds" =~ ^[1-9][0-9]*$ ]]; then
  printf 'maximum age must be a positive number of seconds\n' >&2
  exit 2
fi
backup_dir="$(realpath "$backup_dir")"
if [[ ! -d "$backup_dir" ]]; then
  printf 'backup directory does not exist: %s\n' "$backup_dir" >&2
  exit 1
fi

latest_manifest="$(
  find "$backup_dir" -maxdepth 1 -type f -name 'exocord-*.sha256' \
    -printf '%T@ %p\n' |
    sort -nr |
    head -n 1 |
    cut -d' ' -f2-
)"
if [[ -z "$latest_manifest" || ! -f "$latest_manifest" ]]; then
  printf 'no Exocord backup manifest exists in %s\n' "$backup_dir" >&2
  exit 1
fi

modified_epoch="$(stat --format='%Y' "$latest_manifest")"
age_seconds="$(( $(date -u +%s) - modified_epoch ))"
if (( age_seconds < 0 )); then
  printf 'latest backup manifest is dated in the future: %s\n' "$latest_manifest" >&2
  exit 1
fi
if (( age_seconds > max_age_seconds )); then
  printf 'latest backup is %s seconds old (maximum %s): %s\n' \
    "$age_seconds" "$max_age_seconds" "$latest_manifest" >&2
  exit 1
fi

prefix="$(basename "$latest_manifest" .sha256)"
expected_dump="$prefix.dump"
expected_state="$prefix.state.tar.gz"
if [[ "$(wc -l < "$latest_manifest" | tr -d ' ')" -ne 2 ]] ||
  ! grep -Eq "^[0-9a-f]{64}  ${expected_dump}$" "$latest_manifest" ||
  ! grep -Eq "^[0-9a-f]{64}  ${expected_state}$" "$latest_manifest"
then
  printf 'latest backup manifest has an unexpected shape: %s\n' "$latest_manifest" >&2
  exit 1
fi

(
  cd "$backup_dir"
  sha256sum --check --strict --status "$(basename "$latest_manifest")"
)
printf 'fresh verified backup: %s (%s seconds old)\n' \
  "$latest_manifest" "$age_seconds"
