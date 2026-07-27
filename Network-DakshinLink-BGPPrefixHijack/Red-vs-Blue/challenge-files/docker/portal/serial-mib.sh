#!/usr/bin/env bash
set -euo pipefail
base=".1.3.6.1.2.1.47.1.1.1.1.11"
instance="${base}.1"
case "${1:-}" in
  -g)
    [[ "${2:-}" == "$instance" ]] || exit 0
    printf '%s\nstring\nSN#%s\n' "$instance" "${DEVICE_SERIAL:?}"
    ;;
  -n)
    requested="${2:-}"
    [[ "$requested" < "$instance" ]] || exit 0
    printf '%s\nstring\nSN#%s\n' "$instance" "${DEVICE_SERIAL:?}"
    ;;
  *)
    exit 0
    ;;
esac
