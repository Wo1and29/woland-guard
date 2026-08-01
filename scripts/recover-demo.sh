#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: scripts/recover-demo.sh ABSOLUTE_LEDGER" >&2
    exit 2
fi

case "$1" in
  /*) ;;
  *)
    echo "recovery ledger path must be absolute" >&2
    exit 2
    ;;
esac
exec uv run --no-sync python -m scripts.demo_e2e.recovery cleanup --ledger "$1"
