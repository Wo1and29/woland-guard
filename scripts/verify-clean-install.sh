#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

cd -- "$PROJECT_ROOT"
exec uv run --no-project --python 3.12 python -m scripts.demo_e2e.clean_install \
  --source-root "$PROJECT_ROOT"
