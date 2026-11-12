#!/bin/sh
set -eu
if [ "${QS_API_TOKEN:-}" = "" ]; then
  echo "refusing to start: QS_API_TOKEN must be set for a public listener" >&2
  exit 1
fi
exec "$@"
