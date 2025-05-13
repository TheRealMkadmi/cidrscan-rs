#!/usr/bin/env bash
set -e

if [ "$RUNNER_OS" = "Windows" ]; then
  exec cargo "$@"
else
  if command -v cross >/dev/null 2>&1; then
    exec cross "$@"
  else
    exec cargo "$@"
  fi
fi