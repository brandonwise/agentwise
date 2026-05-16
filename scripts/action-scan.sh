#!/usr/bin/env bash
set -euo pipefail

: "${INPUT_PATH:=.}"
: "${INPUT_FORMAT:=terminal}"
: "${INPUT_FAIL_ON:=}"
: "${INPUT_OUTPUT:=}"
: "${INPUT_LIVE:=false}"
: "${INPUT_SUPPLY_CHAIN:=false}"

cmd=(agentwise scan "$INPUT_PATH" --format "$INPUT_FORMAT")

if [[ -n "$INPUT_FAIL_ON" ]]; then
  cmd+=(--fail-on "$INPUT_FAIL_ON")
fi

if [[ -n "$INPUT_OUTPUT" ]]; then
  cmd+=(--output "$INPUT_OUTPUT")
fi

case "$INPUT_LIVE" in
  true)
    cmd+=(--live)
    ;;
  false|"")
    ;;
  *)
    echo "INPUT_LIVE must be 'true' or 'false'" >&2
    exit 1
    ;;
esac

case "$INPUT_SUPPLY_CHAIN" in
  true)
    cmd+=(--supply-chain)
    ;;
  false|"")
    ;;
  *)
    echo "INPUT_SUPPLY_CHAIN must be 'true' or 'false'" >&2
    exit 1
    ;;
esac

printf 'Running:'
printf ' %q' "${cmd[@]}"
printf '\n'
"${cmd[@]}"
