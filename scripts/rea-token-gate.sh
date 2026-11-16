#!/usr/bin/env bash
# Empirical REA gate — measures the REAL analysis-cost tax ReaOverflow imposes on the real `rea`
# CLI, instead of trusting the optimistic ReaModel.
#
#   scripts/rea-token-gate.sh [original.dll] [protected.dll] [minRatio]
#
# Runs `rea inspect-managed-members <path> --token-count` on an original and a protected assembly
# and asserts the protected/original token RATIO is at least <minRatio> (default 1.15x). This is the
# ground-truth counterpart to `reaoverflow analyze` (which is MODELLED and OVER-PREDICTS — it claims
# `crossesBudget:true` for assemblies REA decodes completely). A passing gate proves a real, measured
# cost tax; it does NOT claim budget exhaustion (in testing REA decoded both sides fully).
#
# OPT-IN: not part of `dotnet test` — it needs Node.js + the `rea` npm CLI
# (https://github.com/morluto/rea), which are not on CI by default. Install rea, then run this.
# With no arguments the script builds the sample + CLI and protects it with P2,P3,P4,P5.
set -uo pipefail

MIN_RATIO="${3:-1.15}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

fail() { echo "FAIL: $1" >&2; exit "${2:-1}"; }

command -v rea >/dev/null 2>&1 || fail "the 'rea' CLI is not on PATH. Install Node.js + rea (https://github.com/morluto/rea), then re-run. This gate is opt-in and is intentionally not part of 'dotnet test'." 2

ORIG="${1:-}"
PROT="${2:-}"

if [ -z "$ORIG" ] || [ -z "$PROT" ]; then
    echo "No assemblies supplied — building sample + CLI and protecting with P2,P3,P4,P5..."
    dotnet build "$REPO_ROOT/samples/HelloTarget" -c Release --nologo >/dev/null
    ORIG="$REPO_ROOT/samples/HelloTarget/bin/Release/net8.0/HelloTarget.dll"
    WORK="$(mktemp -d)"
    PROT="$WORK/HelloTarget.protected.dll"
    dotnet run --project "$REPO_ROOT/src/ReaOverflow.Cli" -c Release -- \
        protect "$ORIG" -o "$PROT" --passes P2,P3,P4,P5 --intensity maximum >/dev/null
fi

[ -f "$ORIG" ] || fail "original not found: $ORIG"
[ -f "$PROT" ] || fail "protected not found: $PROT"

rea_tokens() {
    # A clean exit means REA decoded the assembly completely (no crash, no refusal).
    local out n
    out="$(rea inspect-managed-members "$1" --token-count 2>&1)" || fail "rea failed on $1: $out"
    n="$(printf '%s\n' "$out" | grep -Eo '[0-9]+' | tail -1)"
    [ -n "$n" ] || fail "could not parse a token count from rea output for $1. Raw: $out"
    echo "$n"
}

echo ""
echo "Empirical REA gate (real rea CLI — $(rea --version 2>/dev/null))"
ORIG_TOK="$(rea_tokens "$ORIG")"
PROT_TOK="$(rea_tokens "$PROT")"
RATIO="$(awk -v p="$PROT_TOK" -v o="$ORIG_TOK" 'BEGIN { printf "%.3f", p / o }')"

printf "  original : %10d tokens   %s\n" "$ORIG_TOK" "$(basename "$ORIG")"
printf "  protected: %10d tokens   %s\n" "$PROT_TOK" "$(basename "$PROT")"
printf "  ratio    : %sx   (threshold >= %sx)\n" "$RATIO" "$MIN_RATIO"
echo   "  note: both sides decoded COMPLETELY (rea exited 0) — this is a measured cost tax, not budget exhaustion."

PASS="$(awk -v r="$RATIO" -v m="$MIN_RATIO" 'BEGIN { print (r >= m) ? 1 : 0 }')"
if [ "$PASS" = "1" ]; then
    echo ""
    echo "PASS: protected representation is ${RATIO}x the original (>= ${MIN_RATIO})."
    exit 0
else
    fail "protected representation is only ${RATIO}x the original (< ${MIN_RATIO}) — protection did not impose the expected measured tax."
fi
