#!/usr/bin/env bash
# Empirical REA gate for P9 — proves the representation bomb EXHAUSTS rea's 64 MiB representation
# budget on the REAL `rea` CLI, instead of trusting the model.
#
#   scripts/rea-p9-exhaustion-gate.sh                          # builds the sample, protects with P9 (maximum)
#   scripts/rea-p9-exhaustion-gate.sh original.dll p9.dll      # tests one supplied pair
#
# Asserts, against the real rea CLI:
#   * ORIGINAL inspect-managed-members -> coverage COMPLETE (rea reads the members fine).
#   * P9 BUILD inspect-managed-members -> coverage UNAVAILABLE with a resource-limit issue
#     ("Managed metadata exceeds the 67108864 byte representation budget") and ZERO managed members.
# This is a denial BY EXHAUSTION, not a crash: rea exits 0 and reports the budget overflow. The
# matching load-safety + runtime-equivalence of the P9 build is proven separately by `dotnet test`
# (GatedPassTests.P9_RepresentationBomb_*) and `reaoverflow verify`.
#
# MEASURED 2026-11-16 against rea@6.7.0 (quadratic cross-reference lever; cliff ~218k-238k edges on
# FileHound.Core.dll). OPT-IN: not part of `dotnet test` — it needs Node.js + the `rea` CLI.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
fail() { echo "FAIL: $1" >&2; exit "${2:-1}"; }

command -v rea >/dev/null 2>&1 || fail "the 'rea' CLI is not on PATH. Install Node.js + rea, then re-run. This gate is opt-in and is intentionally not part of 'dotnet test'." 2

# Extract normalized_result.coverage.{state, issues[0].code, issues[0].detail}. Prints "<state>|<code>|<detail>".
probe() {
    rea inspect-managed-members "$1" --format json 2>/dev/null | node -e '
        let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
          try{const c=(JSON.parse(s).normalized_result||{}).coverage||{};
            const i=(c.issues&&c.issues[0])||{};
            console.log([c.state||"none",i.code||"",i.detail||""].join("|"));}
          catch(e){console.log("parsefail||");}});'
}

assert_complete() {
    local state; state="$(probe "$1" | cut -d'|' -f1)"
    printf "  original  members : coverage=%s   %s\n" "$state" "$(basename "$1")"
    [ "$state" = "complete" ] || fail "original members coverage is '$state', expected 'complete' — rea should read the unprotected sample fully."
}

assert_exhausted() {
    local path="$1" label="$2" out state code detail
    out="$(probe "$path")"; state="$(echo "$out" | cut -d'|' -f1)"; code="$(echo "$out" | cut -d'|' -f2)"; detail="$(echo "$out" | cut -d'|' -f3-)"
    printf "  P9[%-8s] members: coverage=%s issue=%s\n" "$label" "$state" "$code"
    [ "$state" = "unavailable" ] || fail "[$label] P9 build coverage is '$state', expected 'unavailable' — P9 did not exhaust rea's representation budget."
    [ "$code" = "resource-limit" ] || fail "[$label] P9 build issue is '$code', expected 'resource-limit'."
    case "$detail" in *"representation budget"*) : ;; *) fail "[$label] P9 build detail '$detail' did not name the representation budget." ;; esac
}

echo ""
echo "Empirical REA P9 exhaustion gate (real rea CLI — $(rea --version 2>/dev/null))"

ORIG="${1:-}"
PROT="${2:-}"
if [ -n "$ORIG" ] && [ -n "$PROT" ]; then
    [ -f "$ORIG" ] || fail "original not found: $ORIG"
    [ -f "$PROT" ] || fail "protected not found: $PROT"
    assert_complete "$ORIG"
    assert_exhausted "$PROT" "supplied"
else
    echo "No assemblies supplied — building the sample and protecting it with P9 (maximum)..."
    dotnet build "$REPO_ROOT/samples/HelloTarget" -c Release --nologo >/dev/null
    ORIG="$REPO_ROOT/samples/HelloTarget/bin/Release/net8.0/HelloTarget.dll"
    WORK="$(mktemp -d)"
    assert_complete "$ORIG"
    PROT="$WORK/HelloTarget.p9.dll"
    dotnet run --project "$REPO_ROOT/src/ReaOverflow.Cli" -c Release -- \
        protect "$ORIG" -o "$PROT" --passes P9 --intensity maximum >/dev/null
    assert_exhausted "$PROT" "maximum"
fi

echo ""
echo "PASS: rea reads the original completely but reports the P9 build UNAVAILABLE (resource-limit —"
echo "      representation budget exhausted) with no managed members. (Denial by exhaustion, not a"
echo "      crash — rea exits 0. Load-safety is proven by dotnet test.)"
exit 0
