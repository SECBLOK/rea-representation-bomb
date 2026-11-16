#!/usr/bin/env bash
# Empirical REA gate for P6 — proves the metadata constructions DENY rea's managed inventory on the
# REAL `rea` CLI, instead of trusting the model.
#
#   scripts/rea-p6-denial-gate.sh                          # builds the sample, tests ALL THREE variants
#   scripts/rea-p6-denial-gate.sh original.dll protected.dll   # tests one supplied pair
#
# Asserts, against the real rea CLI:
#   * ORIGINAL  inspect-managed-members  -> coverage COMPLETE (rea reads the members fine).
#   * PROTECTED inspect-managed-members  -> metadata MALFORMED / coverage UNAVAILABLE (0 members).
#   * PROTECTED inspect-managed-artifact -> metadata MALFORMED.
# With no arguments it protects the sample with each P6 variant (dup / manystreams / badname) and
# asserts the denial for every one. This is a metadata-layer DENIAL, not a crash: rea exits 0 and
# labels the file malformed. The matching load-safety + runtime-equivalence of each P6 build is proven
# separately by `dotnet test` (GatedPassTests.P6_RawMetadata_EachVariant_*) and `reaoverflow verify`.
#
# MEASURED 2026-11-16 against rea@6.7.0 and rea@6.9.0 (this repo's P6 fuzz campaign). OPT-IN: not part
# of `dotnet test` — it needs Node.js + the `rea` CLI, which are not on CI by default.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
fail() { echo "FAIL: $1" >&2; exit "${2:-1}"; }

command -v rea >/dev/null 2>&1 || fail "the 'rea' CLI is not on PATH. Install Node.js + rea, then re-run. This gate is opt-in and is intentionally not part of 'dotnet test'." 2

# Extract normalized_result.{metadata.status, coverage.state} from rea JSON with node. Prints "<status> <state>".
probe() {
    rea "$1" "$2" --format json 2>/dev/null | node -e '
        let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
          try{const nr=JSON.parse(s).normalized_result||{};
            console.log((nr.metadata&&nr.metadata.status)||"none",(nr.coverage&&nr.coverage.state)||"none");}
          catch(e){console.log("parsefail none");}});'
}

assert_complete() {
    local status state; read -r status state < <(probe inspect-managed-members "$1")
    printf "  original  members : status=%s coverage=%s   %s\n" "$status" "$state" "$(basename "$1")"
    [ "$state" = "complete" ] || fail "original members coverage is '$state', expected 'complete' — rea should read the unprotected sample fully."
}

assert_denied() {
    local path="$1" label="$2" ms mstate as astate
    read -r ms mstate < <(probe inspect-managed-members "$path")
    read -r as astate < <(probe inspect-managed-artifact "$path")
    printf "  P6[%-11s] members: status=%s coverage=%s | artifact: status=%s\n" "$label" "$ms" "$mstate" "$as"
    [ "$ms" = "malformed" ] || fail "[$label] protected members status is '$ms', expected 'malformed' — P6 did not deny rea."
    [ "$as" = "malformed" ] || fail "[$label] protected artifact status is '$as', expected 'malformed' — P6 did not deny rea."
}

echo ""
echo "Empirical REA P6 denial gate (real rea CLI — $(rea --version 2>/dev/null))"

ORIG="${1:-}"
PROT="${2:-}"
if [ -n "$ORIG" ] && [ -n "$PROT" ]; then
    # Single supplied pair.
    [ -f "$ORIG" ] || fail "original not found: $ORIG"
    [ -f "$PROT" ] || fail "protected not found: $PROT"
    assert_complete "$ORIG"
    assert_denied "$PROT" "supplied"
else
    # Build the sample + CLI and test all three variants.
    echo "No assemblies supplied — building the sample and testing all P6 variants (dup, manystreams, badname)..."
    dotnet build "$REPO_ROOT/samples/HelloTarget" -c Release --nologo >/dev/null
    ORIG="$REPO_ROOT/samples/HelloTarget/bin/Release/net8.0/HelloTarget.dll"
    WORK="$(mktemp -d)"
    assert_complete "$ORIG"
    for variant in dup manystreams badname; do
        PROT="$WORK/HelloTarget.p6.$variant.dll"
        dotnet run --project "$REPO_ROOT/src/ReaOverflow.Cli" -c Release -- \
            protect "$ORIG" -o "$PROT" --passes P6 --p6-variant "$variant" >/dev/null
        assert_denied "$PROT" "$variant"
    done
fi

echo ""
echo "PASS: rea reads the original completely but reports every P6 build MALFORMED with no managed"
echo "      members. (Denial, not a crash — rea exits 0. Load-safety is proven by dotnet test.)"
exit 0
