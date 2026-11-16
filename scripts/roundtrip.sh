#!/usr/bin/env bash
# Runtime-equivalence + plaintext-leak harness.
#   scripts/roundtrip.sh [passes] [intensity]
# Builds nothing; assumes CLI (Debug) and sample (Release) are already built.
set -uo pipefail
PASSES="${1:-}"
INTENSITY="${2:-maximum}"
ROOT="/m/Projects/ReaOverflow"
SRC="$ROOT/samples/HelloTarget/bin/Release/net8.0"
CLI="$ROOT/src/ReaOverflow.Cli/bin/Debug/net8.0/ReaOverflow.Cli.dll"
PROT="/e/claude-tmp/claude/c6d31f68f497b93f/fba70164-7372-4659-9b7e-a8c845a9f71c/scratchpad/protected"

rm -rf "$PROT"; mkdir -p "$PROT"; cp -r "$SRC"/* "$PROT/"
dotnet "$SRC/HelloTarget.dll" > /tmp/base.txt 2>&1

ARGS=(protect "$PROT/HelloTarget.dll" -o "$PROT/HelloTarget.dll" --intensity "$INTENSITY")
[ -n "$PASSES" ] && ARGS+=(--passes "$PASSES")
dotnet "$CLI" "${ARGS[@]}"
RC=$?
echo "(protect exit=$RC)"

dotnet "$PROT/HelloTarget.dll" > /tmp/prot.txt 2>&1
echo "--- protected output ---"; cat /tmp/prot.txt
echo "--- equivalence ---"
if diff /tmp/base.txt /tmp/prot.txt >/dev/null; then echo "RUNTIME-EQUIVALENT ✓"; else echo "DIVERGED ✗"; diff /tmp/base.txt /tmp/prot.txt; fi
echo "--- plaintext leak check (UTF-16 aware) ---"
if tr -d '\000' < "$PROT/HelloTarget.dll" | grep -a -q "api-token-9F3A"; then echo "PLAINTEXT PRESENT ✗"; else echo "PLAINTEXT ABSENT ✓"; fi
SIZE_SRC=$(stat -c%s "$SRC/HelloTarget.dll"); SIZE_PROT=$(stat -c%s "$PROT/HelloTarget.dll")
echo "--- size: $SIZE_SRC -> $SIZE_PROT bytes ---"
