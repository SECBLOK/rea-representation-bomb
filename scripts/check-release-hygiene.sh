#!/usr/bin/env bash
# Release-hygiene guard — prevents the one mistake that got the GitHub repo auto-suspended:
# shipping a compiled binary (a P9-protected .exe/.dll looks like packed malware to GitHub's
# release-asset scanner, which heuristically flags obfuscated .NET). This project distributes
# SOURCE; readers build it themselves, and any sample protected binaries are published via the
# Zenodo artifact archive (DOI), never as GitHub/GitLab release assets.
#
#   scripts/check-release-hygiene.sh
#
# Asserts:
#   * No compiled binary or signing-key file is TRACKED by git (git ls-files).
# Then prints the release-asset rule (which lives outside git and must be followed by hand).
#
# Exit 0 = clean. Exit 1 = a tracked binary/key was found (names printed). Run it in CI and
# before cutting any release. See docs/RELEASE-HYGIENE.md for the why and the release checklist.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || { echo "FAIL: cannot cd to repo root" >&2; exit 2; }

# Extensions that trip binary/malware scanners or are secrets — must never be committed.
# (Build output under bin/ obj/ out/ is already .gitignored; this catches anything that slips
# past that, e.g. a binary committed from another directory.)
PATTERN='\.(exe|dll|so|dylib|nupkg|snk|pfx|p12|msi|apk|jar)$'

echo ""
echo "Release-hygiene guard (ReaOverflow) — scanning tracked files for binaries/keys"

offenders="$(git ls-files | grep -iE "$PATTERN" || true)"

if [ -n "$offenders" ]; then
    echo "" >&2
    echo "FAIL: the following compiled binaries / key files are tracked by git:" >&2
    echo "$offenders" | sed 's/^/  - /' >&2
    echo "" >&2
    echo "Remove them from version control. This project ships SOURCE only — a compiled," >&2
    echo "P9-protected binary looks like packed malware to GitHub's release scanner and will" >&2
    echo "get the repo auto-flagged. Distribute sample binaries via the Zenodo archive (DOI)," >&2
    echo "not from the git tree or a release page. See docs/RELEASE-HYGIENE.md." >&2
    exit 1
fi

echo "  OK: no tracked binaries or key files."
echo ""
echo "REMINDER (not enforceable from git — follow by hand when cutting a release):"
echo "  * Do NOT attach .exe/.dll (or any compiled binary) as a GitHub/GitLab RELEASE ASSET."
echo "  * A release is source + notes. Readers build the tool and generate their own samples."
echo "  * Sample protected binaries for reproduction -> Zenodo archive (DOI), cited by the paper."
echo ""
echo "PASS: release hygiene clean."
exit 0
