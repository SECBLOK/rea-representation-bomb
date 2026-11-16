<#
Release-hygiene guard — prevents the one mistake that got the GitHub repo auto-suspended:
shipping a compiled binary (a P9-protected .exe/.dll looks like packed malware to GitHub's
release-asset scanner, which heuristically flags obfuscated .NET). This project distributes
SOURCE; readers build it themselves, and any sample protected binaries are published via the
Zenodo artifact archive (DOI), never as GitHub/GitLab release assets.

    pwsh scripts/check-release-hygiene.ps1   (or: powershell -File scripts\check-release-hygiene.ps1)

Asserts no compiled binary or signing-key file is TRACKED by git, then prints the release-asset
rule (which lives outside git and must be followed by hand). Exit 0 = clean, 1 = offender found.
See docs/RELEASE-HYGIENE.md for the why and the release checklist.
#>
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# Extensions that trip binary/malware scanners or are secrets — must never be committed.
$pattern = '\.(exe|dll|so|dylib|nupkg|snk|pfx|p12|msi|apk|jar)$'

Write-Host ""
Write-Host "Release-hygiene guard (ReaOverflow) — scanning tracked files for binaries/keys"

$tracked = git ls-files
$offenders = $tracked | Where-Object { $_ -imatch $pattern }

if ($offenders) {
    Write-Host ""
    Write-Host "FAIL: the following compiled binaries / key files are tracked by git:"
    $offenders | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""
    Write-Host "Remove them from version control. This project ships SOURCE only — a compiled,"
    Write-Host "P9-protected binary looks like packed malware to GitHub's release scanner and will"
    Write-Host "get the repo auto-flagged. Distribute sample binaries via the Zenodo archive (DOI),"
    Write-Host "not from the git tree or a release page. See docs/RELEASE-HYGIENE.md."
    exit 1
}

Write-Host "  OK: no tracked binaries or key files."
Write-Host ""
Write-Host "REMINDER (not enforceable from git — follow by hand when cutting a release):"
Write-Host "  * Do NOT attach .exe/.dll (or any compiled binary) as a GitHub/GitLab RELEASE ASSET."
Write-Host "  * A release is source + notes. Readers build the tool and generate their own samples."
Write-Host "  * Sample protected binaries for reproduction -> Zenodo archive (DOI), cited by the paper."
Write-Host ""
Write-Host "PASS: release hygiene clean."
exit 0
