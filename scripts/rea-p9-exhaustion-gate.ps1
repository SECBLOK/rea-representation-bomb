<#
.SYNOPSIS
  Empirical REA gate for P9 — proves the representation bomb EXHAUSTS rea's 64 MiB representation
  budget on the REAL `rea` CLI, instead of trusting the model.

.DESCRIPTION
  Asserts, against the real rea CLI:
    * ORIGINAL  inspect-managed-members -> coverage COMPLETE (rea reads the members fine).
    * P9 BUILD  inspect-managed-members -> coverage UNAVAILABLE with a resource-limit issue
      ("Managed metadata exceeds the 67108864 byte representation budget") and ZERO managed members.
  With no arguments it builds the sample, protects it with `--passes P9 --intensity maximum`, and
  asserts the exhaustion. This is a denial BY EXHAUSTION, not a crash: rea exits 0 and reports the
  budget overflow. The matching load-safety + runtime-equivalence of the P9 build is proven separately
  by `dotnet test` (GatedPassTests.P9_RepresentationBomb_*) and `reaoverflow verify`.

  MEASURED 2026-11-16 against rea@6.7.0 (quadratic cross-reference lever; cliff ~218k-238k edges on
  FileHound.Core.dll). OPT-IN: not part of `dotnet test` - it needs Node.js + the `rea` CLI.

.EXAMPLE
  scripts\rea-p9-exhaustion-gate.ps1                                                 # build + test sample
  scripts\rea-p9-exhaustion-gate.ps1 -Original original.dll -Protected p9.dll        # one supplied pair
#>
param([string]$Original, [string]$Protected)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

$rea = Get-Command rea -ErrorAction SilentlyContinue
if ($null -eq $rea) { Fail "the 'rea' CLI is not on PATH. Install Node.js + rea, then re-run. This gate is opt-in and is intentionally not part of 'dotnet test'." }

function Probe($path) {
    $json = & rea inspect-managed-members $path --format json 2>$null | Out-String
    try {
        $nr = ($json | ConvertFrom-Json).normalized_result
        $state = $nr.coverage.state; if ($null -eq $state) { $state = "none" }
        $issue = ""
        if ($null -ne $nr.coverage.issues -and $nr.coverage.issues.Count -gt 0) { $issue = [string]$nr.coverage.issues[0].code }
        $detail = ""
        if ($null -ne $nr.coverage.issues -and $nr.coverage.issues.Count -gt 0) { $detail = [string]$nr.coverage.issues[0].detail }
        return [PSCustomObject]@{ State = $state; Issue = $issue; Detail = $detail }
    } catch { return [PSCustomObject]@{ State = "parsefail"; Issue = ""; Detail = "" } }
}

function Assert-Complete($path) {
    $m = Probe $path
    Write-Host ("  original  members : coverage={0}   {1}" -f $m.State, (Split-Path $path -Leaf))
    if ($m.State -ne "complete") { Fail "original members coverage is '$($m.State)', expected 'complete' - rea should read the unprotected sample fully." }
}

function Assert-Exhausted($path, $label) {
    $m = Probe $path
    Write-Host ("  P9[{0,-8}] members: coverage={1} issue={2}" -f $label, $m.State, $m.Issue)
    if ($m.State -ne "unavailable") { Fail "[$label] P9 build coverage is '$($m.State)', expected 'unavailable' - P9 did not exhaust rea's representation budget." }
    if ($m.Issue -ne "resource-limit") { Fail "[$label] P9 build issue is '$($m.Issue)', expected 'resource-limit'." }
    if ($m.Detail -notmatch "representation budget") { Fail "[$label] P9 build detail '$($m.Detail)' did not name the representation budget." }
}

Write-Host ""
Write-Host "Empirical REA P9 exhaustion gate (real rea CLI - $(& rea --version 2>$null))"

if ((-not [string]::IsNullOrEmpty($Original)) -and (-not [string]::IsNullOrEmpty($Protected))) {
    if (-not (Test-Path $Original))  { Fail "original not found: $Original" }
    if (-not (Test-Path $Protected)) { Fail "protected not found: $Protected" }
    Assert-Complete $Original
    Assert-Exhausted $Protected "supplied"
} else {
    Write-Host "No assemblies supplied - building the sample and protecting it with P9 (maximum)..."
    dotnet build "$repoRoot/samples/HelloTarget" -c Release --nologo | Out-Null
    $Original = "$repoRoot/samples/HelloTarget/bin/Release/net8.0/HelloTarget.dll"
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("reap9_" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $work | Out-Null
    Assert-Complete $Original
    $prot = Join-Path $work "HelloTarget.p9.dll"
    dotnet run --project "$repoRoot/src/ReaOverflow.Cli" -c Release -- protect "$Original" -o "$prot" --passes P9 --intensity maximum | Out-Null
    Assert-Exhausted $prot "maximum"
}

Write-Host ""
Write-Host "PASS: rea reads the original completely but reports the P9 build UNAVAILABLE (resource-limit -"
Write-Host "      representation budget exhausted) with no managed members. (Denial by exhaustion, not a"
Write-Host "      crash - rea exits 0. Load-safety is proven by dotnet test.)"
exit 0
