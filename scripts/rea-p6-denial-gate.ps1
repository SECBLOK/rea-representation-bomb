<#
.SYNOPSIS
  Empirical REA gate for P6 — proves the metadata constructions DENY rea's managed inventory on the
  REAL `rea` CLI, instead of trusting the model.

.DESCRIPTION
  Asserts, against the real rea CLI:
    * ORIGINAL  inspect-managed-members  -> coverage COMPLETE (rea reads the members fine).
    * PROTECTED inspect-managed-members  -> metadata MALFORMED / coverage UNAVAILABLE (0 members).
    * PROTECTED inspect-managed-artifact -> metadata MALFORMED.
  With no arguments it protects the sample with each P6 variant (dup / manystreams / badname) and
  asserts the denial for every one. This is a metadata-layer DENIAL, not a crash: rea exits 0 and
  labels the file malformed. The matching load-safety + runtime-equivalence of each P6 build is proven
  separately by `dotnet test` (GatedPassTests.P6_RawMetadata_EachVariant_*) and `reaoverflow verify`.

  MEASURED 2026-11-16 against rea@6.7.0 and rea@6.9.0 (this repo's P6 fuzz campaign). OPT-IN: not part
  of `dotnet test` — it needs Node.js + the `rea` CLI.

.EXAMPLE
  scripts\rea-p6-denial-gate.ps1                                       # tests all three variants
  scripts\rea-p6-denial-gate.ps1 -Original original.dll -Protected protected.dll   # one supplied pair
#>
param([string]$Original, [string]$Protected)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

$rea = Get-Command rea -ErrorAction SilentlyContinue
if ($null -eq $rea) { Fail "the 'rea' CLI is not on PATH. Install Node.js + rea, then re-run. This gate is opt-in and is intentionally not part of 'dotnet test'." }

function Probe($cmd, $path) {
    $json = & rea $cmd $path --format json 2>$null | Out-String
    try {
        $nr = ($json | ConvertFrom-Json).normalized_result
        $status = $nr.metadata.status; if ($null -eq $status) { $status = "none" }
        $state  = $nr.coverage.state;  if ($null -eq $state)  { $state  = "none" }
        return [PSCustomObject]@{ Status = $status; State = $state }
    } catch { return [PSCustomObject]@{ Status = "parsefail"; State = "none" } }
}

function Assert-Complete($path) {
    $m = Probe "inspect-managed-members" $path
    Write-Host ("  original  members : status={0} coverage={1}   {2}" -f $m.Status, $m.State, (Split-Path $path -Leaf))
    if ($m.State -ne "complete") { Fail "original members coverage is '$($m.State)', expected 'complete' - rea should read the unprotected sample fully." }
}

function Assert-Denied($path, $label) {
    $m = Probe "inspect-managed-members"  $path
    $a = Probe "inspect-managed-artifact" $path
    Write-Host ("  P6[{0,-11}] members: status={1} coverage={2} | artifact: status={3}" -f $label, $m.Status, $m.State, $a.Status)
    if ($m.Status -ne "malformed") { Fail "[$label] protected members status is '$($m.Status)', expected 'malformed' - P6 did not deny rea." }
    if ($a.Status -ne "malformed") { Fail "[$label] protected artifact status is '$($a.Status)', expected 'malformed' - P6 did not deny rea." }
}

Write-Host ""
Write-Host "Empirical REA P6 denial gate (real rea CLI - $(& rea --version 2>$null))"

if ((-not [string]::IsNullOrEmpty($Original)) -and (-not [string]::IsNullOrEmpty($Protected))) {
    if (-not (Test-Path $Original))  { Fail "original not found: $Original" }
    if (-not (Test-Path $Protected)) { Fail "protected not found: $Protected" }
    Assert-Complete $Original
    Assert-Denied $Protected "supplied"
} else {
    Write-Host "No assemblies supplied - building the sample and testing all P6 variants (dup, manystreams, badname)..."
    dotnet build "$repoRoot/samples/HelloTarget" -c Release --nologo | Out-Null
    $Original = "$repoRoot/samples/HelloTarget/bin/Release/net8.0/HelloTarget.dll"
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("reap6_" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $work | Out-Null
    Assert-Complete $Original
    foreach ($variant in @("dup", "manystreams", "badname")) {
        $prot = Join-Path $work "HelloTarget.p6.$variant.dll"
        dotnet run --project "$repoRoot/src/ReaOverflow.Cli" -c Release -- protect "$Original" -o "$prot" --passes P6 --p6-variant $variant | Out-Null
        Assert-Denied $prot $variant
    }
}

Write-Host ""
Write-Host "PASS: rea reads the original completely but reports every P6 build MALFORMED with no managed"
Write-Host "      members. (Denial, not a crash - rea exits 0. Load-safety is proven by dotnet test.)"
exit 0
