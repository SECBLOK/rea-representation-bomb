<#
.SYNOPSIS
  Empirical REA gate - measures the REAL analysis-cost tax ReaOverflow imposes on the real `rea`
  CLI, instead of trusting the optimistic ReaModel.

.DESCRIPTION
  Runs `rea inspect-managed-members <path> --token-count` on an original and a protected assembly
  and asserts the protected/original token RATIO is at least -MinRatio (default 1.15x). This is the
  ground-truth counterpart to `reaoverflow analyze` (which is MODELLED and over-predicts - it claims
  `crossesBudget:true` for assemblies REA decodes completely). A passing gate proves a real,
  measured cost tax; it does NOT claim budget exhaustion (in testing REA decoded both sides fully).

  OPT-IN: this is not part of `dotnet test`, because it needs Node.js + the `rea` npm CLI
  (https://github.com/morluto/rea), which are not on CI by default. Install rea, then run this.

  With no -Original/-Protected, the script builds the sample + CLI and protects the sample with
  P2,P3,P4,P5 --intensity maximum, so it is runnable from a clean checkout once `rea` is installed.

.EXAMPLE
  pwsh scripts/rea-token-gate.ps1
  pwsh scripts/rea-token-gate.ps1 -Original app.dll -Protected app.protected.dll -MinRatio 1.2
#>
[CmdletBinding()]
param(
    [string]$Original,
    [string]$Protected,
    [double]$MinRatio = 1.15
)
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Fail($msg, $code = 1) { Write-Host "FAIL: $msg" -ForegroundColor Red; exit $code }

# --- tooling check (opt-in dependency) ---
if (-not (Get-Command rea -ErrorAction SilentlyContinue)) {
    Fail "the 'rea' CLI is not on PATH. Install Node.js + rea (https://github.com/morluto/rea), then re-run. This gate is opt-in and is intentionally not part of 'dotnet test'." 2
}

# --- build + protect the sample if no pair was supplied ---
if (-not $Original -or -not $Protected) {
    Write-Host "No assemblies supplied - building sample + CLI and protecting with P2,P3,P4,P5..." -ForegroundColor Cyan
    & dotnet build "$RepoRoot/samples/HelloTarget" -c Release --nologo | Out-Null
    $Original = Join-Path $RepoRoot 'samples/HelloTarget/bin/Release/net8.0/HelloTarget.dll'
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("reaoverflow-gate-" + [System.Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $Protected = Join-Path $work 'HelloTarget.protected.dll'
    & dotnet run --project "$RepoRoot/src/ReaOverflow.Cli" -c Release -- `
        protect $Original -o $Protected --passes P2,P3,P4,P5 --intensity maximum | Out-Null
}

if (-not (Test-Path $Original))  { Fail "original not found: $Original" }
if (-not (Test-Path $Protected)) { Fail "protected not found: $Protected" }

function Get-ReaTokens($path) {
    # `--token-count` prints the token count of the full representation; a clean exit means REA
    # decoded the assembly completely (no crash, no refusal).
    $out = & rea inspect-managed-members $path --token-count 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "rea failed on $path (exit $LASTEXITCODE): $out" }
    $n = ($out | Select-String -Pattern '^\s*\d+\s*$' | Select-Object -Last 1).ToString().Trim()
    if (-not $n) { $n = ($out | Where-Object { $_ -match '\d' } | Select-Object -Last 1) -replace '[^\d]','' }
    if (-not $n) { Fail "could not parse a token count from rea output for $path. Raw: $out" }
    return [int]$n
}

Write-Host "`nEmpirical REA gate (real rea CLI - $(rea --version 2>$null))" -ForegroundColor Cyan
$origTok = Get-ReaTokens $Original
$protTok = Get-ReaTokens $Protected
$ratio = [math]::Round($protTok / $origTok, 3)

Write-Host ("  original : {0,10:N0} tokens   {1}" -f $origTok, (Split-Path -Leaf $Original))
Write-Host ("  protected: {0,10:N0} tokens   {1}" -f $protTok, (Split-Path -Leaf $Protected))
Write-Host ("  ratio    : {0}x   (threshold >= {1}x)" -f $ratio, $MinRatio)
Write-Host "  note: both sides decoded COMPLETELY (rea exited 0) - this is a measured cost tax, not budget exhaustion."

if ($ratio -ge $MinRatio) {
    Write-Host "`nPASS: protected representation is ${ratio}x the original (>= $MinRatio)." -ForegroundColor Green
    exit 0
} else {
    Fail "protected representation is only ${ratio}x the original (< $MinRatio) - protection did not impose the expected measured tax."
}

