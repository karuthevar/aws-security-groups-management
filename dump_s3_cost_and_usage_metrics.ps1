<#
.SYNOPSIS
    Dumps Live S3 Storage, Object Counts, and Cost Metrics across AWS Organizations.
.DESCRIPTION
    Directly queries CloudWatch GetMetricData in batch and S3 to pull:
      - BucketSizeBytes (Standard Storage, etc.)
      - NumberOfObjects (Total object count)
      - DaysSinceLastWrite / NewestObjectModified
      - EstimatedMonthlyCostUSD ($/mo)
      - PotentialMonthlySavingsUSD ($/mo)
      - FinOps Cost Status
.PARAMETER CurrentSession
    Audits currently authenticated PowerShell session.
.PARAMETER Profiles
    List of profiles (defaults to rus-ext rus-ioc cccs).
.PARAMETER OpenCsv
    Automatically opens the generated CSV in Excel upon completion.
#>

[CmdletBinding()]
param(
    [switch]$CurrentSession,
    [string[]]$Profiles = @("rus-ext", "rus-ioc", "cccs"),
    [string]$OutputCsv = "s3_live_cost_and_usage_metrics.csv",
    [switch]$OpenCsv
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PyScript = Join-Path $ScriptDir "dump_s3_cost_and_usage_metrics.py"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Starting AWS S3 Live Storage, Object Counts & Cost Metrics Auditor" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan

$pyArgs = @($PyScript, "--output-csv", $OutputCsv)

if ($CurrentSession) {
    Write-Host "[*] Auditing CURRENT authenticated PowerShell session directly..." -ForegroundColor Yellow
    $pyArgs += "--current-session"
} else {
    Write-Host "[*] Auditing target profiles: $($Profiles -join ', ')..." -ForegroundColor Yellow
    $pyArgs += "--profiles"
    $pyArgs += $Profiles
}

& python $pyArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[SUCCESS] S3 Cost & Usage Metrics Audit completed successfully!" -ForegroundColor Green
    if ($OpenCsv -and (Test-Path $OutputCsv)) {
        Write-Host "[*] Opening $OutputCsv in Microsoft Excel..." -ForegroundColor Cyan
        Invoke-Item $OutputCsv
    }
} else {
    Write-Host "`n[ERROR] Audit encountered an issue (Exit Code: $LASTEXITCODE)." -ForegroundColor Red
}
