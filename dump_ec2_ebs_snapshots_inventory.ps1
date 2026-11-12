<#
.SYNOPSIS
    AWS Multi-Organization EC2, EBS Volumes & Snapshots Lineage Auditor Runner

.DESCRIPTION
    Scans EC2 instances, EBS volumes, and EBS Snapshots across multiple AWS
    Organizations (rus-ext, rus-ioc, cccs) or the active PowerShell AWS session.
    Snapshot is central to this report, mapping source volumes and originating EC2s,
    and isolating orphaned/unattached storage waste.

.PARAMETER Profiles
    List of AWS CLI profiles to audit (default: rus-ext, rus-ioc, cccs).

.PARAMETER CurrentSession
    Switch to audit the currently authenticated AWS session in PowerShell directly.

.PARAMETER Role
    Custom IAM role name to assume in member accounts.

.PARAMETER StaleDays
    Age threshold in days to flag snapshots as stale (default: 180).

.PARAMETER OpenPortal
    Automatically launch the interactive HTML dashboard portal in your default browser upon completion.

.PARAMETER OpenCsv
    Automatically open the Snapshot-Centric CSV report in Microsoft Excel upon completion.

.EXAMPLE
    .\dump_ec2_ebs_snapshots_inventory.ps1 -OpenPortal

.EXAMPLE
    .\dump_ec2_ebs_snapshots_inventory.ps1 -CurrentSession -OpenPortal

.EXAMPLE
    .\dump_ec2_ebs_snapshots_inventory.ps1 -Profiles rus-ext cccs -OpenCsv
#>

[CmdletBinding()]
param(
    [string[]]$Profiles = @("rus-ext", "rus-ioc", "cccs"),
    [switch]$CurrentSession,
    [string]$Role = $env:ROLE_NAME,
    [int]$StaleDays = 180,
    [string]$InputJson = "",
    [switch]$OpenPortal,
    [switch]$OpenCsv
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PyScript = Join-Path $ScriptDir "dump_ec2_ebs_snapshots_inventory.py"

if (-not (Test-Path $PyScript)) {
    Write-Error "Could not find python script at: $PyScript"
    exit 1
}

# Resolve Python executable
$PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = (Get-Command py.exe -ErrorAction SilentlyContinue).Source
}
if (-not $PythonExe) {
    Write-Error "python.exe not found in PATH. Please install Python 3.8+ or add it to PATH."
    exit 1
}

$Arguments = @($PyScript)

if ($InputJson -and (Test-Path $InputJson)) {
    $Arguments += @("--input-json", $InputJson)
} elseif ($CurrentSession) {
    $Arguments += @("--current-session")
} else {
    $Arguments += @("--profiles")
    $Arguments += $Profiles
}

if ($Role) {
    $Arguments += @("--role", $Role)
}

if ($StaleDays) {
    $Arguments += @("--stale-snapshot-days", $StaleDays)
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  Launching AWS EC2, EBS Volumes & Snapshots Lineage Auditor" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  Python:  $PythonExe" -ForegroundColor Gray
Write-Host "  Script:  $PyScript" -ForegroundColor Gray
if ($CurrentSession) {
    Write-Host "  Mode:    CURRENT Active PowerShell AWS Session" -ForegroundColor Yellow
} elseif ($InputJson) {
    Write-Host "  Mode:    OFFLINE from JSON ($InputJson)" -ForegroundColor Yellow
} else {
    Write-Host "  Targets: $($Profiles -join ', ')" -ForegroundColor Yellow
}
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

& $PythonExe @Arguments

$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    $PortalHtml = Join-Path $ScriptDir "ec2_ebs_snapshots_inventory_portal.html"
    $SnapshotCsv = Join-Path $ScriptDir "snapshots_all_organizations_inventory.csv"
    $WasteCsv = Join-Path $ScriptDir "orphaned_ebs_and_snapshots_waste.csv"

    if ($OpenPortal -and (Test-Path $PortalHtml)) {
        Write-Host "`n[+] Opening Interactive Portal in browser..." -ForegroundColor Green
        Start-Process $PortalHtml
    }

    if ($OpenCsv -and (Test-Path $SnapshotCsv)) {
        Write-Host "`n[+] Opening Snapshot Inventory CSV in Excel..." -ForegroundColor Green
        Start-Process $SnapshotCsv
    }
} else {
    Write-Host "`n[-] Auditor finished with exit code $ExitCode" -ForegroundColor Red
}

exit $ExitCode
