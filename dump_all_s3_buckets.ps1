<#
.SYNOPSIS
    AWS Multi-Organization S3 Bucket Audit & Inventory Runner for PowerShell.
    Audits S3 buckets, encryption, settings, tags, and security posture across
    all 3 AWS Organizations (rus-ext, rus-ioc / rus-iot, cccs) or the active session.

.DESCRIPTION
    Runs the comprehensive S3 multi-organization audit engine directly from your
    PowerShell terminal. Discovers all member accounts, traverses cross-account IAM roles
    (AWSControlTowerExecution, OrganizationAccountAccessRole), and dumps all S3 bucket
    metadata, encryption settings, public access blocks, TLS enforcement, versioning,
    lifecycle policies, and tags into Excel-ready CSV and JSON files.

.PARAMETER Profiles
    List of AWS CLI profiles to audit. Defaults to @('rus-ext', 'rus-ioc', 'cccs').
    Supports aliases 'rus-iot' and 'rci-cccs'.

.PARAMETER CurrentSession
    Switch to audit whatever AWS Organization or Account your current PowerShell session
    is already authenticated to (via environment variables, active aws login, or SSO).

.PARAMETER Role
    Custom cross-account IAM role to assume in member accounts.
    Defaults to auto-detecting AWSControlTowerExecution and OrganizationAccountAccessRole.

.PARAMETER OutputCsv
    Path for the consolidated CSV export. Default: s3_all_organizations_inventory.csv

.PARAMETER OutputJson
    Path for the complete JSON export. Default: s3_all_organizations_inventory.json

.PARAMETER Workers
    Number of concurrent worker threads for account scanning. Default: 8

.PARAMETER BucketWorkers
    Number of concurrent threads per account for bucket inspection. Default: 5

.PARAMETER OpenCsv
    Switch to automatically launch the generated CSV in Excel upon completion.

.EXAMPLE
    # Scan all 3 Organizations with default profiles:
    .\dump_all_s3_buckets.ps1

.EXAMPLE
    # Scan using your currently authenticated PowerShell session:
    .\dump_all_s3_buckets.ps1 -CurrentSession

.EXAMPLE
    # Scan specific organizations and auto-open CSV in Excel:
    .\dump_all_s3_buckets.ps1 -Profiles "rus-ext", "cccs" -OpenCsv

.EXAMPLE
    # Specify custom output path:
    .\dump_all_s3_buckets.ps1 -OutputCsv "C:\audits\s3_audit_2026.csv"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$Profiles = @("rus-ext", "rus-ioc", "cccs"),

    [Parameter(Mandatory = $false)]
    [switch]$CurrentSession,

    [Parameter(Mandatory = $false)]
    [string]$Role = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputCsv = "s3_all_organizations_inventory.csv",

    [Parameter(Mandatory = $false)]
    [string]$OutputJson = "s3_all_organizations_inventory.json",

    [Parameter(Mandatory = $false)]
    [int]$Workers = 8,

    [Parameter(Mandatory = $false)]
    [int]$BucketWorkers = 5,

    [Parameter(Mandatory = $false)]
    [switch]$OpenCsv
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "dump_all_s3_buckets.py"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  AWS Multi-Organization S3 Bucket Audit & Inventory Tool (PowerShell)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Verify Python
$PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = (Get-Command python3.exe -ErrorAction SilentlyContinue).Source
}

if (-not $PythonExe) {
    Write-Error "Python 3 is required but was not found in your PATH. Please install Python 3.8+."
    exit 1
}

# Verify Boto3
$Boto3Check = & $PythonExe -c "import boto3; print(boto3.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "boto3 is not installed for $PythonExe. Attempting to install..."
    & $PythonExe -m pip install --quiet boto3
}

# Build arguments array
$ArgsList = @($PythonScript)

if ($CurrentSession) {
    $ArgsList += "--current-session"
    Write-Host "[MODE] Auditing Currently Authenticated AWS Session in PowerShell" -ForegroundColor Yellow
} else {
    $ArgsList += "--profiles"
    $ArgsList += $Profiles
    Write-Host "[MODE] Target Organization Profiles: $($Profiles -join ', ')" -ForegroundColor Yellow
}

if ($Role) {
    $ArgsList += "--role"
    $ArgsList += $Role
    Write-Host "[ROLE] Custom Assume Role: $Role" -ForegroundColor Yellow
}

$ArgsList += "--output-csv"
$ArgsList += $OutputCsv

$ArgsList += "--output-json"
$ArgsList += $OutputJson

$ArgsList += "--workers"
$ArgsList += $Workers

$ArgsList += "--bucket-workers"
$ArgsList += $BucketWorkers

Write-Host "[OUTPUT] CSV:  $OutputCsv" -ForegroundColor Gray
Write-Host "[OUTPUT] JSON: $OutputJson" -ForegroundColor Gray
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Gray

# Execute Python engine
& $PythonExe $ArgsList
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    Write-Host "`n[SUCCESS] S3 audit completed successfully!" -ForegroundColor Green
    
    if (Test-Path $OutputCsv) {
        $Item = Get-Item $OutputCsv
        Write-Host "  - CSV File: $($Item.FullName) ($([math]::Round($Item.Length / 1KB, 1)) KB)" -ForegroundColor Green
    }
    if (Test-Path $OutputJson) {
        $Item = Get-Item $OutputJson
        Write-Host "  - JSON File: $($Item.FullName) ($([math]::Round($Item.Length / 1KB, 1)) KB)" -ForegroundColor Green
    }

    if ($OpenCsv -and (Test-Path $OutputCsv)) {
        Write-Host "`nLaunching CSV in default viewer (Excel)..." -ForegroundColor Cyan
        Invoke-Item $OutputCsv
    }
} else {
    Write-Host "`n[ERROR] Audit script encountered an issue (Exit Code: $ExitCode)." -ForegroundColor Red
}

exit $ExitCode
