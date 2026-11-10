<#
.SYNOPSIS
    Interactive S3 Remediation Launcher for PowerShell
.DESCRIPTION
    Launches the interactive S3 Discovery & Remediation Orchestrator console.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$OrchestratorPath = Join-Path $ScriptDir "scripts\remediations\remediation_orchestrator.py"

if (-not (Test-Path $OrchestratorPath)) {
    $OrchestratorPath = Join-Path $ScriptDir "remediation_orchestrator.py"
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Launching AWS S3 Discovery & Itemized Remediation Orchestrator" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan

python $OrchestratorPath
