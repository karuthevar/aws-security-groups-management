# ==============================================================================
# AWS Security & Compliance Executive Portal Launcher (PowerShell)
# Run from PowerShell: .\launch_portal.ps1
# ==============================================================================

$portalPath = Join-Path $PSScriptRoot "portal\index.html"
Write-Host "Launching AWS Security & Compliance Executive Portal: $portalPath" -ForegroundColor Cyan
Start-Process $portalPath
