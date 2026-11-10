<#
.SYNOPSIS
    Enforce TLS 1.2+ HTTPS-Only Policy on Empty S3 Buckets.
.DESCRIPTION
    Safely merges "DenyInsecureTransport" statement into bucket policy on empty buckets
    (0 bytes, 0 objects) while leaving all other bucket properties untouched.
.PARAMETER Execute
    Apply changes live to AWS. By default runs in safe Dry-Run preview mode.
.PARAMETER CurrentSession
    Audits the currently authenticated PowerShell AWS session.
.PARAMETER Profile
    Target specific profile (rus-ext, rus-ioc, cccs).
.PARAMETER Bucket
    Specific bucket name to remediate.
.PARAMETER AccountId
    Account ID for specific bucket.
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$CurrentSession,
    [string]$Profile,
    [string]$Bucket,
    [string]$AccountId,
    [string]$Rollback
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PyScript = Join-Path $ScriptDir "enforce_tls_empty_buckets.py"

$pyArgs = @($PyScript)

if ($Execute) {
    Write-Host "[!] LIVE EXECUTION REQUESTED: Applying policy changes to AWS..." -ForegroundColor Yellow
    $pyArgs += "--execute"
} else {
    Write-Host "[*] DRY-RUN MODE: Simulating policy merges (Safe preview, no changes made)..." -ForegroundColor Cyan
}

if ($CurrentSession) {
    $pyArgs += "--current-session"
}

if ($Profile) {
    $pyArgs += "--profile"
    $pyArgs += $Profile
}

if ($Bucket -and $AccountId) {
    $pyArgs += "--bucket"
    $pyArgs += $Bucket
    $pyArgs += "--account-id"
    $pyArgs += $AccountId
}

if ($Rollback) {
    $pyArgs += "--rollback"
    $pyArgs += $Rollback
}

& python $pyArgs
