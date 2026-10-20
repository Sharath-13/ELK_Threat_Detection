<#
.SYNOPSIS
    Secure Credential Rotation Script
    Project: Centralized Log Monitoring and Threat Detection System

.DESCRIPTION
    Safely changes the Elastic Stack credentials for 'elastic' and 'kibana_system'
    without displaying plaintext credentials in terminal commands or output.
    Updates the local .env file and restarts dependent services cleanly.
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$GenerateRandom,

    [Parameter(Mandatory=$false)]
    [System.Security.SecureString]$NewSecurePassword
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$EnvPath = Join-Path $ProjectDir ".env"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Secure Password Rotation: Elastic Stack" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Read Current Password from .env privately in memory
if (-not (Test-Path $EnvPath)) {
    Write-Host "[-] .env file not found at $EnvPath" -ForegroundColor Red
    exit 1
}

$oldPassMatch = Get-Content $EnvPath | Select-String -Pattern "^ELASTIC_PASSWORD=(.+)$"
if (-not $oldPassMatch) {
    Write-Host "[-] Current ELASTIC_PASSWORD could not be located in .env" -ForegroundColor Red
    exit 1
}
$oldPassword = $oldPassMatch.Matches[0].Groups[1].Value.Trim()

# 2. Determine New Password
$newPlainPassword = ""
if ($GenerateRandom) {
    # Generate 24-char cryptographically secure password
    $bytes = New-Object byte[] 18
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $newPlainPassword = [Convert]::ToBase64String($bytes) + "!9A"
    Write-Host "[*] Generated a cryptographically strong 24-character replacement password." -ForegroundColor Yellow
} elseif ($NewSecurePassword) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewSecurePassword)
    $newPlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
} else {
    $sec = Read-Host -Prompt "Enter New Secure Password" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    $newPlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if ([string]::IsNullOrWhiteSpace($newPlainPassword) -or $newPlainPassword.Length -lt 8) {
    Write-Host "[-] Password must be at least 8 characters long." -ForegroundColor Red
    exit 1
}

# 3. Call Elasticsearch API using old credentials to rotate 'elastic' and 'kibana_system'
Write-Host "[*] Updating credentials in Elasticsearch cluster..." -ForegroundColor Yellow
$oldAuth = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:${oldPassword}"))
$headersOld = @{
    "Authorization" = $oldAuth
    "Content-Type"  = "application/json"
}

# Update kibana_system
$kibanaBody = @{ password = $newPlainPassword } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:9200/_security/user/kibana_system/_password" -Method Post -Headers $headersOld -Body $kibanaBody | Out-Null

# Update elastic superuser
$elasticBody = @{ password = $newPlainPassword } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:9200/_security/user/elastic/_password" -Method Post -Headers $headersOld -Body $elasticBody | Out-Null

Write-Host "[+] Cluster credentials updated successfully." -ForegroundColor Green

# 4. Update .env File without logging secrets
Write-Host "[*] Updating local configuration in .env..." -ForegroundColor Yellow
$envContent = Get-Content $EnvPath
$envContent = $envContent -replace "^ELASTIC_PASSWORD=.*$", "ELASTIC_PASSWORD=$newPlainPassword"
$envContent = $envContent -replace "^KIBANA_PASSWORD=.*$", "KIBANA_PASSWORD=$newPlainPassword"
$envContent = $envContent -replace "^LOGSTASH_INTERNAL_PASSWORD=.*$", "LOGSTASH_INTERNAL_PASSWORD=$newPlainPassword"
Set-Content -Path $EnvPath -Value $envContent -Force
Write-Host "[+] .env updated with new credentials." -ForegroundColor Green

# 5. Restart Kibana and Logstash to adopt new credentials
Write-Host "[*] Restarting Kibana and Logstash to apply updated credentials..." -ForegroundColor Yellow
Set-Location $ProjectDir
docker compose restart kibana logstash | Out-Null

# Clear in-memory variables
$newPlainPassword = $null
$oldPassword = $null
[GC]::Collect()

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  CREDENTIAL ROTATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "  - Elasticsearch credentials updated" -ForegroundColor Green
Write-Host "  - Kibana and Logstash restarted" -ForegroundColor Green
Write-Host "  - New credentials stored securely in .env (Not displayed on screen)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
