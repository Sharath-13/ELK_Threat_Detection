<#
.SYNOPSIS
    Gracefully stops the ELK Stack to free system memory (RAM)
    Project: Centralized Log Monitoring and Threat Detection System
#>

$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Stopping ELK Stack & Freeing Memory" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

docker compose down

Write-Host "[+] All containers stopped successfully. Memory released to Windows host." -ForegroundColor Green
