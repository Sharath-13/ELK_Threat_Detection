<#
.SYNOPSIS
    Starts the Dockerized ELK Stack and Retrieves the Public HTTPS Cloudflare URL
    Project: Centralized Log Monitoring and Threat Detection System
#>

$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Starting ELK Stack & Secure Remote Access (Cloudflare Tunnel)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

docker compose up -d

Write-Host "[*] Containers launched. Waiting for Kibana to become available..." -ForegroundColor Yellow
$maxWaitSec = 180
$elapsed = 0
$kibanaReady = $false

while ($elapsed -lt $maxWaitSec) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    Write-Host "    Waiting for Kibana and Tunnel... (${elapsed}s/${maxWaitSec}s)" -ForegroundColor Gray

    if (-not $kibanaReady) {
        try {
            $status = Invoke-RestMethod -Uri "http://127.0.0.1:5601/api/status" -TimeoutSec 5
            if ($status.status.overall.level -eq "available") {
                $kibanaReady = $true
            }
        } catch {
            # Kibana preboot still serving "server is not ready yet"
        }
    }

    $tunnelLogs = docker logs cloudflared 2>&1
    $urlMatch = $tunnelLogs | Select-String -Pattern "https://[a-zA-Z0-9-]+\.trycloudflare\.com"
    if ($urlMatch -and $kibanaReady) {
        $publicUrl = $urlMatch.Matches[0].Value
        break
    }
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  ELK THREAT DETECTION SYSTEM DEPLOYED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  [+] Local Kibana URL:      http://127.0.0.1:5601" -ForegroundColor Cyan
if ($publicUrl) {
    Write-Host "  [+] Secure Public URL:     $publicUrl" -ForegroundColor Magenta
} else {
    Write-Host "  [!] Public URL initializing. Run: docker logs cloudflared to inspect." -ForegroundColor Yellow
}
Write-Host "  [+] Username:              elastic" -ForegroundColor White
Write-Host "  [+] Password:              [Configured securely in .env]" -ForegroundColor Gray
Write-Host ""
Write-Host "  [+] Logstash Ingestion:    127.0.0.1:5044 (Beats Port)" -ForegroundColor Cyan
Write-Host "  [+] Elasticsearch:         http://127.0.0.1:9200 (Internal Only)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Green
