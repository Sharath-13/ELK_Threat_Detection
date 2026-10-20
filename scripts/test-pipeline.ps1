<#
.SYNOPSIS
    End-to-End Pipeline Health & Ingestion Verification Script
    Project: Centralized Log Monitoring and Threat Detection System
#>

param(
    [string]$EsUrl = "http://127.0.0.1:9200",
    [string]$EsUser = "elastic",
    [string]$EsPass = ""
)

# Load password dynamically from .env if not explicitly passed
if ([string]::IsNullOrWhiteSpace($EsPass)) {
    $envFilePath = Join-Path (Split-Path -Parent $PSScriptRoot) ".env"
    if (Test-Path $envFilePath) {
        $envMatch = Get-Content $envFilePath | Select-String -Pattern "^ELASTIC_PASSWORD=(.+)$"
        if ($envMatch) {
            $EsPass = $envMatch.Matches[0].Groups[1].Value.Trim()
        }
    }
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  ELK Stack Threat Pipeline Validation & Ingestion Test" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$credPair = "${EsUser}:${EsPass}"
$encodedCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($credPair))
$headers = @{ Authorization = "Basic $encodedCreds" }

# 1. Test Elasticsearch Connectivity & Cluster Health
Write-Host "[1/4] Checking Elasticsearch Health at $EsUrl..." -NoNewline
try {
    $health = Invoke-RestMethod -Uri "$EsUrl/_cluster/health" -Headers $headers -TimeoutSec 10
    Write-Host " [ONLINE] (Status: $($health.status))" -ForegroundColor Green
} catch {
    Write-Host " [FAILED] Could not connect to Elasticsearch: $_" -ForegroundColor Red
    exit 1
}

# 2. Test Kibana Status
Write-Host "[2/4] Checking Kibana Status at http://127.0.0.1:5601..." -NoNewline
try {
    $kib = Invoke-WebRequest -Uri "http://127.0.0.1:5601/api/status" -TimeoutSec 10 -UseBasicParsing
    if ($kib.StatusCode -eq 200 -or $kib.StatusCode -eq 302) {
        Write-Host " [ONLINE] (HTTP $($kib.StatusCode))" -ForegroundColor Green
    }
} catch {
    Write-Host " [WARNING] Kibana still initializing or starting..." -ForegroundColor Yellow
}

# 3. Test Logstash Beats Port 5044
Write-Host "[3/4] Checking Logstash Ingestion Port 5044..." -NoNewline
$tcpTest = Test-NetConnection -ComputerName "127.0.0.1" -Port 5044 -WarningAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-Host " [LISTENING] (Port 5044 Ready for Beats)" -ForegroundColor Green
} else {
    Write-Host " [PENDING] Port 5044 not reachable yet." -ForegroundColor Yellow
}

# 4. Check Ingested Security Logs in Elasticsearch
Write-Host "[4/4] Querying 'elk-threats-*' indices for detected threats..." -ForegroundColor Cyan
try {
    $indices = Invoke-RestMethod -Uri "$EsUrl/_cat/indices/elk-threats-*?format=json" -Headers $headers -TimeoutSec 10
    if ($indices.Count -gt 0) {
        Write-Host "[+] Found $($indices.Count) threat indices active!" -ForegroundColor Green
        
        # Query failed logons (Event ID 4625)
        $searchBody = @{
            query = @{
                match = @{
                    "event_action" = "failed_logon"
                }
            }
            size = 5
            sort = @( @{ "@timestamp" = "desc" } )
        } | ConvertTo-Json -Depth 5

        $searchResult = Invoke-RestMethod -Uri "$EsUrl/elk-threats-*/_search" -Method Post -Headers $headers -Body $searchBody -ContentType "application/json"
        $totalFailed = $searchResult.hits.total.value
        Write-Host "[+] Total Failed Logons Indexed: $totalFailed" -ForegroundColor Yellow
        
        if ($totalFailed -gt 0) {
            Write-Host "[+] Recent Detected Threats:" -ForegroundColor Green
            foreach ($hit in $searchResult.hits.hits) {
                $src = $hit._source
                Write-Host "    - [$($src.'@timestamp')] User: $($src.threat_user) | Source IP: $($src.threat_source_ip) | Severity: $($src.threat_severity) | Reason: $($src.failure_reason)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "[i] No 'elk-threats-*' indices created yet. Run simulate_threats.ps1 to generate events." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[i] No security logs indexed yet. (Index will be auto-created upon first log event)." -ForegroundColor Yellow
}

Write-Host "======================================================================" -ForegroundColor Cyan
