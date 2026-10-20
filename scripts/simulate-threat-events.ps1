<#
.SYNOPSIS
    Safe Threat Detection Event Generator for SOC Evaluation & Demonstration
    Project: Centralized Log Monitoring and Threat Detection System using ELK Stack

.DESCRIPTION
    Generates safe, controlled authentication events for both Windows (Event ID 4625)
    and Linux (SSH Brute Force) directly indexed into Elasticsearch / Logstash for
    instant verification on the Kibana SOC Dashboard.
    ALL events are explicitly tagged as SIMULATED to preserve audit integrity.
#>

param(
    [Parameter(Mandatory=$false)]
    [int]$Count = 5,

    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Windows", "Linux")]
    [string]$Platform = "All",

    [Parameter(Mandatory=$false)]
    [string]$EsUrl = "http://127.0.0.1:9200",

    [Parameter(Mandatory=$false)]
    [string]$User = "elastic"
)

# Load password dynamically from .env
$envFilePath = Join-Path (Split-Path -Parent $PSScriptRoot) ".env"
$Pass = ""
if (Test-Path $envFilePath) {
    $envMatch = Get-Content $envFilePath | Select-String -Pattern "^ELASTIC_PASSWORD=(.+)$"
    if ($envMatch) {
        $Pass = $envMatch.Matches[0].Groups[1].Value.Trim()
    }
}

$authHeader = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
$headers = @{
    "Authorization" = $authHeader
    "Content-Type"  = "application/json"
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  ELK Threat Detection: Safe Threat Event Generator (Viva Demo)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[*] Target Cluster:  $EsUrl" -ForegroundColor Yellow
Write-Host "[*] Platform Scope:  $Platform" -ForegroundColor Yellow
Write-Host "[*] Event Batch:     $Count simulated events per scenario" -ForegroundColor Yellow
Write-Host "[*] Safety Tag:      SIMULATED TEST - NO REAL ATTACK" -ForegroundColor Green
Write-Host ""

$todayIndex = "elk-threats-" + (Get-Date).ToUniversalTime().ToString("yyyy.MM.dd")
$targets = @("admin", "root", "database_admin", "devops_service", "backup_operator", "finance_user")
$ips = @("192.168.1.150", "192.168.1.188", "10.0.0.45", "172.16.0.22", "192.168.1.200")
$reasons = @(
    "Bad Password / Invalid Credentials",
    "User Account Does Not Exist",
    "Account Currently Locked Out",
    "Account Disabled"
)

$generatedCount = 0

# 1. Windows Event ID 4625 Simulation
if ($Platform -eq "All" -or $Platform -eq "Windows") {
    Write-Host "[*] Generating Windows Event ID 4625 (Failed Logon / Brute Force)..." -ForegroundColor Cyan
    for ($i = 0; $i -lt $Count; $i++) {
        $user = $targets[$i % $targets.Count]
        $srcIp = $ips[$i % $ips.Count]
        $reason = $reasons[$i % $reasons.Count]
        $isoTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        $doc = @{
            "@timestamp"       = $isoTime
            "log_source_os"    = "Windows"
            "event_action"     = "failed_logon"
            "event_category"   = "authentication"
            "threat_detected"  = "Failed Login / Potential Brute Force"
            "threat_severity"  = "HIGH"
            "threat_user"      = $user
            "threat_source_ip" = $srcIp
            "failure_reason"   = $reason
            "logon_type"       = "3"
            "is_simulated"     = $true
            "simulation_label" = "Evaluation Safe Demo Event"
            "winlog" = @{
                "event_id"   = 4625
                "channel"    = "Security"
                "event_data" = @{
                    "TargetUserName" = $user
                    "IpAddress"      = $srcIp
                    "SubStatus"      = "0xC000006A"
                    "LogonType"      = "3"
                }
            }
        } | ConvertTo-Json -Depth 6

        try {
            $null = Invoke-RestMethod -Uri "$EsUrl/$todayIndex/_doc" -Method Post -Headers $headers -Body $doc
            Write-Host "    [+] Windows 4625: User '$user' from $srcIp (Reason: $reason)" -ForegroundColor Gray
            $generatedCount++
        } catch {
            Write-Host "    [-] Failed to index Windows event: $_" -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 200
    }
}

# 2. Linux SSH Authentication Failure Simulation
if ($Platform -eq "All" -or $Platform -eq "Linux") {
    Write-Host "[*] Generating Linux SSH Brute Force Events (Failed password)..." -ForegroundColor Cyan
    for ($i = 0; $i -lt $Count; $i++) {
        $user = $targets[($i + 2) % $targets.Count]
        $srcIp = $ips[($i + 1) % $ips.Count]
        $port = 40000 + $i * 123
        $isoTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        $doc = @{
            "@timestamp"       = $isoTime
            "log_source_os"    = "Linux"
            "event_action"     = "failed_logon"
            "event_category"   = "authentication"
            "threat_detected"  = "SSH Brute Force Attack"
            "threat_severity"  = "HIGH"
            "threat_user"      = $user
            "threat_source_ip" = $srcIp
            "threat_port"      = [string]$port
            "failure_reason"   = "Invalid SSH Password / Key"
            "is_simulated"     = $true
            "simulation_label" = "Evaluation Safe Demo Event"
            "message"          = "Failed password for invalid user $user from $srcIp port $port ssh2"
        } | ConvertTo-Json -Depth 5

        try {
            $null = Invoke-RestMethod -Uri "$EsUrl/$todayIndex/_doc" -Method Post -Headers $headers -Body $doc
            Write-Host "    [+] Linux SSH: User '$user' from ${srcIp}:${port}" -ForegroundColor Gray
            $generatedCount++
        } catch {
            Write-Host "    [-] Failed to index Linux event: $_" -ForegroundColor Red
        }
        Start-Sleep -Milliseconds 200
    }
}

# 3. Successful Logon Event (Baseline Comparison)
Write-Host "[*] Generating Baseline Successful Authentication (Event ID 4624)..." -ForegroundColor Cyan
$docSuccess = @{
    "@timestamp"       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "log_source_os"    = "Windows"
    "event_action"     = "successful_logon"
    "event_category"   = "authentication"
    "threat_severity"  = "LOW"
    "threat_user"      = "authorized_admin"
    "threat_source_ip" = "127.0.0.1 (Local Console)"
    "is_simulated"     = $true
    "simulation_label" = "Evaluation Safe Demo Event"
    "winlog" = @{
        "event_id"   = 4624
        "channel"    = "Security"
        "event_data" = @{
            "TargetUserName" = "authorized_admin"
            "IpAddress"      = "127.0.0.1"
        }
    }
} | ConvertTo-Json -Depth 5
$null = Invoke-RestMethod -Uri "$EsUrl/$todayIndex/_doc" -Method Post -Headers $headers -Body $docSuccess
$generatedCount++
Write-Host "    [+] Windows 4624: Authorized logon for 'authorized_admin'" -ForegroundColor Gray

# Refresh index so events are instantly queryable in Kibana
try {
    $null = Invoke-RestMethod -Uri "$EsUrl/$todayIndex/_refresh" -Method Post -Headers $headers
} catch {}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  SIMULATION COMPLETED: $generatedCount events indexed successfully!" -ForegroundColor Green
Write-Host "  Index: $todayIndex" -ForegroundColor Green
Write-Host ""
Write-Host "  Verify on Kibana Dashboard:" -ForegroundColor Cyan
Write-Host "  http://127.0.0.1:5601/app/dashboards#/view/soc-threat-dashboard" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Green
