# ==============================================================================
# Automated Kibana Dashboard and Threat Analytics Provisioner
# Project: Centralized Log Monitoring and Threat Detection System
# ==============================================================================

param(
    [string]$KibanaUrl = "http://127.0.0.1:5601",
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
    "kbn-xsrf" = "true"
    "Authorization" = $authHeader
    "Content-Type" = "application/json"
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Provisioning SOC Threat Detection Dashboard in Kibana" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 0. Locate or Create the Data View for elk-threats-*
Write-Host "[*] Locating Data View for 'elk-threats-*'..." -ForegroundColor Yellow
$DataViewId = "a3e8f74e-f5ae-4b61-ab0a-2e733b111aca"

try {
    $existingViews = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/_find?type=index-pattern&search=elk-threats-*" -Method Get -Headers $headers
    if ($existingViews.saved_objects.Count -gt 0) {
        $matched = $existingViews.saved_objects[0]
        $DataViewId = $matched.id
        $viewName = $matched.attributes.name
        if (-not $viewName) { $viewName = $matched.attributes.title }
        Write-Host "[+] Found Existing Data View '$viewName' (ID: $DataViewId)" -ForegroundColor Green
    } else {
        Write-Host "[*] Creating new Data View 'ELK Threat Intelligence'..." -ForegroundColor Yellow
        $dvPayload = @{
            attributes = @{
                title = "elk-threats-*"
                name = "ELK Threat Intelligence"
                timeFieldName = "@timestamp"
            }
        } | ConvertTo-Json -Depth 5
        $newDv = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/index-pattern/$DataViewId?overwrite=true" -Method Post -Headers $headers -Body $dvPayload
        Write-Host "[+] Created Data View 'ELK Threat Intelligence' (ID: $DataViewId)" -ForegroundColor Green
    }
} catch {
    Write-Host "[-] Note locating data view: $_. Using ID: $DataViewId" -ForegroundColor Yellow
}

# Helper function to generate standard searchSourceJSON with both indexRefName and direct index
function New-SearchSourceJSON {
    param([string]$Query = "")
    return (@{
        query = @{
            query = $Query
            language = "kuery"
        }
        filter = @()
        indexRefName = "kibanaSavedObjectMeta.searchSourceJSON.index"
    } | ConvertTo-Json -Compress)
}

# Standard reference array for all visualizations
$dvReference = @(
    @{
        name = "kibanaSavedObjectMeta.searchSourceJSON.index"
        type = "index-pattern"
        id = $DataViewId
    }
)

# 1. Visualization: Total Failed Login Attempts Metric (Event ID 4625)
$viz1 = @{
    attributes = @{
        title = "Total Failed Login Attempts (Event ID 4625)"
        visState = '{"title":"Total Failed Login Attempts (Event ID 4625)","type":"metric","params":{"type":"metric","addTooltip":true,"addLegend":false,"dimensions":{"metrics":[{"accessor":0,"format":{"id":"number","params":{}},"type":"vis_dimension"}]},"metric":{"percentageMode":false,"useRanges":false,"colorSchema":"Green to Red","metricColorMode":"None","colorsRange":[{"from":0,"to":10000,"type":"range"}],"invertColors":false,"labels":{"show":true},"style":{"bgFill":"#000","bgColor":false,"labelColor":false,"subText":"","fontSize":60}}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{"customLabel":"Failed Logons"}}]}'
        uiStateJSON = "{}"
        description = "Counts occurrences of Windows Event ID 4625 and SSH failed authentications"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query 'event_action: "failed_logon"')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-failed-logon?overwrite=true" -Method Post -Headers $headers -Body $viz1
    Write-Host "[+] [1/7] Created/Updated Metric: Total Failed Login Attempts (Event ID 4625)" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 1: $_" -ForegroundColor Red }

# 2. Visualization: Total Successful Logins Metric (Event ID 4624)
$viz2 = @{
    attributes = @{
        title = "Total Successful Logins (Event ID 4624)"
        visState = '{"title":"Total Successful Logins (Event ID 4624)","type":"metric","params":{"type":"metric","addTooltip":true,"addLegend":false,"dimensions":{"metrics":[{"accessor":0,"format":{"id":"number","params":{}},"type":"vis_dimension"}]},"metric":{"percentageMode":false,"useRanges":false,"colorSchema":"Green to Red","metricColorMode":"None","colorsRange":[{"from":0,"to":10000,"type":"range"}],"invertColors":false,"labels":{"show":true},"style":{"bgFill":"#000","bgColor":false,"labelColor":false,"subText":"","fontSize":60}}},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{"customLabel":"Successful Logons"}}]}'
        uiStateJSON = "{}"
        description = "Counts occurrences of Windows Event ID 4624 and SSH successful logins"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query 'event_action: "successful_logon"')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-successful-logon?overwrite=true" -Method Post -Headers $headers -Body $viz2
    Write-Host "[+] [2/7] Created/Updated Metric: Total Successful Logins (Event ID 4624)" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 2: $_" -ForegroundColor Red }

# 3. Visualization: Authentication & Threats by Operating System (Windows vs Linux)
$viz3 = @{
    attributes = @{
        title = "Authentication & Threat Distribution by OS"
        visState = '{"title":"Authentication & Threat Distribution by OS","type":"pie","params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":true},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"log_source_os.keyword","size":5,"order":"desc","orderBy":"1","customLabel":"OS Platform"}}]}'
        uiStateJSON = "{}"
        description = "Monitors threats across Windows and Linux platforms"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query '')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-os-distribution?overwrite=true" -Method Post -Headers $headers -Body $viz3
    Write-Host "[+] [3/7] Created/Updated Chart: Authentication & Threats by OS" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 3: $_" -ForegroundColor Red }

# 4. Visualization: Threat Activity & Authentication Timeline
$viz4 = @{
    attributes = @{
        title = "Threat Activity & Authentication Timeline"
        visState = '{"title":"Threat Activity & Authentication Timeline","type":"histogram","params":{"type":"histogram","grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"truncate":100},"title":{"text":"Timestamp"}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"truncate":100},"title":{"text":"Events"}}],"seriesParams":[{"show":true,"type":"histogram","mode":"stacked","data":{"label":"Events","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"showCircles":true}],"addTooltip":true,"addLegend":true,"legendPosition":"right"},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"date_histogram","schema":"segment","params":{"field":"@timestamp","interval":"auto","min_doc_count":1}},{"id":"3","enabled":true,"type":"terms","schema":"group","params":{"field":"event_action.keyword","size":5,"order":"desc","orderBy":"1"}}]}'
        uiStateJSON = "{}"
        description = "Timeline of failed logins vs successful logins detecting sudden brute-force surges"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query '')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-threat-timeline?overwrite=true" -Method Post -Headers $headers -Body $viz4
    Write-Host "[+] [4/7] Created/Updated Chart: Threat Activity & Timeline" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 4: $_" -ForegroundColor Red }

# 5. Visualization: Top Targeted Accounts (Pie Chart)
$viz5 = @{
    attributes = @{
        title = "Top Targeted User Accounts"
        visState = '{"title":"Top Targeted User Accounts","type":"pie","params":{"type":"pie","addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":true},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"threat_user.keyword","size":10,"order":"desc","orderBy":"1","customLabel":"Target Account"}}]}'
        uiStateJSON = "{}"
        description = "Distribution of targeted usernames under brute-force attacks"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query 'event_action: "failed_logon"')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-targeted-users?overwrite=true" -Method Post -Headers $headers -Body $viz5
    Write-Host "[+] [5/7] Created/Updated Chart: Top Targeted User Accounts" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 5: $_" -ForegroundColor Red }

# 6. Visualization: Failure Reasons (Horizontal Bar Chart)
$viz6 = @{
    attributes = @{
        title = "Logon Failure Reasons Breakdown"
        visState = '{"title":"Logon Failure Reasons Breakdown","type":"horizontal_bar","params":{"type":"horizontal_bar","grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"left","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"rotate":0,"truncate":100},"title":{"text":"Failure Reason"}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":100},"title":{"text":"Attempt Count"}}],"seriesParams":[{"show":true,"type":"histogram","mode":"normal","data":{"label":"Attempt Count","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"showCircles":true}],"addTooltip":true,"addLegend":false},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{}},{"id":"2","enabled":true,"type":"terms","schema":"segment","params":{"field":"failure_reason.keyword","size":5,"order":"desc","orderBy":"1"}}]}'
        uiStateJSON = "{}"
        description = "Windows SubStatus error breakdown translated to human readable failure causes"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query 'event_action: "failed_logon"')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-failure-reasons?overwrite=true" -Method Post -Headers $headers -Body $viz6
    Write-Host "[+] [6/7] Created/Updated Chart: Failure Reasons Breakdown" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 6: $_" -ForegroundColor Red }

# 7. Visualization: Suspicious Login Detection (Data Table)
$viz7 = @{
    attributes = @{
        title = "Suspicious Login Detection"
        visState = '{"title":"Suspicious Login Detection","type":"table","params":{"perPage":10,"showPartialRows":false,"showMetricsAtAllLevels":false,"sort":{"columnIndex":null,"direction":null},"showTotal":false,"totalFunc":"sum"},"aggs":[{"id":"1","enabled":true,"type":"count","schema":"metric","params":{"customLabel":"Event Count"}},{"id":"2","enabled":true,"type":"terms","schema":"bucket","params":{"field":"threat_user.keyword","size":10,"order":"desc","orderBy":"1","customLabel":"Target Account"}},{"id":"3","enabled":true,"type":"terms","schema":"bucket","params":{"field":"threat_source_ip.keyword","size":10,"order":"desc","orderBy":"1","customLabel":"Source IP"}},{"id":"4","enabled":true,"type":"terms","schema":"bucket","params":{"field":"failure_reason.keyword","size":10,"order":"desc","orderBy":"1","customLabel":"Reason"}},{"id":"5","enabled":true,"type":"terms","schema":"bucket","params":{"field":"threat_severity.keyword","size":5,"order":"desc","orderBy":"1","customLabel":"Severity"}}]}'
        uiStateJSON = "{}"
        description = "Audit table of detected suspicious logins and attack signatures"
        kibanaSavedObjectMeta = @{
            searchSourceJSON = (New-SearchSourceJSON -Query 'event_action: "failed_logon"')
        }
    }
    references = $dvReference
} | ConvertTo-Json -Depth 10

try {
    $null = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/visualization/viz-suspicious-logins?overwrite=true" -Method Post -Headers $headers -Body $viz7
    Write-Host "[+] [7/7] Created/Updated Table: Suspicious Login Detection" -ForegroundColor Green
} catch { Write-Host "[-] Failed viz 7: $_" -ForegroundColor Red }

# 8. Assembled Centralized SOC Dashboard
$dashPanels = @(
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 0; y = 0; w = 12; h = 8; i = "1" }; panelIndex = "1"; panelRefName = "panel_1" },
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 12; y = 0; w = 12; h = 8; i = "2" }; panelIndex = "2"; panelRefName = "panel_2" },
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 24; y = 0; w = 24; h = 8; i = "3" }; panelIndex = "3"; panelRefName = "panel_3" },
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 0; y = 8; w = 48; h = 12; i = "4" }; panelIndex = "4"; panelRefName = "panel_4" },
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 0; y = 20; w = 24; h = 14; i = "5" }; panelIndex = "5"; panelRefName = "panel_5" },
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 24; y = 20; w = 24; h = 14; i = "6" }; panelIndex = "6"; panelRefName = "panel_6" },
    @{ version = "8.11.3"; type = "visualization"; gridData = @{ x = 0; y = 34; w = 48; h = 14; i = "7" }; panelIndex = "7"; panelRefName = "panel_7" }
) | ConvertTo-Json -Compress

$dashReferences = @(
    @{ name = "panel_1"; type = "visualization"; id = "viz-failed-logon" },
    @{ name = "panel_2"; type = "visualization"; id = "viz-successful-logon" },
    @{ name = "panel_3"; type = "visualization"; id = "viz-os-distribution" },
    @{ name = "panel_4"; type = "visualization"; id = "viz-threat-timeline" },
    @{ name = "panel_5"; type = "visualization"; id = "viz-targeted-users" },
    @{ name = "panel_6"; type = "visualization"; id = "viz-failure-reasons" },
    @{ name = "panel_7"; type = "visualization"; id = "viz-suspicious-logins" }
)

$dash = @{
    attributes = @{
        title = "[SOC] Windows Threat Detection & Centralized Security Dashboard"
        description = "Centralized SOC Dashboard monitoring Windows Event ID 4625/4624, authentication anomalies, SSH brute-force and attack analytics"
        hits = 0
        kibanaSavedObjectMeta = @{
            searchSourceJSON = '{"query":{"query":"","language":"kuery"},"filter":[]}'
        }
        optionsJSON = '{"useMargins":true,"hidePanelTitles":false}'
        panelsJSON = $dashPanels
        timeRestore = $true
        timeFrom = "now-30d"
        timeTo = "now"
    }
    references = $dashReferences
} | ConvertTo-Json -Depth 10

try {
    $rd = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/dashboard/soc-threat-dashboard?overwrite=true" -Method Post -Headers $headers -Body $dash
    Write-Host ""
    Write-Host "[+] Successfully Built SOC Dashboard: [SOC] Windows Threat Detection & Centralized Security Dashboard" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Direct Dashboard Access URL:" -ForegroundColor Cyan
    Write-Host "    $KibanaUrl/app/dashboards#/view/soc-threat-dashboard" -ForegroundColor White
} catch { Write-Host "[-] Failed dashboard: $_" -ForegroundColor Red }

Write-Host "======================================================================" -ForegroundColor Cyan
