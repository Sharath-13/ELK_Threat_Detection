$headers = @{
    "kbn-xsrf" = "true"
    
    "Authorization" = ("Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:$env:ELASTIC_PASSWORD")))

    "Content-Type" = "application/json"
}

$payload = @{
    objects = @(
        @{ type = "dashboard"; id = "soc-threat-dashboard" }
    )
    includeReferencesDeep = $true
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://127.0.0.1:5601/api/saved_objects/_export" -Method Post -Headers $headers -Body $payload -TimeoutSec 15
$outPath = Join-Path $PSScriptRoot "threat_detection_dashboard.ndjson"
[IO.File]::WriteAllText($outPath, $response)
Write-Host "Export completed successfully to $outPath. Length: $($response.Length)"
