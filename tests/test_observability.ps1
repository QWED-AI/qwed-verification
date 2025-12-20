# Test QWED Observability Endpoints
# PowerShell Script

$API_KEY = "qwed_359997473e4d21e2f1e3ba77c74b2fb3d4fb629907f1fe6aa80fabeae05f6c74"
$BASE_URL = "http://localhost:8000"

Write-Host "Testing QWED Observability Dashboard" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Health Check (No Auth)
Write-Host "Test 1: Health Check (No Auth Required)" -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BASE_URL/health"
    Write-Host "SUCCESS - Status: $($health.status)" -ForegroundColor Green
    Write-Host "  Service: $($health.service)" -ForegroundColor Green
    Write-Host "  Version: $($health.version)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Generate some requests first
Write-Host "Generating test requests..." -ForegroundColor Yellow
for ($i=1; $i -le 5; $i++) {
    $body = @{query = "What is $i + $i?"} | ConvertTo-Json
    try {
        $response = Invoke-RestMethod -Uri "$BASE_URL/verify/natural_language" `
            -Method POST `
            -Headers @{"X-API-Key"=$API_KEY} `
            -ContentType "application/json" `
            -Body $body
        Write-Host "  Request $i completed" -ForegroundColor Gray
    } catch {
        Write-Host "  Request $i failed" -ForegroundColor Gray
    }
}
Write-Host ""

# Test 2: Global Metrics
Write-Host "Test 2: Global Metrics (No Auth)" -ForegroundColor Yellow
try {
    $metrics = Invoke-RestMethod -Uri "$BASE_URL/metrics"
    Write-Host "SUCCESS - Global Metrics:" -ForegroundColor Green
    Write-Host "  Total Requests: $($metrics.global.total_requests)" -ForegroundColor Green
    Write-Host "  Active Orgs: $($metrics.global.active_organizations)" -ForegroundColor Green
    Write-Host "  Uptime: $([math]::Round($metrics.global.uptime_seconds, 2))s" -ForegroundColor Green
    Write-Host "  RPS: $($metrics.global.requests_per_second)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 3: Tenant-Specific Metrics
Write-Host "Test 3: Tenant-Specific Metrics (Requires Auth)" -ForegroundColor Yellow
try {
    $tenant_metrics = Invoke-RestMethod -Uri "$BASE_URL/metrics/1" `
        -Headers @{"X-API-Key"=$API_KEY}
    Write-Host "SUCCESS - Tenant Metrics:" -ForegroundColor Green
    Write-Host "  Org ID: $($tenant_metrics.organization_id)" -ForegroundColor Green
    Write-Host "  Total Requests: $($tenant_metrics.total_requests)" -ForegroundColor Green
    Write-Host "  Success Rate: $($tenant_metrics.success_rate)%" -ForegroundColor Green
    Write-Host "  Avg Latency: $($tenant_metrics.avg_latency_ms)ms" -ForegroundColor Green
    Write-Host "  Providers: $($tenant_metrics.provider_usage | ConvertTo-Json -Compress)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 4: Logs (Scoped to Tenant)
Write-Host "Test 4: Tenant Logs (Scoped)" -ForegroundColor Yellow
try {
    $logs = Invoke-RestMethod -Uri "$BASE_URL/logs?limit=3" `
        -Headers @{"X-API-Key"=$API_KEY}
    Write-Host "SUCCESS - Tenant Logs:" -ForegroundColor Green
    Write-Host "  Organization: $($logs.organization_name)" -ForegroundColor Green
    Write-Host "  Total Logs: $($logs.total_logs)" -ForegroundColor Green
    Write-Host "  Recent Queries:" -ForegroundColor Green
    foreach ($log in $logs.logs) {
        Write-Host "    - $($log.query) [$($log.domain)] (Verified: $($log.is_verified))" -ForegroundColor Gray
    }
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 5: Unauthorized Access (should fail)
Write-Host "Test 5: Unauthorized Access to Other Org (should fail)" -ForegroundColor Yellow
try {
    $unauthorized = Invoke-RestMethod -Uri "$BASE_URL/metrics/999" `
        -Headers @{"X-API-Key"=$API_KEY}
    Write-Host "FAILED - Should have been blocked!" -ForegroundColor Red
    Write-Host ""
} catch {
    if ($_.Exception.Response.StatusCode -eq 403) {
        Write-Host "SUCCESS - Correctly blocked (403 Forbidden)" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "FAILED - Blocked with: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
    }
}

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Observability Testing Complete!" -ForegroundColor Cyan
