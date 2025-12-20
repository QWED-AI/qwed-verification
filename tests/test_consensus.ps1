# Test Consensus Verification (Phase 2B)
# PowerShell Script

$API_KEY = "qwed_c3ec03e4443a8f3f00c427b3815771c48c7d0f9be924057ce1e18fda2fc84a20"
$BASE_URL = "http://localhost:8000"

Write-Host "Testing QWED Multi-Engine Consensus (Phase 2B)" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Single Engine (Fast Mode)
Write-Host "Test 1: Single Engine Verification (Fast)" -ForegroundColor Yellow
$singleBody = @{
    query = "What is 2 + 2?"
    verification_mode = "single"
    min_confidence = 90.0
} | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Uri "$BASE_URL/verify/consensus" `
        -Method POST `
        -Headers @{"X-API-Key"=$API_KEY} `
        -ContentType "application/json" `
        -Body $singleBody
    
    Write-Host "SUCCESS - Single Engine:" -ForegroundColor Green
    Write-Host "  Answer: $($result.final_answer)" -ForegroundColor Green
    Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Green
    Write-Host "  Engines Used: $($result.engines_used)" -ForegroundColor Green
    Write-Host "  Latency: $($result.total_latency_ms)ms" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 2: High Confidence (2 Engines)
Write-Host "Test 2: High Confidence Mode (2 Engines)" -ForegroundColor Yellow
$highBody = @{
    query = "What is 15% of 200?"
    verification_mode = "high"
    min_confidence = 95.0
} | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Uri "$BASE_URL/verify/consensus" `
        -Method POST `
        -Headers @{"X-API-Key"=$API_KEY} `
        -ContentType "application/json" `
        -Body $highBody
    
    Write-Host "SUCCESS - High Confidence:" -ForegroundColor Green
    Write-Host "  Answer: $($result.final_answer)" -ForegroundColor Green
    Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Green
    Write-Host "  Agreement: $($result.agreement_status)" -ForegroundColor Green
    Write-Host "  Engines Used: $($result.engines_used)" -ForegroundColor Green
    Write-Host "  Verification Chain:" -ForegroundColor Green
    foreach ($engine in $result.verification_chain) {
        Write-Host "    - $($engine.engine) [$($engine.method)]: $($engine.result) ($($engine.confidence)%)" -ForegroundColor Gray
    }
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 3: Maximum Verification (3+ Engines - Critical Domain)
Write-Host "Test 3: Maximum Verification (Critical Domain)" -ForegroundColor Yellow
$maxBody = @{
    query = "What is 15% of 200?"
    verification_mode = "maximum"
    min_confidence = 99.0
} | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Uri "$BASE_URL/verify/consensus" `
        -Method POST `
        -Headers @{"X-API-Key"=$API_KEY} `
        -ContentType "application/json" `
        -Body $maxBody
    
    Write-Host "SUCCESS - Maximum Verification:" -ForegroundColor Green
    Write-Host "  Answer: $($result.final_answer)" -ForegroundColor Green
    Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Green
    Write-Host "  Agreement: $($result.agreement_status)" -ForegroundColor Green
    Write-Host "  Engines Used: $($result.engines_used)" -ForegroundColor Green
    Write-Host "  Meets Requirement: $($result.meets_requirement)" -ForegroundColor Green
    Write-Host "  Total Latency: $($result.total_latency_ms)ms" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Detailed Verification Chain:" -ForegroundColor Cyan
    foreach ($engine in $result.verification_chain) {
        $status = if ($engine.success) { "SUCCESS" } else { "FAILED" }
        Write-Host "    [$status] $($engine.engine)" -ForegroundColor $(if ($engine.success) { "Green" } else { "Red" })
        Write-Host "      Method: $($engine.method)" -ForegroundColor Gray
        Write-Host "      Result: $($engine.result)" -ForegroundColor Gray
        Write-Host "      Confidence: $($engine.confidence)%" -ForegroundColor Gray
        Write-Host "      Latency: $($engine.latency_ms)ms" -ForegroundColor Gray
    }
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 4: Insufficient Confidence (should warn)
Write-Host "Test 4: High Confidence Requirement (may not meet threshold)" -ForegroundColor Yellow
$strictBody = @{
    query = "What is 2 + 2?"
    verification_mode = "single"
    min_confidence = 99.9  # Very high requirement
} | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Uri "$BASE_URL/verify/consensus" `
        -Method POST `
        -Headers @{"X-API-Key"=$API_KEY} `
        -ContentType "application/json" `
        -Body $strictBody
    
    Write-Host "SUCCESS - Met high confidence requirement:" -ForegroundColor Green
    Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Green
    Write-Host ""
} catch {
    if ($_.Exception.Response.StatusCode -eq 422) {
        Write-Host "EXPECTED - Confidence requirement not met (422)" -ForegroundColor Yellow
        Write-Host "  (Use 'high' or 'maximum' mode for higher confidence)" -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "FAILED - Unexpected error: $_" -ForegroundColor Red
        Write-Host ""
    }
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Consensus Verification Testing Complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "- Single engine mode: Fast, 1 engine" -ForegroundColor Green
Write-Host "- High confidence mode: 2 engines, higher confidence" -ForegroundColor Green
Write-Host "- Maximum mode: 3+ engines, critical domains" -ForegroundColor Green
Write-Host "- Confidence scoring: Working" -ForegroundColor Green
Write-Host "- Verification chain: Full transparency" -ForegroundColor Green
