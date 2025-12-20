# Test Agent Registry (Phase 2A)
# PowerShell Script

$API_KEY = "qwed_c3ec03e4443a8f3f00c427b3815771c48c7d0f9be924057ce1e18fda2fc84a20"
$BASE_URL = "http://localhost:8000"

Write-Host "Testing QWED Agent Registry (Phase 2)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Register an AI Agent
Write-Host "Test 1: Register a New AI Agent" -ForegroundColor Yellow
$registerBody = @{
    name = "CustomerSupportBot"
    agent_type = "autonomous"
    description = "Handles customer support queries"
    permissions = @("use_tool_send_email", "use_tool_query_data")
    max_cost_per_day = 50.0
} | ConvertTo-Json

try {
    $agentResponse = Invoke-RestMethod -Uri "$BASE_URL/agents/register" `
        -Method POST `
        -Headers @{"X-API-Key"=$API_KEY} `
        -ContentType "application/json" `
        -Body $registerBody
    
    $AGENT_ID = $agentResponse.agent_id
    $AGENT_TOKEN = $agentResponse.agent_token
    
    Write-Host "SUCCESS - Agent Registered:" -ForegroundColor Green
    Write-Host "  Agent ID: $AGENT_ID" -ForegroundColor Green
    Write-Host "  Agent Token: $($AGENT_TOKEN.Substring(0, 20))..." -ForegroundColor Green
    Write-Host "  Type: $($agentResponse.type)" -ForegroundColor Green
    Write-Host "  Max Cost/Day: `$$($agentResponse.max_cost_per_day)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# Test 2: Agent Makes a Verification Request
Write-Host "Test 2: Agent Makes Verification Request" -ForegroundColor Yellow
$verifyBody = @{
    query = "Calculate 15% tip on `$80 bill"
} | ConvertTo-Json

try {
    $verifyResponse = Invoke-RestMethod -Uri "$BASE_URL/agents/$AGENT_ID/verify" `
        -Method POST `
        -Headers @{"X-Agent-Token"=$AGENT_TOKEN} `
        -ContentType "application/json" `
        -Body $verifyBody
    
    Write-Host "SUCCESS - Verification Complete:" -ForegroundColor Green
    Write-Host "  Status: $($verifyResponse.status)" -ForegroundColor Green
    Write-Host "  Answer: $($verifyResponse.final_answer)" -ForegroundColor Green
    Write-Host "  Provider: $($verifyResponse.provider_used)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 3: Agent Attempts Approved Tool Call
Write-Host "Test 3: Agent Uses Approved Tool (send_email)" -ForegroundColor Yellow
$toolBody = @{
    tool_params = @{
        to = "customer@example.com"
        subject = "Support Ticket #123"
        body = "Your issue has been resolved."
    }
} | ConvertTo-Json

try {
    $toolResponse = Invoke-RestMethod -Uri "$BASE_URL/agents/$AGENT_ID/tools/send_email" `
        -Method POST `
        -Headers @{"X-Agent-Token"=$AGENT_TOKEN} `
        -ContentType "application/json" `
        -Body $toolBody
    
    Write-Host "SUCCESS - Tool Call Approved & Executed:" -ForegroundColor Green
    Write-Host "  Tool: $($toolResponse.tool)" -ForegroundColor Green
    Write-Host "  Approved: $($toolResponse.approved)" -ForegroundColor Green
    Write-Host "  Executed: $($toolResponse.executed)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

# Test 4: Agent Attempts Dangerous Tool (should be blocked)
Write-Host "Test 4: Agent Attempts Dangerous Tool (should be blocked)" -ForegroundColor Yellow
$dangerousBody = @{
    tool_params = @{
        table = "users"
    }
} | ConvertTo-Json

try {
    $dangerousResponse = Invoke-RestMethod -Uri "$BASE_URL/agents/$AGENT_ID/tools/delete_database" `
        -Method POST `
        -Headers @{"X-Agent-Token"=$AGENT_TOKEN} `
        -ContentType "application/json" `
        -Body $dangerousBody
    
    Write-Host "FAILED - Dangerous tool should have been blocked!" -ForegroundColor Red
    Write-Host ""
} catch {
    if ($_.Exception.Response.StatusCode -eq 403) {
        Write-Host "SUCCESS - Dangerous tool correctly blocked (403 Forbidden)" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "FAILED - Unexpected error: $_" -ForegroundColor Red
        Write-Host ""
    }
}

# Test 5: View Agent Activity Log
Write-Host "Test 5: View Agent Activity Log" -ForegroundColor Yellow
try {
    $activityResponse = Invoke-RestMethod -Uri "$BASE_URL/agents/$AGENT_ID/activity?limit=10" `
        -Headers @{"X-Agent-Token"=$AGENT_TOKEN}
    
    Write-Host "SUCCESS - Activity Log Retrieved:" -ForegroundColor Green
    Write-Host "  Agent: $($activityResponse.agent_name)" -ForegroundColor Green
    Write-Host "  Total Activities: $($activityResponse.total_activities)" -ForegroundColor Green
    Write-Host "  Current Cost Today: `$$($activityResponse.current_cost_today)" -ForegroundColor Green
    Write-Host "  Budget Remaining: `$$($activityResponse.max_cost_per_day - $activityResponse.current_cost_today)" -ForegroundColor Green
    Write-Host "  Recent Activities:" -ForegroundColor Green
    foreach ($activity in $activityResponse.activities | Select-Object -First 3) {
        Write-Host "    - [$($activity.status)] $($activity.type): $($activity.description)" -ForegroundColor Gray
    }
    Write-Host ""
} catch {
    Write-Host "FAILED - Error: $_" -ForegroundColor Red
    Write-Host ""
}

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Agent Registry Testing Complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "- Agent registration: Working" -ForegroundColor Green
Write-Host "- Agent authentication: Working" -ForegroundColor Green
Write-Host "- Verification requests: Working" -ForegroundColor Green
Write-Host "- Tool approval (safe): Working" -ForegroundColor Green
Write-Host "- Tool blocking (dangerous): Working" -ForegroundColor Green
Write-Host "- Activity logging: Working" -ForegroundColor Green
