# QWED Adversarial Testing Suite - Instructions

## 🎯 Purpose
Test Claude Sonnet 4.5 and Claude Opus 4.5 with the hardest math and logic problems to prove that QWED's verification engines catch LLM errors. Generate evidence for social media.

---

## 📁 Files Created

### Test Suites
1. **`adversarial_math_tests.py`** - 18 math tests targeting:
   - Multi-step arithmetic extraction errors
   - PEMDAS ambiguity (6/2(1+2))
   - Large number precision
   - Percentage calculation traps
   - Cognitive bias problems (bat & ball)
   - Complex nested operations
   
2. **`adversarial_logic_tests.py`** - 16 logic tests targeting:
   - Tower of Hanoi (sequence validation)
   - Knights & Knaves (truth tables)
   - River crossing puzzles
   - Constraint satisfaction
   - Boolean SAT problems
   - Graph coloring
   - Temporal logic cycles

3. **`run_all_adversarial_tests.py`** - Master runner:
   - Runs all tests
   - Generates combined report
   - Creates social media evidence

---

## 🚀 How to Run

### Prerequisites
```bash
# 1. Make sure you're in the qwed_new directory
cd c:\Users\rahul\.gemini\antigravity\playground\vector-meteoroid\qwed_new

# 2. Activate your virtual environment
qwed_env\Scripts\activate

# 3. Start the QWED API locally
uvicorn qwed_new.api.main:app --reload
# Should be running on http://localhost:8000
```

### Run Tests

**Option 1: Run All Tests (Recommended)**
```bash
cd benchmarks\deep_suite
python run_all_adversarial_tests.py
```

**Option 2: Run Individual Suites**
```bash
# Math tests only
python adversarial_math_tests.py

# Logic tests only
python adversarial_logic_tests.py
```

---

## 📊 What You'll Get

### 1. Detailed JSON Reports
- `adversarial_math_report.json` - Full math test results
- `adversarial_logic_report.json` - Full logic test results
- `master_adversarial_report_TIMESTAMP.json` - Combined results

### 2. Social Media Evidence
- `social_media_evidence_TIMESTAMP.txt` - Ready-to-share proof
  - Exact queries that tripped LLMs
  - LLM's wrong answer vs correct answer
  - QWED's detection

### Example Evidence Output:
```
🎯 Tested Advanced LLMs (Claude Sonnet 4.5 & Opus 4.5)

📊 RESULTS:
   Total Tests: 34
   LLM Errors Detected: 12

🔢 MATH ENGINE CATCHES:
   Example 1:
   Query: If a $500 item is increased by 20% then decreased by 20%, what's the final price?
   LLM Answer: $500
   Correct Answer: $480
   ✅ QWED CAUGHT THE ERROR
```

---

## 🎬 Expected Test Results

### High-Probability Catches (Based on Known LLM Weaknesses)

**Math Tests:**
- ✅ Bat & ball problem (LLMs say $0.10, answer is $0.05)
- ✅ Percentage asymmetry (+20% then -20% ≠ original)
- ✅ Extraction errors (grabbing intermediate instead of final)
- ✅ Ambiguous notation (6/2(1+2))
- ✅ Large number precision errors

**Logic Tests:**
- ✅ Tower of Hanoi illegal moves
- ✅ Knights & Knaves contradictions
- ✅ River crossing constraint violations
- ✅ SAT contradictions not detected

---

## 📱 For Social Media Posts

### What to Share:
1. **Evidence file** - Shows exact LLM mistakes
2. **Statistics** - "Tested 34 adversarial problems, caught 12 LLM errors"
3. **Screenshots** - JSON report showing QWED catching errors
4. **Narrative** - "This proves why verification is critical for AI safety"

### Message Template:
```
🧪 Tested Claude Sonnet 4.5 & Opus 4.5 with adversarial math & logic problems

📊 Results: 
- 34 hard problems
- 12 LLM errors caught by verification engines

🎯 Examples:
- Cognitive bias traps
- Ambiguous notation
- Multi-step extraction errors
- Constraint violations

This proves why AI needs verification layers for safety-critical applications.

#AIVerification #AITrust #MachineLearning
```

---

## 🔧 Customization

### Add More Tests
Edit the `ADVERSARIAL_TESTS` list in either file:

```python
{
    "id": "your_test_id",
    "query": "Your challenging query",
    "expected": 42,
    "why_hard": "Why this trips LLMs",
    "provider": "anthropic"  # or "claude_opus"
}
```

### Change Providers
In each test dict, set:
- `"provider": "anthropic"` - Claude Sonnet 4.5
- `"provider": "claude_opus"` - Claude Opus 4.5
- `"provider": "azure_openai"` - GPT-4

### Adjust Timeout
If tests are timing out:
```python
response = requests.post(..., timeout=120)  # Increase from 60
```

---

## ⚠️ Troubleshooting

**"Connection refused"**
- Make sure QWED API is running on localhost:8000
- Check: `curl http://localhost:8000/health`

**"Invalid API key"**
- The test files use the demo API key
- Update `API_KEY` variable if you changed it

**"Provider not found"**
- Make sure Claude Opus provider was deployed
- Check `config.py` has CLAUDE_OPUS configured

**Tests taking too long**
- Normal! Each LLM call takes 5-30 seconds
- Total runtime: ~30-60 minutes for all tests
- Run individual suites to save time

---

## 📈 Success Metrics

### Minimum Viable Evidence:
- ✅ At least 5 LLM errors caught
- ✅ At least 2 different error types (math + logic)
- ✅ Clear proof: LLM output vs correct answer

### Ideal Results:
- 🎯 10+ errors caught
- 🎯 Mix of Sonnet and Opus failures
- 🎯 Dramatic examples (big divergence from correct answer)

---

## 🎥 Demo Video Ideas

1. **Screen recording:**
   - Show test running
   - Highlight LLM giving wrong answer
   - Show QWED detecting error
   - Display "QWED CAUGHT ERROR" message

2. **Screenshots for Twitter:**
   - Side-by-side: LLM answer vs QWED verification
   - Final summary report
   - Evidence file highlights

---

## 🚀 Next Steps After Testing

1. **Analyze Results:**
   - Which tests caught the most errors?
   - Which provider (Sonnet vs Opus) made more mistakes?
   
2. **Create Content:**
   - Twitter thread with examples
   - LinkedIn post about verification importance
   - Blog post: "Why AI Needs Verification Layers"

3. **Improve Tests:**
   - Add more tests that caught errors
   - Create paraphrase variants
   - Test with other LLMs (GPT-4, Gemini)

---

## 📞 Support

If tests fail or you need help:
1. Check error logs in the JSON reports
2. Verify API is running: `http://localhost:8000/docs`
3. Test single query manually first
4. Review the full_response in JSON for debugging

---

**Ready to prove the world needs verification? Run the tests! 🚀**
