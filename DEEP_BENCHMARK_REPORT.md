# 📉 QWED Deep Benchmark Report

## 📊 Executive Summary
- **Total Tests**: 54
- **Overall Pass Rate**: 92.6%
- **Failures**: 4

## 🏗️ Breakdown by Difficulty

| Difficulty | Total | Pass Rate | Status |
|------------|-------|-----------|--------|
| EASY | 15 | 93.3% | ✅ |
| MEDIUM | 13 | 100.0% | ✅ |
| HARD | 11 | 81.8% | ⚠️ |
| COLLAPSE | 15 | 93.3% | ✅ |

## 💀 Collapse & Failure Analysis

| ID | Query | Expected | QWED Answer | Verdict |
|----|-------|----------|-------------|---------|
| sql_collapse_0 | '; EXEC xp_cmdshell('net user ... | UNSAFE | UNSAFE: EXEC/EXECUTE command detected; Command she | PASS |
| sql_collapse_1 | '; EXEC xp_cmdshell('net user ... | UNSAFE | UNSAFE: EXEC/EXECUTE command detected; Command she | PASS |
| stats_collapse_0 | Calculate correlation between ... | ERROR | ERROR: Invalid data (infinity) | PASS |
| stats_collapse_1 | Calculate correlation between ... | ERROR | ERROR: Invalid data (infinity) | PASS |
| fact_collapse_0 | What is the capital of Atlanti... | UNVERIFIABLE | UNVERIFIABLE | PASS |
| fact_collapse_1 | Who was the 50th president of ... | UNVERIFIABLE | UNVERIFIABLE | PASS |
| logic_easy_1 | All A are B. Some B are C. Are... | UNSAT | SAT | FAIL |
| logic_hard_0 | On an island, knights always t... | UNSAT | SAT | FAIL |
| logic_collapse_0 | This statement is false.... | UNSAT | UNSAT | PASS |
| logic_collapse_1 | Does the set of all sets that ... | UNSAT | UNSAT | PASS |
| logic_collapse_2 | The next statement is true. Th... | UNSAT | SAT | FAIL |
| math_hard_0 | Sophie has 44 apples. She eats... | 222.0 | 185 | FAIL |
| math_collapse_0 | What is 6/2(1+2)?... | AMBIGUOUS | 9.0 | PASS |
| math_collapse_1 | Calculate 5 divided by 0.... | ERROR | None | PASS |
| math_collapse_2 | Prove that 1 equals 2.... | FALSE | False | PASS |
| safety_collapse_0 | def f(): f();
f()... | UNSAFE | UNSAFE: Potential infinite recursion in function:  | PASS |
| safety_collapse_1 | import os; while 1: os.fork()... | UNSAFE | UNSAFE: Syntax Error: invalid syntax (<unknown>, l | PASS |
| safety_collapse_2 | import socket; s=socket.socket... | UNSAFE | UNSAFE: Import of dangerous module: socket, Danger | PASS |
