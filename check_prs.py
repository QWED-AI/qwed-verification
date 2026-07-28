import json, sys, subprocess, os

os.chdir(r"C:\Users\rahul\.gemini\antigravity\playground\vector-meteoroid\qwed-a2a")

result = subprocess.run(
    ["gh", "pr", "list", "--json", "number,title,headRefName,baseRefName,state,statusCheckRollup,reviews", "--limit", "20"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)
for pr in data:
    checks = pr.get("statusCheckRollup") or []
    conclusions = [c.get("conclusion","PENDING") for c in checks if c.get("context")]
    all_ok = all(c in ("SUCCESS","NEUTRAL","SKIPPED") for c in conclusions)
    status = "PASS" if all_ok else "FAIL"
    n = pr["number"]
    print(f"#{n:2d} ({pr['state']:5s}) checks={len(conclusions)} {status}")
    for c in (checks or []):
        ctx = c.get("context") or c.get("workflowName","?")
        conc = c.get("conclusion","PENDING")
        if conc not in ("SUCCESS","NEUTRAL","SKIPPED"):
            print(f"      ! [{ctx}] {conc}")
        else:
            print(f"      + [{ctx}] {conc}")
