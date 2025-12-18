# QWED Contributor Onboarding Guide (Phase 0: Security)

**Welcome aboard!** 🚀
We believe in **Trust & Openness**. You have full access to the codebase because we want you to see the big picture.

---

## 📚 Step 1: The Context (1 Hour)

Don't read the code yet. Read these first to understand *why* we exist.

1. **[The Story](docs/WALKTHROUGH.md)**: Read how we evolved from a simple prototype to an Enterprise Architecture.
2. **[The System](docs/ARCHITECTURE.md)**: Understand the "Firewall" concept. We sit between the AI and the Database.
3. **[The Threat Model](architecture/SECURITY_IMPLEMENTATION_REPORT.md)**: Briefly scan the "SQL Injection" section to understand what we are protecting against.

---

## 🛠️ Step 2: The Setup (30 Mins)

1. **Clone the Repo**:
```bash
git clone https://github.com/rahuldass19/qwed-verification.git
cd qwed-verification
```

2. **Install Dependencies**:
```bash
# We use standard pip for the core dependencies
pip install -e .
```

3. **Environment Variables**:
* Create a `.env` file (copy `.env.example`).
* *Note: We now use **PostgreSQL** via Docker. Ensure you have Docker running (`docker-compose up -d`) to run the full suite, but for this task, standard unit tests will suffice.*

---

## 🎯 Step 3: The Task (Phase 0)

### The Goal: Building a "SQL Firewall" for AI Agents

Enterprises want to use "Text-to-SQL" agents (e.g., "Show me top 10 users").
**The Risk:** LLMs hallucinate. If an LLM generates `DROP TABLE users` or `SELECT * FROM passwords`, the company is destroyed.

**QWED's Role**: We parse the SQL (using AST analysis) and **Block** dangerous queries before they hit the database.

### Real-World Scenarios (Your Task)

You are building the **Safety Test Suite** for our SQL Engine.
**Your Workspace**: `tests/test_sql_safety.py` (Create this file).

**Task**: Write 5-10 test cases that simulate these "Bad AI" behaviors:

| Scenario | The Safety Rule (What QWED must catch) | Why it matters (Real World Impact) |
| --- | --- | --- |
| **The Destructor** | Query contains `DROP`, `TRUNCATE`, or `ALTER` | Prevents AI from deleting the production database. |
| **The Data Leak** | Query selects sensitive columns: `password_hash`, `ssn`, `salary` | Prevents AI from revealing PII or credentials. |
| **The Injection** | Query contains comment attacks (`--`, `/*`) or `1=1` | Prevents classic SQL Injection bypasses. |
| **The Mass Delete** | `DELETE` or `UPDATE` statement without a `WHERE` clause | Prevents accidentally wiping all records instead of one. |

**Output**:
Write the **Tests** first (TDD). Create scenarios for both **Safe Queries** (e.g., `SELECT name FROM users`) and **Unsafe Queries`. Assert that our engine raises a `SecurityViolation` error for the unsafe ones.

---

## 🚀 Step 4: Submission

1.  Create a branch: `git checkout -b feature/invoice-tests`
2.  Push your changes.
3.  Open a Pull Request (PR).

---

### Questions?
Ping me anytime. I value:
*   **Curiosity**: Ask "Why did you design it this way?"
*   **Clarity**: Write simple, readable code.
*   **Speed**: Ship small, verified changes.
