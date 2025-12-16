# QWED Contributor Onboarding Guide (Phase 0)

**Welcome aboard!** 🚀

We believe in **Trust & Openness**. You have full access to the codebase because we want you to see the big picture.

---

## 📚 Step 1: The Context (1 Hour)

Don't read the code yet. Read these first to understand *why* we exist.

1.  **[The Story](docs/WALKTHROUGH.md)**: Read how we evolved from a simple prototype to a 8-engine architecture. It explains the "Why".
2.  **[The System](docs/ARCHITECTURE.md)**: Understand the 3-Layer Defense System (Translation -> Validation -> Verification).
3.  **[The Data](src/qwed_new/core/schemas.py)**: Look at `MathVerificationTask`. This is the core data structure we pass around.

---

## 🛠️ Step 2: The Setup (30 Mins)

1.  **Clone the Repo**:
    ```bash
    git clone https://github.com/StartUp-Rahul/qwed-verification.git
    cd qwed-verification
    ```

2.  **Install Dependencies**:
    ```bash
    # We use uv for speed, but pip works too
    pip install -r requirements.txt
    ```

3.  **Environment Variables**:
    *   Create a `.env` file (copy `.env.example` if it exists, or ask me for the template).
    *   *Note: You don't need live API keys for the Phase 0 task. You can run tests using mocks.*

---

## 🎯 Step 3: The Task (Phase 0)

### The Business Goal: Building an "AI Auditor"
Enterprises process thousands of invoices daily. Manual auditing is slow; standard OCR is error-prone; and raw LLMs "hallucinate" numbers.

**QWED's Role**: We act as the **Mathematical Guarantee**.
We don't just "read" the invoice; we **prove** it is valid using the Z3 Theorem Prover.

### Real-World Scenarios (Your Task)
You are building the **Verification Logic** for a FinTech client. They need to block invalid invoices *before* payment.

**Your Workspace**: `tests/test_enterprise.py` (Create this file).

**Task**: Write 5-10 test cases that cover these real-world failure modes:

| Scenario | The Logic Rule (What QWED must verify) | Why it matters (Real World Impact) |
| :--- | :--- | :--- |
| **GST Fraud** | `GST Format = 2 digits (State Code) + 10 alphanumeric (PAN) + ...` | Prevents accepting fake invoices from shell companies. |
| **Math Error** | `Subtotal + Tax_Amount == Total_Amount` | Vendors often make rounding errors or hidden surcharges. |
| **Date Slip** | `Invoice_Date <= Payment_Due_Date` AND `Invoice_Date <= Today` | Prevents paying for future-dated or stale invoices. |
| **Tax Rate** | `Tax_Amount == Subtotal * 0.18` (assuming 18% GST) | Ensures compliance with tax laws, preventing audits. |

**Output**:
We need you to write the **Tests** that simulate these scenarios (both Valid and Invalid invoices) and assert that our Logic Engine catches them to demonstrate TDD (Test Driven Development).

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
