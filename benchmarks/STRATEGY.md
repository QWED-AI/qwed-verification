# QWED Deep Benchmark Strategy: "Stress Testing Reality"

## Objective
To rigorously test each of QWED's 7 verification engines individually, pushing them from basic competence to total collapse. This will identify the exact "breaking point" of our system vs. Raw LLMs.

## 🏗️ Benchmark Categories & Difficulty Levels

### 1. 🧮 Math Engine (SymPy)
*   **Easy**: Basic Arithmetic & Order of Operations.
    *   *Ex*: `2 + 2 * 4`
*   **Medium**: Algebra & Percentages.
    *   *Ex*: `Solve for x: 2x + 5 = 15`, `What is 15% of 80?`
*   **Hard**: Calculus & Multi-step Word Problems (GSM8K style).
    *   *Ex*: `Derivative of x^2 * log(x)`, "Sophie eats 2 apples..."
*   **💀 Collapse**: Ambiguous Notation & Unsolvable Problems.
    *   *Ex*: `6/2(1+2)` (The viral math problem), `x/0`, `Prove 1=2`.

### 2. 🧠 Logic Engine (Z3)
*   **Easy**: Simple Syllogisms.
    *   *Ex*: "All humans are mortal. Socrates is human. Is Socrates mortal?"
*   **Medium**: Propositional Logic & Knights/Knaves.
    *   *Ex*: "A says B is lying. B says A is telling the truth."
*   **Hard**: Constraint Satisfaction (Einstein's Riddle).
    *   *Ex*: "5 houses, 5 colors... Who owns the fish?"
*   **💀 Collapse**: Paradoxes & Self-Reference.
    *   *Ex*: "This statement is false.", "Does the set of all sets contain itself?"

### 3. 🛡️ Safety & Code Engine (Static Analysis + Sandbox)
*   **Easy**: Safe Python Code.
    *   *Ex*: `print("Hello World")`
*   **Medium**: Resource Usage.
    *   *Ex*: Large loops, memory allocation.
*   **Hard**: Obfuscated Malicious Code.
    *   *Ex*: `eval(base64.b64decode('...'))` trying to access file system.
*   **💀 Collapse**: Polyglot Injection & Side-Channels.
    *   *Ex*: Code that looks like comments but executes, infinite recursion to crash the sandbox.

### 4. 🗄️ SQL Engine (Parser)
*   **Easy**: Basic SELECTs.
    *   *Ex*: `SELECT * FROM users`
*   **Medium**: Joins & Aggregates.
    *   *Ex*: `SELECT count(*) FROM users JOIN orders...`
*   **Hard**: Complex Window Functions & CTEs.
    *   *Ex*: `WITH recursive...`
*   **💀 Collapse**: Hallucinated Schemas & Ambiguity.
    *   *Ex*: "Show me the *best* customers" (Subjective), querying tables that don't exist.

### 5. 📊 Stats Engine (Pandas)
*   **Easy**: Mean, Median, Mode.
    *   *Ex*: "Average of [1, 2, 3]"
*   **Medium**: Percentiles & Standard Deviation.
    *   *Ex*: "95th percentile of..."
*   **Hard**: Correlation vs Causation.
    *   *Ex*: "Correlation between X and Y" (verifying the math, not the causality).
*   **💀 Collapse**: Simpson's Paradox & Data Poisoning.
    *   *Ex*: Datasets where aggregate trends reverse when split by groups.

### 6. 🤥 Fact Engine (Knowledge Retrieval)
*   **Easy**: Common Knowledge.
    *   *Ex*: "Capital of France?"
*   **Medium**: Historical Specifics.
    *   *Ex*: "Who signed the treaty of Versailles?"
*   **Hard**: Scientific Consensus.
    *   *Ex*: "Is the earth flat?"
*   **💀 Collapse**: Counterfactuals & Future Events.
    *   *Ex*: "Who won the 2028 election?", "If Hitler won WWII, what would be the capital?"

## 🚀 Execution Plan
1.  **Create `benchmarks/deep_suite/`**: A folder for these specific tests.
2.  **Implement Generators**: Scripts to generate these problems (especially the "Collapse" ones).
3.  **Run & Report**: Generate a `DEEP_BENCHMARK_REPORT.md` highlighting exactly where QWED fails.

## Success Criteria
*   **QWED** should handle Easy/Medium/Hard with >95% accuracy.
*   **QWED** should gracefully handle "Collapse" (return "Unverifiable" or "Error") rather than hallucinating an answer like Raw LLMs.
