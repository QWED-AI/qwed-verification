# QWED Engine Architecture

QWED achieves deterministic verification through a multi-engine "Consensus Kernel".

## The 8 Core Engines

### 1. Math Engine (`math_verifier`)
-   **Technology**: SymPy (Symbolic Python)
-   **Function**: Converts natural language math into symbolic expressions.
-   **Why**: $1+1=2$ is a fact, not a probability. We solve it, we don't predict it.

### 2. Logic Engine (`logic_verifier`)
-   **Technology**: Z3 Theorem Prover
-   **Function**: Models logic puzzles as constraint satisfaction problems.
-   **Why**: Ensures that conclusions strictly follow premises (e.g., Syllogisms).

### 3. Code Engine (`code_verifier`)
-   **Technology**: Sandboxed Python Execution + AST Analysis
-   **Function**: Writes code to solve the problem, verifies the code is safe, then executes it.
-   **Why**: Code execution is the ultimate ground truth for computational problems.

### 4. Stats Engine (`stats_verifier`)
-   **Technology**: Pandas / NumPy
-   **Function**: Performs deterministic analysis on datasets (CSV/SQL).
-   **Why**: LLMs are terrible at calculating averages over 1000 rows. Pandas is perfect at it.

### 5. Fact Engine (`fact_verifier`)
-   **Technology**: RAG (Retrieval Augmented Generation) + Citation Checking
-   **Function**: Verifies claims against a trusted corpus (e.g., "The policy covers X").
-   **Why**: Prevents hallucination of non-existent facts.

### 6. Image Engine (`image_verifier`)
-   **Technology**: Vision Language Models (VLM) + Forensic Analysis
-   **Function**: Verifies claims about visual content and detects generation artifacts.
-   **Why**: "Deepfake Detection" requires visual reasoning, not just pixel matching.

### 7. Reasoning Engine (`reasoning_verifier`)
-   **Technology**: Chain-of-Thought Validation
-   **Function**: Checks if step B actually follows from step A.
-   **Why**: Catching logical fallacies in the argument structure.

### 8. Consensus Engine (`consensus_verifier`)
-   **Technology**: Weighted Voting Algorithm
-   **Function**: The "Judge". It queries multiple engines and calculates a confidence score.
-   **Why**: If SymPy and Python Code Execution both say "42", confidence is 100%.
