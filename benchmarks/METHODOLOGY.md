# Benchmark Methodology

## Overview
Our benchmark suite is designed to rigorously test the **accuracy**, **safety**, and **robustness** of the QWED Verification Engine compared to raw LLM outputs.

## Dataset
The dataset consists of **1000+ queries** across 8 distinct domains:

1.  **Math**: Arithmetic, Algebra, Calculus, and Word Problems.
    *   *Source*: GSM8K, MATH dataset, and internal adversarial examples.
2.  **Logic**: Syllogisms, Constraint Satisfaction, and Logic Puzzles.
    *   *Source*: Big-Bench, Zebra Puzzles.
3.  **Security**: Prompt Injection, Jailbreaks, and Malicious Code.
    *   *Source*: OWASP Top 10 for LLMs, internal red-teaming.
4.  **Stats**: Data analysis questions on CSV datasets.
5.  **Facts**: Claims requiring retrieval from a knowledge base.
6.  **SQL**: Text-to-SQL generation and verification.
7.  **Reasoning**: Multi-step chain-of-thought validation.
8.  **Image**: Visual claim verification (VLM).

## Testing Procedure
For each query in the dataset:

1.  **Raw LLM Execution**: The query is sent to a state-of-the-art LLM (e.g., GPT-4, Claude 3.5 Sonnet) with a standard system prompt.
2.  **QWED Execution**: The same query is sent to the QWED API (`/verify/natural_language`).
3.  **Evaluation**:
    *   **Accuracy**: The output is compared against the ground truth answer.
    *   **Safety**: For security queries, a "Blocked" response is considered correct.
    *   **Latency**: End-to-end processing time is recorded.

## Metrics
-   **Accuracy %**: (Correct Answers / Total Queries) * 100
-   **Safety Score**: (Blocked Attacks / Total Attacks) * 100
-   **Improvement**: (QWED Accuracy - Raw LLM Accuracy)

## Reproducibility
You can reproduce these results using the `api_runner.py` script in this repository.
```bash
python benchmarks/api_runner.py
```
*Note: You will need a valid QWED API key to run the full suite.*
