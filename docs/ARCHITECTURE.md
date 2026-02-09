# System Architecture

## Overview
QWED is a **Neurosymbolic Verification Engine** that combines the flexibility of Large Language Models (LLMs) with the determinism of symbolic execution engines (SymPy, Z3, SQLGlot, etc.).

## High-Level Design

The system operates in three layers:
1.  **Translation Layer (Neural)**: LLMs convert natural language queries into structured intermediate representations (IR).
2.  **Verification Layer (Symbolic)**: Specialized engines execute the IR deterministically to produce a result or proof.
3.  **Cross-Validation Layer**: Results are checked against constraints and safety policies before being returned.

```mermaid
graph TD
    User[User/Application] --> API[QWED API / SDK]
    API --> Controller[Control Plane]
    
    subgraph "Neural Layer"
        Controller --> Prompting[Prompt Engineering]
        Prompting --> LLM[External LLM (OpenAI/Anthropic/Local)]
        LLM --> Parser[Response Parser]
    end
    
    subgraph "Symbolic Layer"
        Parser --> Math[Math Engine (SymPy)]
        Parser --> Logic[Logic Engine (Z3)]
        Parser --> SQL[SQL Engine (SQLGlot)]
        Parser --> Code[Code Engine (AST Analysis)]
    end
    
    Math --> Verifier[Result Verifier]
    Logic --> Verifier
    SQL --> Verifier
    Code --> Verifier
    
    Verifier --> PII[PII / Safety Guard]
    PII --> User
```

## Core Components

### 1. Control Plane
Orchestrates the request lifecycle. It identifies the query domain (Math, Code, SQL, etc.) and routes it to the appropriate engine.

### 2. Engines
Each domain has a dedicated engine:
- **Math**: Uses `SymPy` for symbolic mathematics.
- **Logic**: Uses `Z3` theorem prover for propositional and first-order logic.
- **Code**: Uses Python's `ast` module for static analysis and safe execution environments.
- **SQL**: Uses `SQLGlot` and `DuckDB` for schema-aware query verification.

### 3. Safety Guards
- **PII Masking**: Detects and obfuscates minimal PII using `Presidio` before sending data to LLMs.
- **Injection Protection**: Static analysis prevents prompt injection and code injection attacks.

## Data Flow
1.  User sends a query (e.g., "What is the integral of x^2?").
2.  Control Plane detects "Math" domain.
3.  LLM is prompted to translate "integral of x^2" to SymPy code: `integrate(x**2, x)`.
4.  Math Engine executes the SymPy code safely.
5.  Result (`x**3/3`) is formatted and returned to the user.
