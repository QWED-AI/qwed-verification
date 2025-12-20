---
sidebar_position: 99
---

# Architecture Diagrams

Visual representations of QWED's architecture and data flow.

## System Overview

```mermaid
graph TB
    subgraph "Client Layer"
        SDK[SDKs<br/>Python/TS/Go/Rust]
        API[REST API<br/>FastAPI]
    end
    
    subgraph "Control Plane"
        CP[Control Plane]
        RL[Rate Limiter]
        AUTH[Auth/Multi-tenancy]
    end
    
    subgraph "Verification Engines"
        MATH[🔢 Math<br/>SymPy]
        LOGIC[🧠 Logic<br/>Z3]
        CODE[💻 Code<br/>AST]
        SQL[🗃️ SQL<br/>SQLGlot]
        STATS[📊 Stats<br/>Wasm Sandbox]
        FACT[📚 Fact<br/>TF-IDF]
        IMAGE[🖼️ Image<br/>Metadata]
        REASON[💭 Reasoning<br/>Multi-LLM]
    end
    
    subgraph "LLM Providers"
        CLAUDE[Anthropic Claude]
        GPT[OpenAI GPT]
        GEMINI[Google Gemini]
    end
    
    subgraph "Storage"
        DB[(SQLite/Postgres)]
        REDIS[(Redis Cache)]
    end
    
    SDK --> API
    API --> CP
    CP --> RL
    CP --> AUTH
    CP --> MATH
    CP --> LOGIC
    CP --> CODE
    CP --> SQL
    CP --> STATS
    CP --> FACT
    CP --> IMAGE
    CP --> REASON
    
    REASON --> CLAUDE
    REASON --> GPT
    REASON --> GEMINI
    
    CP --> DB
    CP --> REDIS
```

## Verification Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Control as Control Plane
    participant Detector as Domain Detector
    participant Engine as Verification Engine
    participant LLM as LLM Provider
    
    User->>API: POST /verify {"query": "2+2=4"}
    API->>Control: Check auth & rate limits
    Control->>Detector: Detect domain
    Detector-->>Control: Domain: MATH
    Control->>Engine: Route to MathVerifier
    
    alt Deterministic Verification
        Engine->>Engine: SymPy symbolic solve
        Engine-->>Control: {verified: true, confidence: 1.0}
    else Requires LLM Translation
        Engine->>LLM: Translate to symbolic
        LLM-->>Engine: Symbolic expression
        Engine->>Engine: Verify with SymPy
        Engine-->>Control: {verified: true, confidence: 0.95}
    end
    
    Control-->>API: Verification result
    API-->>User: {status: "VERIFIED", answer: 4}
```

## Multi-Engine Architecture

```mermaid
flowchart LR
    subgraph Input
        QUERY[User Query]
    end
    
    subgraph Detection
        DD[Domain Detector]
    end
    
    subgraph "Deterministic Engines"
        MATH[🔢 Math Engine<br/>━━━━━━━━<br/>SymPy + Decimal<br/>Calculus<br/>Matrix Ops<br/>Finance NPV/IRR]
        
        LOGIC[🧠 Logic Engine<br/>━━━━━━━━<br/>Z3 SMT Solver<br/>ForAll/Exists<br/>BitVectors<br/>Array Theory]
        
        CODE[💻 Code Engine<br/>━━━━━━━━<br/>AST Analysis<br/>Python/JS/Java/Go<br/>Security Patterns<br/>Vulnerability Detection]
        
        SQL[🗃️ SQL Engine<br/>━━━━━━━━<br/>SQLGlot Parser<br/>Complexity Limits<br/>Injection Detection<br/>Schema Validation]
    end
    
    subgraph "Data Engines"
        STATS[📊 Stats Engine<br/>━━━━━━━━<br/>Wasm Sandbox<br/>Docker Fallback<br/>AST Validation]
        
        FACT[📚 Fact Engine<br/>━━━━━━━━<br/>TF-IDF Similarity<br/>Entity Matching<br/>Citation Extraction]
        
        IMAGE[🖼️ Image Engine<br/>━━━━━━━━<br/>Metadata Parse<br/>Size Verification<br/>VLM Fallback]
    end
    
    subgraph "Orchestration"
        REASON[💭 Reasoning<br/>━━━━━━━━<br/>Multi-LLM<br/>Result Caching<br/>CoT Validation]
        
        CONSENSUS[🤝 Consensus<br/>━━━━━━━━<br/>Async Execution<br/>Circuit Breaker<br/>Weighted Voting]
    end
    
    QUERY --> DD
    DD --> MATH
    DD --> LOGIC
    DD --> CODE
    DD --> SQL
    DD --> STATS
    DD --> FACT
    DD --> IMAGE
    DD --> REASON
    DD --> CONSENSUS
```

## Trust Architecture

```mermaid
graph TB
    subgraph "Untrusted Zone"
        LLM[LLM Translator<br/>Probabilistic]
    end
    
    subgraph "Trusted Zone"
        SYMPY[SymPy<br/>Symbolic Math]
        Z3[Z3 Prover<br/>SAT/SMT]
        AST[AST Parser<br/>Code Analysis]
        SQLGLOT[SQLGlot<br/>Query Parser]
    end
    
    subgraph "Verification Protocol"
        VP1[1. LLM translates query]
        VP2[2. Symbolic engine verifies]
        VP3[3. Result is deterministic]
        VP4[4. Attestation signed]
    end
    
    LLM -->|"Translate"| VP1
    VP1 --> SYMPY
    VP1 --> Z3
    VP1 --> AST
    VP1 --> SQLGLOT
    SYMPY --> VP2
    Z3 --> VP2
    AST --> VP2
    SQLGLOT --> VP2
    VP2 --> VP3
    VP3 --> VP4
    
    style LLM fill:#ff6b6b,stroke:#333,stroke-width:2px
    style SYMPY fill:#51cf66,stroke:#333,stroke-width:2px
    style Z3 fill:#51cf66,stroke:#333,stroke-width:2px
    style AST fill:#51cf66,stroke:#333,stroke-width:2px
    style SQLGLOT fill:#51cf66,stroke:#333,stroke-width:2px
```

## Consensus Engine Flow

```mermaid
flowchart TD
    INPUT[Verification Request]
    
    subgraph "Parallel Execution"
        E1[Engine 1<br/>SymPy]
        E2[Engine 2<br/>Python Eval]
        E3[Engine 3<br/>Z3 Cross-check]
    end
    
    subgraph "Circuit Breaker"
        CB{Error Rate<br/>< 50%?}
        HEALTHY[Healthy]
        DEGRADED[Degraded]
    end
    
    subgraph "Consensus"
        VOTE[Weighted Voting]
        W1["Weight: 1.00"]
        W2["Weight: 0.99"]
        W3["Weight: 0.995"]
    end
    
    OUTPUT[Final Result]
    
    INPUT --> E1 & E2 & E3
    E1 --> CB
    E2 --> CB
    E3 --> CB
    CB -->|Yes| HEALTHY
    CB -->|No| DEGRADED
    HEALTHY --> VOTE
    E1 --> W1 --> VOTE
    E2 --> W2 --> VOTE
    E3 --> W3 --> VOTE
    VOTE --> OUTPUT
```
