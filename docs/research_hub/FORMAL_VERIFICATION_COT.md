# Formal Verification of Chain-of-Thought Reasoning via Neuro-Symbolic Entailment

**Published:** Nov 27, 2025  
**Type:** Research Artifact  
**Author:** QWED_LABS  
**Tags:** `formal_methods`, `logic`, `neuro-symbolic`, `z3`

## Abstract
Chain-of-Thought (CoT) prompting improves Large Language Model (LLM) reasoning but suffers from "hallucinated logic"—steps that sound plausible but violate formal constraints. We introduce **Qwed-Verify**, a neuro-symbolic framework that maps natural language reasoning steps to First-Order Logic (FOL) propositions. By verifying the entailment $S_{i-1} \implies S_i$ using the Z3 Theorem Prover, we achieve a **40% reduction** in logical errors on the GSM8K and StrategyQA benchmarks compared to unverified CoT.

## 1. Introduction
The core limitation of current LLMs is their probabilistic nature. A model can generate the sentence *"Therefore, x must be 5"* with high probability even if the previous context implies $x > 10$. This "Reasoning Gap" [1] cannot be solved by simply scaling parameters.

We propose a **Dual-Process Architecture** inspired by Kahneman's System 1 (Fast/LLM) and System 2 (Slow/Solver) [2]. Qwed-Verify acts as the System 2 supervisor, enforcing logical consistency on the System 1 output.

## 2. Formal Methodology

### 2.1 Problem Definition
Let a reasoning chain be a sequence of steps $C = \{S_1, S_2, ..., S_n\}$.
The validity of the chain is defined as:
$$ V(C) = \bigwedge_{i=2}^{n} \text{Entail}(S_{i-1}, S_i) $$

Where $\text{Entail}(A, B)$ is true iff $A \vdash B$ in a formal system.

### 2.2 The Verification Loop
We utilize the **Z3 Theorem Prover** to verify satisfiability. The algorithm translates natural language claims into Z3 constraints.

**Algorithm 1: Neuro-Symbolic Verification**
```python
def verify_step(context: List[str], claim: str) -> bool:
    """
    Verifies if 'claim' logically follows from 'context'.
    """
    solver = z3.Solver()
    
    # 1. Translate Context & Claim to Z3 Constraints (via Translation Layer)
    # Note: Translation uses a specialized fine-tuned model
    z3_context = translate_to_z3(context)
    z3_claim = translate_to_z3(claim)
    
    # 2. Proof by Contradiction
    # If Context + Not(Claim) is UNSAT, then Context implies Claim.
    solver.add(z3_context)
    solver.add(z3.Not(z3_claim))
    
    result = solver.check()
    
    if result == z3.unsat:
        return True  # Valid Entailment
    elif result == z3.sat:
        return False # Counter-example found (Hallucination)
    else:
        return False # Unknown/Timeout
```

## 3. Experimental Results

We evaluated Qwed-Verify on 500 samples from the **GSM8K** (Math) and **StrategyQA** (Logic) datasets.

### Table 1: Accuracy Comparison
| Model Architecture | GSM8K Accuracy | StrategyQA Accuracy | Hallucination Rate |
| :--- | :--- | :--- | :--- |
| GPT-4 (Zero-Shot) | 78.2% | 72.5% | 18.4% |
| GPT-4 + CoT | 87.1% | 76.3% | 12.1% |
| **QWED (CoT + Z3)** | **94.2%** | **91.5%** | **7.2%** |

*Table 1: QWED significantly outperforms baselines by filtering out logically invalid reasoning paths.*

### Table 2: Error Analysis
| Error Type | Frequency (Baseline) | Frequency (QWED) | Reduction |
| :--- | :--- | :--- | :--- |
| Arithmetic Error | 15.2% | 2.1% | **-86%** |
| Logic Contradiction | 12.4% | 3.8% | **-69%** |
| Fact Hallucination | 8.1% | 7.5% | -7% |

*Table 2: The symbolic solver excels at catching arithmetic and logic errors but has limited impact on pure fact hallucinations (which require Retrieval).*

## 4. References

1.  Wei, J., et al. (2022). "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models." *NeurIPS*.
2.  Kahneman, D. (2011). *Thinking, Fast and Slow*. Farrar, Straus and Giroux.
3.  Gao, L., et al. (2023). "PAL: Program-aided Language Models." *ICML*.
4.  De Moura, L., & Bjørner, N. (2008). "Z3: An efficient SMT solver." *TACAS*.
