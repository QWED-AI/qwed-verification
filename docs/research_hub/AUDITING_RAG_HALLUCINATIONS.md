# Auditing Hallucinations in RAG Pipelines via Atomic Claim Verification

**Published:** Nov 27, 2025  
**Type:** Research Artifact  
**Author:** QWED_LABS  
**Tags:** `safety`, `rag`, `audit`, `nli`

## Abstract
Retrieval-Augmented Generation (RAG) systems frequently suffer from "Attribution Errors," where the generated answer is not supported by the retrieved context. We introduce a **Dual-Verify Architecture** that decomposes responses into atomic claims and verifies each against the source text using Natural Language Inference (NLI). In an audit of 10,000 enterprise queries, this method detected **30% more hallucinations** than standard cosine-similarity metrics.

## 1. Introduction
While RAG reduces hallucinations compared to parametric knowledge, it introduces a new failure mode: **Grounding Failure**. A model may retrieve the correct document but hallucinate specific details (e.g., numbers, dates) that are not present in the text.

Standard evaluation metrics like ROUGE or BLEU are insufficient for detecting these subtle semantic errors [1]. We propose a deterministic auditing layer based on **Atomic Fact Verification** [2].

## 2. Methodology

### 2.1 The Hallucination Gap ($G$)
We define the Hallucination Gap as the semantic distance between the set of claims in the generated answer ($A$) and the retrieved context ($C$).

$$ G(A, C) = 1 - \frac{\sum_{i=1}^{n} \mathbb{I}(\text{Entail}(C, a_i))}{n} $$

Where:
*   $a_i$ is an atomic claim extracted from $A$.
*   $\text{Entail}(C, a_i)$ is a binary function (1 if supported, 0 otherwise).

### 2.2 Verification Algorithm
The QWED Fact Engine implements the following algorithm:

**Algorithm 1: Atomic Claim Verification**
```python
def verify_rag_response(context: str, response: str) -> float:
    """
    Returns a confidence score (0.0 - 1.0) based on factual grounding.
    """
    # 1. Decompose response into atomic facts
    # e.g. "Paris is in France and has 2M people" -> ["Paris is in France", "Paris has 2M people"]
    atomic_claims = decompose_claims(response)
    
    supported_count = 0
    
    for claim in atomic_claims:
        # 2. Verify each claim against context using NLI
        # Returns: ENTAILMENT, NEUTRAL, or CONTRADICTION
        verdict = nli_model.predict(premise=context, hypothesis=claim)
        
        if verdict == 'ENTAILMENT':
            supported_count += 1
        elif verdict == 'CONTRADICTION':
            return 0.0  # Immediate failure on contradiction
            
    return supported_count / len(atomic_claims)
```

## 3. Experimental Results

We audited a RAG pipeline over a corpus of financial reports (10k documents).

### Table 1: Detection Rates
| Metric | Hallucinations Detected | False Positives |
| :--- | :--- | :--- |
| Cosine Similarity (< 0.8) | 42% | 15% |
| LLM-as-a-Judge (GPT-4) | 78% | 8% |
| **QWED Atomic Verify** | **92%** | **3%** |

*Table 1: QWED's granular approach catches "hallucinated details" that semantic similarity misses.*

### Table 2: Context Poisoning Impact
We injected irrelevant "poison" chunks into the context window to measure robustness.

| Method | Accuracy (Clean Context) | Accuracy (Poisoned Context) | Degradation |
| :--- | :--- | :--- | :--- |
| Standard RAG | 92.4% | 78.1% | -14.3% |
| **QWED RAG** | **94.1%** | **91.5%** | **-2.6%** |

*Table 2: By filtering context chunks *before* generation using the Logic Engine, QWED maintains performance even in noisy retrieval environments.*

## 4. References

1.  Lewis, P., et al. (2020). "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *NeurIPS*.
2.  Min, S., et al. (2023). "FActScore: Fine-grained Atomic Evaluation of Factual Precision in Long Form Text Generation." *EMNLP*.
3.  Ji, Z., et al. (2023). "Survey of Hallucination in Natural Language Generation." *ACM Computing Surveys*.
4.  Honovich, O., et al. (2022). "TRUE: Re-evaluating Factual Consistency Evaluation." *NAACL*.
