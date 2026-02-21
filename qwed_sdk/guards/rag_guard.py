"""
RAGGuard: Document-Level Retrieval Mismatch (DRM) Defender.

Verifies that retrieved context chunks in a RAG pipeline originate
from the correct source document, preventing hallucinations caused
by vector databases returning chunks from structurally similar but
semantically wrong documents (e.g., the wrong NDA or Privacy Policy).

Based on research from: "Towards Reliable Retrieval in RAG Systems
for Large Legal Datasets" — DRM is a critical failure mode where
legal/financial documents look structurally identical to embedding
models, causing cross-document contamination of retrieved context.
"""
from fractions import Fraction
from typing import Dict, Any, List, Union


# --- Audit Constants ---
AUDIT_ISSUE = "irac.issue"
AUDIT_RULE = "irac.rule"
AUDIT_APP = "irac.application"
AUDIT_CONCL = "irac.conclusion"


class RAGGuardConfigError(ValueError):
    """Raised when RAGGuard is constructed with invalid configuration."""


class RAGGuard:
    """
    Deterministic guard for RAG pipeline integrity.

    Ensures retrieved chunks match the expected source document,
    preventing Document-Level Retrieval Mismatch (DRM) hallucinations.

    Example::

        guard = RAGGuard()
        result = guard.verify_retrieval_context(
            target_document_id="contract_nda_v2",
            retrieved_chunks=[
                {"id": "c1", "metadata": {"document_id": "contract_nda_v2"}},
                {"id": "c2", "metadata": {"document_id": "contract_nda_v1"}},  # wrong!
            ]
        )
        # result["verified"] == False, result["drm_rate"] == 0.5
    """

    def __init__(
        self,
        max_drm_rate: Union[Fraction, str, int] = Fraction(0),
        require_metadata: bool = True,
    ):
        """
        Args:
            max_drm_rate: Maximum tolerable fraction of mismatched chunks
                (0 = zero tolerance, 1 = allow all). Accepts ``Fraction``,
                ``str`` (e.g., "1/10"), or ``int``. Floats are rejected to
                enforce symbolic precision. Default: ``Fraction(0)``.
            require_metadata: If True, chunks missing ``document_id`` in
                metadata are treated as mismatches. Default: True.
        """
        if isinstance(max_drm_rate, float):
            raise RAGGuardConfigError(
                "max_drm_rate must be Fraction, str, or int to ensure symbolic precision. "
                "Floats are not permitted."
            )
        try:
            threshold = Fraction(max_drm_rate)
        except (ValueError, TypeError) as e:
            raise RAGGuardConfigError(f"Invalid max_drm_rate: {e}") from e

        if not Fraction(0) <= threshold <= Fraction(1):
            raise RAGGuardConfigError("max_drm_rate must be between 0 and 1")
        # Store as exact Fraction — no IEEE-754 round-trip at comparison time
        self._threshold: Fraction = threshold
        self.require_metadata = require_metadata

    @property
    def max_drm_rate(self) -> float:
        """Float view of the DRM threshold (for display/logging)."""
        return float(self._threshold)

    def verify_retrieval_context(
        self,
        target_document_id: str,
        retrieved_chunks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Verify that all retrieved chunks belong to the target document.

        Args:
            target_document_id: The expected source document identifier.
                Must be a non-empty string.
            retrieved_chunks: List of chunk dicts. Each chunk should have
                ``metadata.document_id`` set.

        Returns:
            Dict with ``verified`` bool plus IRAC audit fields.
        """
        if not target_document_id:
            raise ValueError("target_document_id must be a non-empty string.")

        _rule = (
            f"DRM rate must not exceed {float(self._threshold):.1%} "
            f"(max_drm_rate threshold)."
        )

        if not retrieved_chunks:
            return {
                "verified": True,
                "drm_rate": 0.0,
                "chunks_checked": 0,
                "message": "No chunks to verify.",
                AUDIT_ISSUE: "None — no chunks to evaluate.",
                AUDIT_RULE: _rule,
                AUDIT_APP: "Zero chunks provided; check vacuously passes.",
                AUDIT_CONCL: "Verified: no chunks to evaluate.",
            }

        mismatched: List[Dict[str, Any]] = []

        for chunk in retrieved_chunks:
            chunk_id = chunk.get("id", "unknown")
            metadata = chunk.get("metadata") or {}
            chunk_doc_id = metadata.get("document_id")

            if chunk_doc_id is None:
                if self.require_metadata:
                    mismatched.append({
                        "chunk_id": chunk_id,
                        "issue": "MISSING_DOCUMENT_ID",
                        "wrong_source": None,
                    })
            elif chunk_doc_id != target_document_id:
                mismatched.append({
                    "chunk_id": chunk_id,
                    "issue": "WRONG_DOCUMENT",
                    "wrong_source": chunk_doc_id,
                })

        total = len(retrieved_chunks)
        drm_fraction = Fraction(len(mismatched), total)
        drm_float = round(float(drm_fraction), 4)

        if drm_fraction > self._threshold:
            return {
                "verified": False,
                "risk": "DOCUMENT_RETRIEVAL_MISMATCH",
                "drm_rate": drm_float,
                "chunks_checked": total,
                "mismatched_count": len(mismatched),
                "message": (
                    f"Blocked RAG injection: {len(mismatched)}/{total} chunks "
                    f"originated from the wrong source document. "
                    f"DRM rate {float(drm_fraction):.1%} exceeds threshold "
                    f"{float(self._threshold):.1%}. This will cause hallucinations."
                ),
                "details": mismatched,
                AUDIT_ISSUE: "Document-level retrieval mismatch detected in RAG context.",
                AUDIT_RULE: _rule,
                AUDIT_APP: (
                    f"{len(mismatched)} of {total} chunks originated from "
                    "wrong or unidentified source documents."
                ),
                AUDIT_CONCL: f"Blocked: DRM rate {drm_float:.1%} exceeds threshold.",
            }

        _success_message = (
            f"{len(mismatched)}/{total} mismatch(es) tolerated "
            f"(DRM rate {drm_float:.1%} ≤ threshold {float(self._threshold):.1%})."
            if mismatched else
            f"All {total} chunk(s) verified from correct source document."
        )

        _app_message = (
            f"{len(mismatched)} mismatch(es) tolerated; "
            f"{total - len(mismatched)}/{total} chunk(s) from correct source."
            if mismatched else
            f"All {total} chunk(s) passed document_id equality check."
        )

        return {
            "verified": True,
            "drm_rate": drm_float,
            "chunks_checked": total,
            "mismatched_count": len(mismatched),
            "details": mismatched,
            "message": _success_message,
            AUDIT_ISSUE: "None — all chunks evaluated.",
            AUDIT_RULE: _rule,
            AUDIT_APP: _app_message,
            AUDIT_CONCL: "Verified: DRM rate within acceptable threshold.",
        }

    def filter_valid_chunks(
        self,
        target_document_id: str,
        retrieved_chunks: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Return only the chunks that belong to the target document.

        Useful when you want to silently drop mismatched chunks rather
        than raising an error.

        Args:
            target_document_id: The expected source document identifier.
            retrieved_chunks: Full list of retrieved chunks.

        Returns:
            Filtered list containing only matching chunks.
        """
        if not target_document_id:
            raise ValueError("target_document_id must be a non-empty string.")

        def _chunk_matches(chunk: Dict[str, Any]) -> bool:
            doc_id = chunk.get("metadata", {}).get("document_id")
            if doc_id == target_document_id:
                return True
            # When require_metadata=False, chunks with no document_id are kept
            return not self.require_metadata and doc_id is None

        return [chunk for chunk in retrieved_chunks if _chunk_matches(chunk)]
