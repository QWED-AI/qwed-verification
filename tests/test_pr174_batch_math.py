import asyncio

from qwed_new.core.batch import BatchItem, BatchVerificationService, VerificationType


def test_batch_math_identity_verification_returns_valid():
    service = BatchVerificationService()
    item = BatchItem(
        id="math-identity",
        query="x + x = 2*x",
        verification_type=VerificationType.MATH,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["type"] == "math"
    assert result["is_valid"] is True
    assert result["message"] == "Identity verified"


def test_batch_math_non_identity_verification_returns_invalid():
    service = BatchVerificationService()
    item = BatchItem(
        id="math-not-equal",
        query="x + x = x",
        verification_type=VerificationType.MATH,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["type"] == "math"
    assert result["is_valid"] is False
    assert result["message"] == "Not equal"


def test_batch_math_simplification_only_is_not_reported_as_valid():
    service = BatchVerificationService()
    item = BatchItem(
        id="math-simplified",
        query="x + x",
        verification_type=VerificationType.MATH,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["type"] == "math"
    assert result["is_valid"] is False
    assert result["status"] == "SIMPLIFIED"
    assert result["simplified"] == "2*x"
    assert "no equality or proof claim" in result["message"]
