"""
Tests for Batch Verification and SDK.

Real integration tests - no mocks.
"""

import pytest
import asyncio


class TestBatchService:
    """Test batch verification service."""
    
    def test_create_batch_job(self):
        """Test creating a batch job."""
        from qwed_new.core.batch import batch_service, VerificationType
        
        items = [
            {"query": "2+2=4", "type": "math"},
            {"query": "3*3=9", "type": "math"},
        ]
        
        job = batch_service.create_job(
            organization_id=1,
            items=items
        )
        
        assert job.job_id is not None
        assert job.total_items == 2
        assert job.organization_id == 1
    
    def test_batch_job_progress(self):
        """Test batch job progress calculation."""
        from qwed_new.core.batch import BatchJob, BatchItem, BatchStatus
        
        items = [
            BatchItem(id="1", query="test1"),
            BatchItem(id="2", query="test2"),
        ]
        
        job = BatchJob(
            job_id="test-123",
            organization_id=1,
            items=items
        )
        
        assert job.progress_percent == 0.0
        
        job.completed_items = 1
        assert job.progress_percent == 50.0
        
        job.completed_items = 2
        assert job.progress_percent == 100.0
    
    def test_batch_job_to_dict(self):
        """Test batch job serialization."""
        from qwed_new.core.batch import BatchJob, BatchItem, BatchStatus
        
        job = BatchJob(
            job_id="test-456",
            organization_id=1,
            items=[BatchItem(id="1", query="test")]
        )
        
        result = job.to_dict()
        
        assert result["job_id"] == "test-456"
        assert result["status"] == "pending"
        assert result["total_items"] == 1


class TestSDKModels:
    """Test SDK data models."""
    
    def test_verification_result_from_dict(self):
        """Test VerificationResult parsing."""
        from qwed_sdk.models import VerificationResult
        
        data = {
            "status": "VERIFIED",
            "is_valid": True,
            "simplified": "4"
        }
        
        result = VerificationResult.from_dict(data)
        
        assert result.status == "VERIFIED"
        assert result.is_verified == True
        assert result.result == data
    
    def test_batch_result_from_dict(self):
        """Test BatchResult parsing."""
        from qwed_sdk.models import BatchResult
        
        data = {
            "job_id": "abc-123",
            "status": "completed",
            "progress_percent": 100.0,
            "total_items": 2,
            "completed_items": 2,
            "failed_items": 0,
            "items": [
                {"id": "1", "query": "test", "type": "math", "status": "completed"}
            ]
        }
        
        result = BatchResult.from_dict(data)
        
        assert result.job_id == "abc-123"
        assert result.success_rate == 100.0
        assert len(result.items) == 1
    
    def test_verification_type_enum(self):
        """Test VerificationType enum."""
        from qwed_sdk.models import VerificationType
        
        assert VerificationType.MATH.value == "math"
        assert VerificationType.LOGIC.value == "logic"
        assert VerificationType.NATURAL_LANGUAGE.value == "natural_language"


class TestCLI:
    """Test CLI helpers."""
    
    def test_cli_imports(self):
        """Test CLI can be imported."""
        from qwed_sdk.cli import main
        
        assert callable(main)
    
    def test_cli_result_printing(self):
        """Test result printing helper."""
        from qwed_sdk.cli import _print_result
        from qwed_sdk.models import VerificationResult
        
        result = VerificationResult(
            status="VERIFIED",
            is_verified=True,
            result={"is_valid": True}
        )
        
        # Should not raise
        _print_result(result, as_json=False)
        _print_result(result, as_json=True)
