"""
Tests for AblationTracker.

Verifies per-engine tracking works correctly.
"""

import pytest
from qwed_new.core.ablation_tracker import (
    AblationTracker, 
    get_tracker, 
    record_verification,
    EngineType,
    VerificationStatus
)


class TestAblationTracker:
    """Tests for AblationTracker class."""
    
    def test_initialization(self):
        """Test tracker initializes with all engines."""
        tracker = AblationTracker()
        stats = tracker.get_stats()
        
        # Should have all 8 engines
        assert "math" in stats["engines"]
        assert "logic" in stats["engines"]
        assert "code" in stats["engines"]
        assert "sql" in stats["engines"]
        assert "stats" in stats["engines"]
        assert "fact" in stats["engines"]
        assert "image" in stats["engines"]
        assert "consensus" in stats["engines"]
    
    def test_record_verified(self):
        """Test recording a verified (correct) result."""
        tracker = AblationTracker()
        
        result = {"is_correct": True, "status": "VERIFIED"}
        tracker.record("math", result, latency_ms=5.0)
        
        stats = tracker.get_stats()
        assert stats["engines"]["math"]["verified"] == 1
        assert stats["engines"]["math"]["rejected"] == 0
        assert stats["engines"]["math"]["total"] == 1
    
    def test_record_rejected(self):
        """Test recording a rejected (error caught) result."""
        tracker = AblationTracker()
        
        result = {"is_correct": False, "status": "CORRECTION_NEEDED"}
        tracker.record("math", result, latency_ms=10.0)
        
        stats = tracker.get_stats()
        assert stats["engines"]["math"]["rejected"] == 1
        assert stats["engines"]["math"]["verified"] == 0
        assert stats["engines"]["math"]["detection_rate"] == 100.0
    
    def test_record_error(self):
        """Test recording an engine error."""
        tracker = AblationTracker()
        
        result = {"is_correct": False, "status": "ERROR", "error": "Syntax error"}
        tracker.record("sql", result, latency_ms=2.0)
        
        stats = tracker.get_stats()
        assert stats["engines"]["sql"]["errors"] == 1
    
    def test_multiple_engines(self):
        """Test tracking across multiple engines."""
        tracker = AblationTracker()
        
        # Math: 2 verified, 1 rejected
        tracker.record("math", {"is_correct": True, "status": "VERIFIED"})
        tracker.record("math", {"is_correct": True, "status": "VERIFIED"})
        tracker.record("math", {"is_correct": False, "status": "CORRECTION_NEEDED"})
        
        # Logic: 1 verified, 2 rejected  
        tracker.record("logic", {"is_correct": True, "status": "VERIFIED"})
        tracker.record("logic", {"is_correct": False, "status": "REJECTED"})
        tracker.record("logic", {"is_correct": False, "status": "REJECTED"})
        
        stats = tracker.get_stats()
        
        # Math
        assert stats["engines"]["math"]["verified"] == 2
        assert stats["engines"]["math"]["rejected"] == 1
        assert stats["engines"]["math"]["llm_accuracy"] == pytest.approx(66.67, rel=0.1)
        
        # Logic
        assert stats["engines"]["logic"]["verified"] == 1
        assert stats["engines"]["logic"]["rejected"] == 2
        assert stats["engines"]["logic"]["detection_rate"] == pytest.approx(66.67, rel=0.1)
        
        # Summary
        assert stats["summary"]["total_verifications"] == 6
        assert stats["summary"]["total_errors_caught"] == 3
        assert stats["summary"]["total_verified_correct"] == 3
    
    def test_latency_tracking(self):
        """Test average latency calculation."""
        tracker = AblationTracker()
        
        tracker.record("code", {"is_correct": True}, latency_ms=10.0)
        tracker.record("code", {"is_correct": True}, latency_ms=20.0)
        tracker.record("code", {"is_correct": True}, latency_ms=30.0)
        
        stats = tracker.get_stats()
        assert stats["engines"]["code"]["avg_latency_ms"] == 20.0
    
    def test_export_json(self):
        """Test JSON export."""
        tracker = AblationTracker()
        tracker.record("math", {"is_correct": False, "status": "REJECTED"})
        
        json_output = tracker.export_json()
        
        assert "math" in json_output
        assert "rejected" in json_output
    
    def test_export_markdown(self):
        """Test markdown export."""
        tracker = AblationTracker()
        tracker.record("math", {"is_correct": True, "status": "VERIFIED"})
        tracker.record("logic", {"is_correct": False, "status": "REJECTED"})
        
        md = tracker.export_markdown()
        
        assert "# QWED Per-Engine Ablation Statistics" in md
        assert "| Math |" in md
        assert "| Logic |" in md
        assert "Detection Rate" in md
    
    def test_get_errors_caught(self):
        """Test getting list of caught errors."""
        tracker = AblationTracker()
        
        tracker.record("math", {"is_correct": True, "status": "VERIFIED"})
        tracker.record("math", {
            "is_correct": False, 
            "status": "CORRECTION_NEEDED",
            "claimed_value": 150000,
            "calculated_value": 162889
        })
        
        errors = tracker.get_errors_caught()
        
        assert len(errors) == 1
        assert errors[0]["engine"] == "math"
        assert errors[0]["error_details"]["claimed_value"] == 150000
    
    def test_reset(self):
        """Test resetting stats."""
        tracker = AblationTracker()
        
        tracker.record("math", {"is_correct": True})
        tracker.record("logic", {"is_correct": False})
        
        tracker.reset()
        
        stats = tracker.get_stats()
        assert stats["summary"]["total_verifications"] == 0
        assert stats["summary"]["total_errors_caught"] == 0
    
    def test_global_tracker(self):
        """Test global tracker singleton."""
        tracker1 = get_tracker()
        tracker2 = get_tracker()
        
        assert tracker1 is tracker2
    
    def test_convenience_function(self):
        """Test record_verification convenience function."""
        # Reset global tracker first
        get_tracker().reset()
        
        record_verification("sql", {"is_correct": False, "status": "REJECTED"})
        
        stats = get_tracker().get_stats()
        assert stats["engines"]["sql"]["rejected"] == 1
    
    def test_engine_breakdown(self):
        """Test detailed engine breakdown."""
        tracker = AblationTracker()
        
        tracker.record("code", {"is_correct": True, "status": "VERIFIED"})
        tracker.record("code", {
            "is_correct": False,
            "status": "REJECTED",
            "error": "Unsafe pattern detected"
        })
        
        breakdown = tracker.get_engine_breakdown("code")
        
        assert breakdown["engine"] == "code"
        assert breakdown["stats"]["verified"] == 1
        assert breakdown["stats"]["rejected"] == 1
        assert len(breakdown["recent_rejections"]) == 1
    
    def test_case_insensitive_engine_names(self):
        """Test that engine names are case insensitive."""
        tracker = AblationTracker()
        
        tracker.record("MATH", {"is_correct": True})
        tracker.record("Math", {"is_correct": True})
        tracker.record("math", {"is_correct": True})
        
        stats = tracker.get_stats()
        assert stats["engines"]["math"]["total"] == 3


class TestEngineType:
    """Tests for EngineType enum."""
    
    def test_all_engines_defined(self):
        """Ensure all 8 engines are defined."""
        engines = [e.value for e in EngineType]
        
        assert len(engines) == 8
        assert "math" in engines
        assert "logic" in engines
        assert "code" in engines
        assert "sql" in engines
        assert "stats" in engines
        assert "fact" in engines
        assert "image" in engines
        assert "consensus" in engines
