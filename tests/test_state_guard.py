import pytest
import subprocess
from qwed_new.guards.state_guard import StateGuard

def test_state_guard_initialization(tmp_path):
    # Should fail if not a git repo
    with pytest.raises(RuntimeError, match="not a valid git repository"):
        StateGuard(str(tmp_path))
        
    # Make it a git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    
    guard = StateGuard(str(tmp_path))
    assert guard.workspace == tmp_path.resolve()

def test_state_guard_snapshot_and_rollback(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@qwed.ai"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(tmp_path), check=True)
    
    # Create an initial file
    test_file = tmp_path / "test.txt"
    test_file.write_text("initial")
    
    guard = StateGuard(str(tmp_path))
    
    # Take a snapshot
    tree_hash = guard.create_pre_execution_snapshot()
    assert len(tree_hash) == 40
    
    # Commit the initial state just to establish HEAD for git checkout to work cleanly (optional)
    subprocess.run(["git", "commit", "-m", "Initial"], cwd=str(tmp_path), capture_output=True)
    
    # Modify the workspace
    test_file.write_text("malicious agent modification")
    rogue_file = tmp_path / "rogue.txt"
    rogue_file.write_text("left behind")
    
    assert test_file.read_text() == "malicious agent modification"
    assert rogue_file.exists()
    
    # Rollback
    success = guard.rollback(tree_hash)
    assert success is True
    
    # Verify rollback
    assert test_file.read_text() == "initial"
    assert not rogue_file.exists()

def test_state_guard_invalid_hash(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    guard = StateGuard(str(tmp_path))
    
    success = guard.rollback("invalid_hash_string_here_with_semicolon;")
    assert success is False
