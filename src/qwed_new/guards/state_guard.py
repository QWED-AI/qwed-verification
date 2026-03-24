import os
import re
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class StateGuard:
    """
    Provides deterministic rollback capabilities for agentic file operations 
    using Shadow Git Snapshots. Ensures system integrity during agentic execution.
    """
    def __init__(self, workspace_path: str):
        self.workspace = Path(workspace_path).resolve()
        if not self.workspace.exists() or not self.workspace.is_dir():
            raise ValueError(f"Invalid workspace path: {self.workspace}")
            
        # Ensure we are operating inside a git repository
        if not (self.workspace / ".git").exists():
            raise RuntimeError(f"Workspace {self.workspace} is not a valid git repository. Shadow snapshots require git.")

        self.shadow_repo = Path.home() / ".qwed" / "shadow_snapshots"
        self.shadow_repo.mkdir(parents=True, exist_ok=True)

    def _is_valid_tree_hash(self, tree_hash: str) -> bool:
        """Validate the tree hash to prevent command line injection or bad references."""
        return bool(re.match(r"^[0-9a-f]{40}$", tree_hash))

    def create_pre_execution_snapshot(self) -> str:
        """Runs `git add . && git write-tree` to create a state snapshot before the agent acts."""
        try:
            # First, stage all changes to ensure they are hashed
            subprocess.run(
                ["git", "add", "."], 
                cwd=str(self.workspace), 
                check=True,
                capture_output=True
            )
            
            # Create an immutable state hash
            result = subprocess.run(
                ["git", "write-tree"], 
                cwd=str(self.workspace), 
                capture_output=True, 
                text=True,
                check=True
            )
            tree_hash = result.stdout.strip()
            
            if not self._is_valid_tree_hash(tree_hash):
                raise ValueError(f"Invalid tree hash generated: {tree_hash}")
                
            logger.info(f"Created pre-execution shadow snapshot: {tree_hash}")
            return tree_hash
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create shadow snapshot: {e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}")
            raise RuntimeError(f"Shadow Git Snapshot failed: {e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}") from e

    def rollback(self, tree_hash: str) -> bool:
        """Restores the exact state from a tree hash if QWED detects a post-execution failure."""
        if not self._is_valid_tree_hash(tree_hash):
            logger.error(f"Rollback aborted: Invalid tree hash format '{tree_hash}'")
            return False
            
        try:
            # Revert the working directory to the exact state of the tree hash
            # If things were staged but not committed, checkout tree-hash will overwrite
            # working tree safely.
            subprocess.run(
                ["git", "checkout", tree_hash, "--", "."], 
                cwd=str(self.workspace),
                check=True,
                capture_output=True
            )
            logger.warning(f"Successfully rolled back workspace to snapshot {tree_hash}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to rollback shadow snapshot {tree_hash}: {e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}")
            return False
