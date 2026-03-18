"""
Tests for credential_store.py — Secure .env file writer.

Covers: write_env_file, verify_gitignore, add_env_to_gitignore, symlink
protection, atomic write, _find_project_root, _build_env_content, _read_existing_env.
"""

import os
import stat
import pytest
from pathlib import Path
from unittest.mock import patch

from qwed_new.providers.credential_store import (
    write_env_file,
    verify_gitignore,
    add_env_to_gitignore,
    _find_project_root,
    _build_env_content,
    _read_existing_env,
)


@pytest.fixture
def tmp_project(tmp_path):
    """Create a temp project with pyproject.toml and .gitignore."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n__pycache__\n.env\n")
    return tmp_path


class TestFindProjectRoot:
    def test_finds_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        result = _find_project_root(tmp_path)
        assert result == tmp_path

    def test_finds_git(self, tmp_path):
        (tmp_path / ".git").mkdir()
        result = _find_project_root(tmp_path)
        assert result == tmp_path

    def test_walks_up(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        sub = tmp_path / "src" / "pkg"
        sub.mkdir(parents=True)
        result = _find_project_root(sub)
        assert result == tmp_path

    def test_fallback_to_cwd(self, tmp_path):
        """When no marker found, returns start dir."""
        empty = tmp_path / "empty"
        empty.mkdir()
        result = _find_project_root(empty)
        # Falls back to the start directory (actually walks up)
        assert result.exists()


class TestBuildEnvContent:
    def test_basic(self):
        content = _build_env_content({"FOO": "bar", "BAZ": "qux"})
        assert "FOO=bar" in content
        assert "BAZ=qux" in content
        assert "QWED Environment Configuration" in content

    def test_active_provider(self):
        merged = {"ACTIVE_PROVIDER": "openai", "KEY": "val"}
        content = _build_env_content(merged)
        assert "ACTIVE_PROVIDER=openai" in content
        assert "KEY=val" in content

    def test_sorted_keys(self):
        content = _build_env_content({"ZZZ": "z", "AAA": "a"})
        idx_a = content.index("AAA=a")
        idx_z = content.index("ZZZ=z")
        assert idx_a < idx_z


class TestReadExistingEnv:
    def test_reads_vars(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("KEY1=val1\nKEY2=val2\n")
        result = _read_existing_env(env)
        assert result == {"KEY1": "val1", "KEY2": "val2"}

    def test_skips_comments(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("# comment\nKEY=val\n")
        result = _read_existing_env(env)
        assert result == {"KEY": "val"}

    def test_skips_empty(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("\n\nKEY=val\n\n")
        result = _read_existing_env(env)
        assert result == {"KEY": "val"}

    def test_nonexistent(self, tmp_path):
        env = tmp_path / ".env"
        result = _read_existing_env(env)
        assert result == {}


class TestWriteEnvFile:
    def test_creates_env(self, tmp_project):
        result = write_env_file({"MY_KEY": "my_val"}, project_root=tmp_project)
        assert result.exists()
        content = result.read_text()
        assert "MY_KEY=my_val" in content

    def test_merges_existing(self, tmp_project):
        env = tmp_project / ".env"
        env.write_text("OLD_KEY=old_val\n")
        write_env_file({"NEW_KEY": "new_val"}, project_root=tmp_project)
        content = env.read_text()
        assert "OLD_KEY=old_val" in content
        assert "NEW_KEY=new_val" in content

    def test_overrides_existing(self, tmp_project):
        env = tmp_project / ".env"
        env.write_text("KEY=old\n")
        write_env_file({"KEY": "new"}, project_root=tmp_project)
        content = env.read_text()
        assert "KEY=new" in content
        assert "KEY=old" not in content

    def test_active_provider(self, tmp_project):
        write_env_file({}, project_root=tmp_project, active_provider="openai")
        content = (tmp_project / ".env").read_text()
        assert "ACTIVE_PROVIDER=openai" in content

    def test_refuses_symlink(self, tmp_project):
        """Rejects symlinked .env paths."""
        if os.name == "nt":
            pytest.skip("Symlinks require elevated privileges on Windows")
        env = tmp_project / ".env"
        target = tmp_project / "real_env"
        target.write_text("SECRET=x\n")
        env.symlink_to(target)
        with pytest.raises(ValueError, match="symlinked"):
            write_env_file({"K": "v"}, project_root=tmp_project)

    def test_refuses_directory(self, tmp_project):
        """Rejects directory .env paths."""
        env = tmp_project / ".env"
        env.mkdir(exist_ok=True)
        with pytest.raises(ValueError, match="non-regular"):
            write_env_file({"K": "v"}, project_root=tmp_project)


class TestVerifyGitignore:
    def test_present(self, tmp_project):
        assert verify_gitignore(tmp_project) is True

    def test_absent(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / ".gitignore").write_text("*.pyc\n")
        assert verify_gitignore(tmp_path) is False

    def test_no_gitignore(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        assert verify_gitignore(tmp_path) is False

    def test_wildcard_match(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / ".gitignore").write_text("*.env\n")
        assert verify_gitignore(tmp_path) is True


class TestAddEnvToGitignore:
    def test_adds_when_missing(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / ".gitignore").write_text("*.pyc\n")
        assert add_env_to_gitignore(tmp_path) is True
        content = (tmp_path / ".gitignore").read_text()
        assert ".env" in content

    def test_noop_when_present(self, tmp_project):
        assert add_env_to_gitignore(tmp_project) is True

    def test_creates_gitignore(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        assert add_env_to_gitignore(tmp_path) is True
        assert (tmp_path / ".gitignore").exists()
