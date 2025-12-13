"""
Test Data Cleanup and Management Utilities
Helpers for managing test data, temporary files, and cleanup
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional
import json
from datetime import datetime, timedelta


class TestDataManager:
    """Manage test data and cleanup"""
    
    def __init__(self, base_dir: str = "./test_results"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def cleanup_old_reports(self, days_old: int = 7) -> int:
        """
        Remove test reports older than specified days
        
        Args:
            days_old: Remove reports older than this many days
        
        Returns:
            Number of files removed
        """
        cutoff_date = datetime.now() - timedelta(days=days_old)
        removed_count = 0
        
        for file_path in self.base_dir.glob("qwed_test_report_*"):
            if file_path.is_file():
                file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_time < cutoff_date:
                    file_path.unlink()
                    removed_count += 1
        
        return removed_count
    
    def get_latest_report(self, format: str = "json") -> Optional[Path]:
        """
        Get the most recent test report of given format
        
        Args:
            format: Report format (json, html, markdown)
        
        Returns:
            Path to latest report or None
        """
        ext = f".{format}" if format != "markdown" else ".md"
        reports = list(self.base_dir.glob(f"qwed_test_report_*{ext}"))
        
        if not reports:
            return None
        
        # Sort by modification time (newest first)
        reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return reports[0]
    
    def archive_reports(self, archive_dir: str = "./test_archives") -> int:
        """
        Move old reports to archive directory
        
        Args:
            archive_dir: Directory to archive reports to
        
        Returns:
            Number of files archived
        """
        archive_path = Path(archive_dir)
        archive_path.mkdir(parents=True, exist_ok=True)
        
        archived_count = 0
        cutoff_date = datetime.now() - timedelta(days=1)
        
        for file_path in self.base_dir.glob("qwed_test_report_*"):
            if file_path.is_file():
                file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_time < cutoff_date:
                    dest = archive_path / file_path.name
                    shutil.move(str(file_path), str(dest))
                    archived_count += 1
        
        return archived_count
    
    def get_report_summary(self) -> dict:
        """
        Get summary of available reports
        
        Returns:
            Dictionary with report counts by format
        """
        return {
            "json": len(list(self.base_dir.glob("*.json"))),
            "html": len(list(self.base_dir.glob("*.html"))),
            "markdown": len(list(self.base_dir.glob("*.md"))),
            "total": len(list(self.base_dir.glob("qwed_test_report_*")))
        }
    
    def cleanup_all(self) -> int:
        """
        Remove all test reports
        
        Returns:
            Number of files removed
        """
        removed_count = 0
        
        for file_path in self.base_dir.glob("qwed_test_report_*"):
            if file_path.is_file():
                file_path.unlink()
                removed_count += 1
        
        return removed_count


class TempFileManager:
    """Manage temporary files for tests"""
    
    def __init__(self):
        self.temp_files: List[Path] = []
    
    def create_temp_file(self, content: str, suffix: str = ".py") -> Path:
        """
        Create a temporary file with given content
        
        Args:
            content: File content
            suffix: File extension
        
        Returns:
            Path to created file
        """
        import tempfile
        fd, path = tempfile.mkstemp(suffix=suffix, text=True)
        
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        
        temp_path = Path(path)
        self.temp_files.append(temp_path)
        return temp_path
    
    def cleanup(self):
        """Remove all temporary files created"""
        for file_path in self.temp_files:
            if file_path.exists():
                file_path.unlink()
        
        self.temp_files.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


def generate_test_code(vulnerability_type: str = "eval") -> str:
    """
    Generate test code with specific vulnerability
    
    Args:
        vulnerability_type: Type of vulnerability to include
    
    Returns:
        Code string with vulnerability
    """
    templates = {
        "eval": '''
user_input = input("Enter code: ")
result = eval(user_input)
print(result)
''',
        "pickle": '''
import pickle
data = input("Enter pickled data: ")
obj = pickle.loads(data.encode())
''',
        "sql_injection": '''
import sqlite3
username = input("Username: ")
query = f"SELECT * FROM users WHERE name='{username}'"
conn.execute(query)
''',
        "command_injection": '''
import subprocess
filename = input("Filename: ")
subprocess.run(["cat", filename], shell=True)
''',
        "path_traversal": '''
filepath = input("File to read: ")
with open(filepath, 'r') as f:
    content = f.read()
''',
        "xxe": '''
import xml.etree.ElementTree as ET
xml_data = input("XML: ")
tree = ET.fromstring(xml_data)
'''
    }
    
    return templates.get(vulnerability_type, templates["eval"])


def compare_test_results(report1_path: str, report2_path: str) -> dict:
    """
    Compare two test reports and show differences
    
    Args:
        report1_path: Path to first JSON report
        report2_path: Path to second JSON report
    
    Returns:
        Dictionary with comparison results
    """
    with open(report1_path, 'r') as f:
        report1 = json.load(f)
    
    with open(report2_path, 'r') as f:
        report2 = json.load(f)
    
    summary1 = report1.get('summary', {})
    summary2 = report2.get('summary', {})
    
    return {
        "total_tests_change": summary2.get('total_tests', 0) - summary1.get('total_tests', 0),
        "pass_rate_change": summary2.get('pass_rate', 0) - summary1.get('pass_rate', 0),
        "new_failures": summary2.get('failed', 0) - summary1.get('failed', 0),
        "report1_date": summary1.get('timestamp'),
        "report2_date": summary2.get('timestamp')
    }
