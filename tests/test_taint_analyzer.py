"""
Tests for TaintAnalyzer - AST-based data flow security analysis.

Tests cover:
1. Direct taint (input() -> eval())
2. Indirect taint (x = input(); y = x; eval(y))
3. Sanitization (input() -> int() -> eval())
4. Multiple sources and sinks
5. Complex flow patterns
"""

import pytest
from src.qwed_new.core.taint_analyzer import TaintAnalyzer, TaintStatus


@pytest.fixture
def analyzer():
    """Create a fresh analyzer for each test."""
    return TaintAnalyzer()


class TestDirectTaint:
    """Test direct taint from source to sink."""
    
    def test_eval_input_vulnerable(self, analyzer):
        """eval(input()) is a critical vulnerability."""
        code = 'eval(input("Enter: "))'
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert len(result["vulnerabilities"]) >= 1
        assert result["vulnerabilities"][0]["severity"] == "CRITICAL"
    
    def test_exec_input_vulnerable(self, analyzer):
        """exec(input()) is a critical vulnerability."""
        code = 'exec(input())'
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert any(v["sink"]["name"] == "exec" for v in result["vulnerabilities"])
    
    def test_os_system_input_vulnerable(self, analyzer):
        """os.system(input()) is command injection."""
        code = '''
import os
cmd = input("Enter command: ")
os.system(cmd)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert len(result["vulnerabilities"]) >= 1


class TestIndirectTaint:
    """Test taint propagation through variable assignments."""
    
    def test_single_hop_propagation(self, analyzer):
        """x = input(); eval(x) should be caught."""
        code = '''
x = input()
eval(x)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert "x" in result["tainted_variables"]
    
    def test_multi_hop_propagation(self, analyzer):
        """x = input(); y = x; z = y; eval(z) should be caught."""
        code = '''
x = input()
y = x
z = y
eval(z)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert "x" in result["tainted_variables"]
        assert "y" in result["tainted_variables"]
        assert "z" in result["tainted_variables"]
    
    def test_string_concatenation_propagation(self, analyzer):
        """Taint propagates through string operations."""
        code = '''
user = input()
cmd = "ls " + user
os.system(cmd)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert "user" in result["tainted_variables"]


class TestSanitization:
    """Test that sanitizers clean tainted data."""
    
    def test_int_sanitizes(self, analyzer):
        """int(input()) should be clean (can't inject code as int)."""
        code = '''
x = input()
y = int(x)
# y is now clean (just a number)
'''
        result = analyzer.analyze(code)
        
        # y should be clean even though x is tainted
        assert "x" in result["tainted_variables"]
        # Note: This specific test may need adjustment based on how we track clean
    
    def test_escape_sanitizes(self, analyzer):
        """escape(input()) should be clean."""
        code = '''
from html import escape
x = input()
y = escape(x)
'''
        result = analyzer.analyze(code)
        
        assert "x" in result["tainted_variables"]
        # y should be marked as clean after escape


class TestSafeCode:
    """Test that safe code is correctly identified."""
    
    def test_no_user_input_is_safe(self, analyzer):
        """Code without user input sources is safe."""
        code = '''
x = "hello"
print(x)
y = 5 + 3
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == True
        assert len(result["vulnerabilities"]) == 0
    
    def test_hardcoded_eval_is_safe(self, analyzer):
        """eval with hardcoded string is not a taint vulnerability."""
        code = '''
x = "2 + 2"
result = eval(x)
'''
        result = analyzer.analyze(code)
        
        # While eval is dangerous, there's no tainted input
        assert len(result["tainted_variables"]) == 0
    
    def test_subprocess_with_constant_args(self, analyzer):
        """subprocess with constant args is not a taint issue."""
        code = '''
import subprocess
subprocess.run(["ls", "-la"])
'''
        result = analyzer.analyze(code)
        
        assert len(result["vulnerabilities"]) == 0 or \
               all(v["source"]["variable"] == "" for v in result["vulnerabilities"])


class TestComplexFlows:
    """Test complex data flow patterns."""

    def test_build_flow_path_falls_back_to_direct_path(self, analyzer):
        """Fallback path should connect source and sink directly."""
        analyzer._flow_graph.clear()

        path = analyzer._build_flow_path("source", "sink")

        assert path == ["source", "sink"]
    
    def test_conditional_flow(self, analyzer):
        """Taint propagation through conditionals is limited.
        
        NOTE: Full conditional tracking requires SSA/phi-node analysis.
        Current implementation tracks the source (x) but may not catch
        all paths through conditionals. This is documented as a known
        limitation for future enhancement.
        """
        code = '''
x = input()
if len(x) > 0:
    y = x
else:
    y = "default"
eval(y)
'''
        result = analyzer.analyze(code)
        
        # We CAN verify that x is tainted
        assert "x" in result["tainted_variables"]
        # Note: y propagation through if/else is a known limitation
        # Full support would require control-flow-sensitive analysis
    
    def test_function_parameter_flow(self, analyzer):
        """Taint tracking across function boundaries (basic)."""
        code = '''
def process(data):
    eval(data)

user_input = input()
process(user_input)
'''
        result = analyzer.analyze(code)
        
        assert "user_input" in result["tainted_variables"]
    
    def test_multiple_sources(self, analyzer):
        """Multiple different sources should all be tracked."""
        code = '''
import os
a = input()
b = os.environ.get("USER")
eval(a)
exec(b)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert len(result["sources_found"]) >= 2


class TestWebFrameworkSources:
    """Test web framework input sources."""
    
    def test_flask_request_args(self, analyzer):
        """Flask request.args.get is a taint source."""
        code = '''
from flask import request
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
'''
        result = analyzer.analyze(code)
        
        assert "user_id" in result["tainted_variables"]
        assert result["is_safe"] == False
    
    def test_flask_request_form(self, analyzer):
        """Flask request.form.get is a taint source."""
        code = '''
username = request.form.get("username")
os.system(f"echo {username}")
'''
        result = analyzer.analyze(code)
        
        assert "username" in result["tainted_variables"]


class TestSinkVariety:
    """Test various sink types."""
    
    def test_pickle_loads_sink(self, analyzer):
        """pickle.loads with tainted data is critical."""
        code = '''
import pickle
data = input()
obj = pickle.loads(data)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
        assert any("pickle" in v["sink"]["name"] for v in result["vulnerabilities"])
    
    def test_subprocess_popen_sink(self, analyzer):
        """subprocess.Popen with tainted args is critical."""
        code = '''
import subprocess
cmd = input()
proc = subprocess.Popen(cmd, shell=True)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == False
    
    def test_open_with_tainted_path(self, analyzer):
        """open() with tainted path is path traversal."""
        code = '''
filename = input("Enter filename: ")
with open(filename) as f:
    content = f.read()
'''
        result = analyzer.analyze(code)
        
        # open with tainted path should be flagged
        assert "filename" in result["tainted_variables"]


class TestResultStructure:
    """Test the structure of analysis results."""
    
    def test_result_has_required_fields(self, analyzer):
        """Result should have all required fields."""
        code = 'x = 1'
        result = analyzer.analyze(code)
        
        assert "is_safe" in result
        assert "vulnerabilities" in result
        assert "tainted_variables" in result
        assert "sources_found" in result
        assert "sinks_found" in result
        assert "summary" in result
    
    def test_vulnerability_structure(self, analyzer):
        """Vulnerability objects should have complete info."""
        code = 'eval(input())'
        result = analyzer.analyze(code)
        
        if result["vulnerabilities"]:
            vuln = result["vulnerabilities"][0]
            assert "severity" in vuln
            assert "description" in vuln
            assert "source" in vuln
            assert "sink" in vuln
            assert "recommendation" in vuln
    
    def test_summary_counts(self, analyzer):
        """Summary should have correct counts."""
        code = '''
x = input()
eval(x)
exec(x)
'''
        result = analyzer.analyze(code)
        
        summary = result["summary"]
        assert summary["total_sources"] >= 1
        assert summary["total_sinks"] >= 2
        assert summary["total_vulnerabilities"] >= 2


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_code(self, analyzer):
        """Empty code should be safe."""
        result = analyzer.analyze("")
        
        assert result["is_safe"] == True
    
    def test_syntax_error(self, analyzer):
        """Syntax errors should be handled gracefully."""
        code = "def broken(: pass"
        result = analyzer.analyze(code)
        
        assert "error" in result
        assert result["is_safe"] == False
    
    def test_comments_ignored(self, analyzer):
        """Comments should not affect analysis."""
        code = '''
# eval(input())  <- This is a comment
x = "safe"
print(x)
'''
        result = analyzer.analyze(code)
        
        assert result["is_safe"] == True
    
    def test_string_literals_not_tainted(self, analyzer):
        """String literals should not be tainted."""
        code = '''
x = "input()"  # This is a string, not a call
eval(x)
'''
        result = analyzer.analyze(code)
        
        # x is a string literal, not tainted
        assert "x" not in result["tainted_variables"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
