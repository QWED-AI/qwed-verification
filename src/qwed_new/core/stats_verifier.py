import pandas as pd
import json
import logging
from typing import Optional, Dict, Any
from qwed_new.core.translator import TranslationLayer
from qwed_new.core.secure_code_executor import SecureCodeExecutor
from qwed_new.core.code_executor import CodeExecutor
from qwed_new.core.code_verifier import CodeVerifier

logger = logging.getLogger(__name__)


class StatsVerifier:
    """
    Engine 3: Statistical Verifier.
    Verifies claims about tabular data by generating and executing code.
    NOW USES DOCKER ISOLATION for enhanced security.
    Falls back to basic executor if Docker unavailable.
    """

    def __init__(self):
        self.translator = TranslationLayer()
        self.secure_executor = SecureCodeExecutor()
        self.basic_executor = CodeExecutor()  # Fallback
        self.code_verifier = CodeVerifier()
        
        # Check if Docker is available
        self.use_docker = self.secure_executor.is_available()
        if self.use_docker:
            logger.info("StatsVerifier: Using Docker-based secure execution")
        else:
            logger.warning("StatsVerifier: Docker unavailable, falling back to basic executor")

    def verify_stats(self, query: str, df: pd.DataFrame, provider: Optional[str] = None) -> Dict[str, Any]:
        """
        Verifies a statistical claim using secure Docker execution.

        Args:
            query: The user's question or claim (e.g., "Did sales increase?").
            df: The pandas DataFrame containing the data.
            provider: Optional LLM provider to use.

        Returns:
            dict: {
                "status": str,
                "result": Any,
                "code": str,
                "columns": list[str],
                "security_checks": dict
            }
        """
        # 1. Extract Schema
        columns = list(df.columns)

        # 2. Generate Code (LLM)
        try:
            code = self.translator.translate_stats(query, columns, provider=provider)
        except Exception as e:
            logger.error(f"Code generation failed: {e}")
            return {
                "status": "ERROR",
                "error": f"Code generation failed: {str(e)}",
                "columns": columns
            }

        # 3. Pre-execution Security Check
        security_result = self.code_verifier.verify_code(code, language="python")
        
        if not security_result["is_safe"]:
            logger.warning(f"Generated code failed security validation: {security_result['issues']}")
            return {
                "status": "BLOCKED",
                "error": "Generated code failed security validation",
                "issues": security_result["issues"],
                "code": code,
                "columns": columns
            }

        # 4. Execute code (Docker or fallback)
        if self.use_docker:
            return self._execute_with_docker(code, df, columns)
        else:
            return self._execute_with_fallback(code, df, columns)
    
    def _execute_with_docker(self, code: str, df: pd.DataFrame, columns: list) -> Dict[str, Any]:
        """Execute code in Docker sandbox."""
        # Convert DataFrame to serializable format for Docker
        context = {
            "df": df  # SecureCodeExecutor handles DataFrame serialization
        }

        # Execute Code in Docker Sandbox
        try:
            success, error, result = self.secure_executor.execute(code, context)
            
            if success:
                return {
                    "status": "SUCCESS",
                    "result": result,
                    "code": code,
                    "columns": columns,
                    "security_checks": {
                        "ast_validation": "PASSED",
                        "sandbox_isolation": "DOCKER",
                        "network_isolation": "ENABLED"
                    }
                }
            else:
                logger.error(f"Docker execution failed: {error}")
                return {
                    "status": "EXECUTION_FAILED",
                    "error": error,
                    "code": code,
                    "columns": columns
                }
        except Exception as e:
            logger.error(f"Docker execution exception: {e}")
            return {
                "status": "EXECUTION_ERROR",
                "error": str(e),
                "code": code,
                "columns": columns
            }
    
    def _execute_with_fallback(self, code: str, df: pd.DataFrame, columns: list) -> Dict[str, Any]:
        """Execute code with basic executor (fallback when Docker unavailable)."""
        logger.info("Using fallback executor (Docker unavailable)")
        
        try:
            result = self.basic_executor.execute(code, df)
            
            return {
                "status": "SUCCESS",
                "result": result,
                "code": code,
                "columns": columns,
                "security_checks": {
                    "ast_validation": "PASSED",
                    "sandbox_isolation": "BASIC",
                    "network_isolation": "DISABLED",
                    "warning": "Docker unavailable, using basic execution"
                }
            }
        except Exception as e:
            logger.error(f"Fallback execution failed: {e}")
            return {
                "status": "EXECUTION_FAILED",
                "error": str(e),
                "code": code,
                "columns": columns
            }
