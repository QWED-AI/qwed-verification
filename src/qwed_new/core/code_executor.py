import pandas as pd
import numpy as np
import scipy
import math
import io
import contextlib

class CodeExecutor:
    """
    Safely executes generated Python code for statistical analysis.
    Restricts imports and system access.
    """
    
    ALLOWED_GLOBALS = {
        "pd": pd,
        "np": np,
        "scipy": scipy,
        "math": math,
        "print": print,
        "len": len,
        "sum": sum,
        "max": max,
        "min": min,
        "abs": abs,
        "round": round,
        "list": list,
        "dict": dict,
        "set": set,
        "tuple": tuple,
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
    }

    def execute(self, code: str, df: pd.DataFrame = None) -> str:
        """
        Executes the provided code with the DataFrame `df` in context.
        The code is expected to define a function `verify_claim(df)` or simply run and print/return something.
        
        For this implementation, we expect the code to print the result or assign it to a variable named `result`.
        """
        
        # Capture stdout
        output_buffer = io.StringIO()
        
        # Execution context
        local_scope = {"df": df if df is not None else pd.DataFrame(), "result": None}
        
        try:
            with contextlib.redirect_stdout(output_buffer):
                exec(code, self.ALLOWED_GLOBALS, local_scope)
            
            # Check if 'result' variable was set
            if local_scope.get("result") is not None:
                return str(local_scope["result"])
            
            # Fallback to stdout
            output = output_buffer.getvalue().strip()
            if output:
                return output
                
            return "No result returned or printed."
            
        except Exception as e:
            return f"Execution Error: {str(e)}"
