
import re
from decimal import Decimal
from typing import List, Dict, Any

class ProcessVerifier:
    """
    Verifies the structural integrity and process adherence of AI reasoning.
    Moves verification from 'Black Box' (Output) to 'Glass Box' (Trace).
    """
    
    def __init__(self):
        # IRAC Patterns based on MSLR [Source 154, 163]
        self.irac_patterns = {
            "issue": re.compile(r"\b(issue|question|problem presented)\b", re.I),
            "rule": re.compile(r"\b(rule|law|statute|regulation|article \d+)\b", re.I),
            "application": re.compile(r"\b(application|analysis|applying|in this case)\b", re.I),
            "conclusion": re.compile(r"\b(conclusion|holding|verdict|therefore)\b", re.I)
        }

    def verify_irac_structure(self, reasoning_trace: str) -> Dict[str, Any]:
        """
        Enforces 'Reasoned Elaboration' by checking for IRAC components.
        Source: MSLR Benchmark [Source 154].
        
        Args:
            reasoning_trace (str): The full text of the agent's reasoning.
            
        Returns:
            Dict[str, Any]: Verification result including score and missing steps.
        """
        missing_steps = []
        matches = {}
        
        for step, pattern in self.irac_patterns.items():
            match = pattern.search(reasoning_trace)
            if match:
                matches[step] = True
            else:
                missing_steps.append(step)
        
        # Calculate score (0 to 1) using Decimal for deterministic arithmetic
        score = Decimal(4 - len(missing_steps)) / Decimal(4)
        
        return {
            "verified": len(missing_steps) == 0,
            "score": score,
            "missing_steps": missing_steps,
            "mechanism": "Regex Pattern Matching (Deterministic)"
        }

    def verify_trace(self, text: str, key_middle: List[str]) -> Dict[str, Any]:
        """
        Calculates 'Process Rate' by verifying presence of intermediate milestones.
        Source: LegalAgentBench [Source 634, 649].
        
        Args:
            text (str): The reasoning text to check.
            key_middle (List[str]): List of required keywords/milestones.
            
        Returns:
            Dict[str, Any]: Verification result with process rate.
        """
        if not key_middle:
            return {
                "verified": True,
                "process_rate": Decimal(1),
                "missed_milestones": []
            }
            
        text_lc = text.lower()
        found_milestones = [
            kw for kw in key_middle 
            if re.search(rf"\b{re.escape(kw.lower())}\b", text_lc)
        ]
        process_rate = Decimal(len(found_milestones)) / Decimal(len(key_middle))

        return {
            "verified": process_rate == Decimal(1),
            "process_rate": process_rate,
            "missed_milestones": list(set(key_middle) - set(found_milestones))
        }
