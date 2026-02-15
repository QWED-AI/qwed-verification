
import re
from typing import List, Dict, Any, Optional

class ProcessVerifier:
    """
    Verifies the structural integrity and process adherence of AI reasoning.
    Moves verification from 'Black Box' (Output) to 'Glass Box' (Trace).
    """
    
    def __init__(self):
        # IRAC Patterns based on MSLR [Source 154, 163]
        self.irac_patterns = {
            "issue": r"(?i)(issue|question|problem presented)",
            "rule": r"(?i)(rule|law|statute|regulation|article \d+)",
            "application": r"(?i)(application|analysis|applying|in this case)",
            "conclusion": r"(?i)(conclusion|holding|verdict|therefore)"
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
            match = re.search(pattern, reasoning_trace)
            if match:
                matches[step] = True
            else:
                missing_steps.append(step)
        
        # Calculate score (0.0 to 1.0)
        # 4 steps total
        score = (4 - len(missing_steps)) / 4.0
        
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
                "process_rate": 1.0,
                "missed_milestones": []
            }
            
        found_milestones = [kw for kw in key_middle if kw.lower() in text.lower()]
        process_rate = len(found_milestones) / len(key_middle)
        
        return {
            "verified": process_rate == 1.0,
            "process_rate": process_rate,
            "missed_milestones": list(set(key_middle) - set(found_milestones))
        }
