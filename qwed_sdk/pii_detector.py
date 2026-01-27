from typing import List, Dict, Any, Tuple, Optional
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
except ImportError:
    AnalyzerEngine = None
    AnonymizerEngine = None

def check_pii_dependencies() -> bool:
    """Check if Presidio dependencies are available."""
    return AnalyzerEngine is not None and AnonymizerEngine is not None

class PIIDetector:
    """
    Microsoft Presidio-based PII detection and masking.
    Ensures sensitive data (Credit Cards, SSNs, Emails) is redacted before LLM calls.
    """
    
    DEFAULT_ENTITIES = [
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "PHONE_NUMBER",
        "US_SSN",
        "IBAN_CODE",
        "IP_ADDRESS",
        "PERSON",
        "LOCATION"
    ]
    
    def __init__(self, entities: Optional[List[str]] = None):
        """
        Initialize PII Detector.
        
        Args:
            entities: List of PII entity types to detect (default: broad set)
        """
        if AnalyzerEngine is None:
            raise ImportError(
                "Presidio not found. Install with: pip install presidio-analyzer presidio-anonymizer spacy && python -m spacy download en_core_web_lg"
            )
            
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.entities = entities or self.DEFAULT_ENTITIES
    
    def detect_and_mask(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Detect PII in text and return masked version + report.
        
        Args:
            text: Input text (e.g., prompt)
            
        Returns:
            Tuple[str, dict]: (masked_text, pii_report)
        """
        # 1. Analyze
        results = self.analyzer.analyze(
            text=text,
            entities=self.entities,
            language='en'
        )
        
        pii_count = len(results)
        detected_types = list(set([r.entity_type for r in results]))
        
        if pii_count == 0:
            return text, {"pii_detected": 0, "types": []}
        
        # 2. Anonymize (Mask)
        # We replace with <ENTITY_TYPE> to keep context for the LLM if possible, 
        # or simplified <REDACTED> if preferred. 
        # Here we use the entity type to allow the LLM to know *something* was there.
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL_ADDRESS>"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE_NUMBER>"}),
                "US_SSN": OperatorConfig("replace", {"new_value": "<US_SSN>"}),
                "IBAN_CODE": OperatorConfig("replace", {"new_value": "<IBAN_CODE>"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "<IP_ADDRESS>"}),
            }
        )
        
        return anonymized_result.text, {
            "pii_detected": pii_count,
            "types": detected_types,
            "items": [str(r) for r in results],
            "positions": [{"start": r.start, "end": r.end, "type": r.entity_type} for r in results]
        }
