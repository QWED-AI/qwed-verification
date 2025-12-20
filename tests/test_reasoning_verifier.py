"""
Test Engine 8: Reasoning Verifier
Tests translation accuracy and cross-validation between GPT-4 and Claude.
"""

import asyncio
from qwed_new.core.reasoning_verifier import ReasoningVerifier
from qwed_new.core.translator import TranslationLayer

async def test_reasoning_verifier():
    print("🧠 Testing Engine 8: Reasoning Verifier\n")
    
    verifier = ReasoningVerifier()
    translator = TranslationLayer()
    
    test_cases = [
        {
            "name": "Clear Problem (Should Pass)",
            "query": "What is 15% of 200?",
            "expected_valid": True
        },
        {
            "name": "Ambiguous Problem (Complex Word Problem)",
            "query": "Sophie has 42 apples. She eats 7. Then buys 5 times as many as she has left. How many apples does she have?",
            "expected_valid": False  # Likely to have translation issues
        },
        {
            "name": "Missing Information",
            "query": "If I start with some apples and eat 5, how many do I have?",
            "expected_valid": False
        }
    ]
    
    for test in test_cases:
        print(f"\n{'='*60}")
        print(f"Test: {test['name']}")
        print(f"Query: {test['query']}")
        print("-" * 60)
        
        try:
            # Translate the query
            task = translator.translate(test['query'])
            print(f"Primary Formula (GPT-4): {task.expression}")
            
            # Validate reasoning
            result = verifier.verify_understanding(
                query=test['query'],
                primary_task=task,
                enable_cross_validation=True
            )
            
            print(f"\n✓ Validation Result:")
            print(f"  - Valid: {result.is_valid}")
            print(f"  - Confidence: {result.confidence:.2f}")
            print(f"  - Issues: {result.issues if result.issues else 'None'}")
            
            if result.alternative_formula:
                print(f"  - Alternative (Claude): {result.alternative_formula}")
                print(f"  - Formulas Match: {result.primary_formula == result.alternative_formula}")
            
            print(f"\n✓ Reasoning Trace:")
            for step in result.reasoning_trace[:3]:  # Show first 3 steps
                print(f"  - {step}")
            
            print(f"\n✓ Semantic Facts:")
            print(f"  - Numbers: {result.semantic_facts.get('numbers', [])}")
            print(f"  - Operations: {set(result.semantic_facts.get('operations', []))}")
            
            # Validate expectation
            status = "✅ PASS" if result.is_valid == test['expected_valid'] else "❌ UNEXPECTED"
            print(f"\n{status} (Expected valid={test['expected_valid']}, Got valid={result.is_valid})")
            
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print("✅ Reasoning Verifier Test Complete")

if __name__ == "__main__":
    asyncio.run(test_reasoning_verifier())
