"""
Evaluation Harness for QWED.

This script runs the test dataset against the active LLM provider
and calculates accuracy metrics.
"""

import json
import os
import time
from typing import List, Dict
from qwed_new.core.translator import TranslationLayer
from qwed_new.core.verifier import VerificationEngine
from qwed_new.core.validator import SemanticValidator

def load_dataset(path: str) -> List[Dict]:
    with open(path, 'r') as f:
        return json.load(f)

def evaluate():
    # Initialize components
    translator = TranslationLayer()
    validator = SemanticValidator()
    verifier = VerificationEngine()
    
    # Load dataset
    dataset_path = os.path.join(os.path.dirname(__file__), "tests", "dataset.json")
    dataset = load_dataset(dataset_path)
    
    print(f"🚀 Starting Evaluation on {len(dataset)} queries...")
    print(f"🤖 Active Provider: {translator.provider.__class__.__name__}")
    print("-" * 60)
    
    results = []
    passed = 0
    
    start_total = time.time()
    
    for item in dataset:
        print(f"Processing [{item['id']}] {item['category']}: {item['query']}")
        
        start_item = time.time()
        result_entry = {
            "id": item["id"],
            "query": item["query"],
            "expected": item["expected_answer"],
            "status": "FAILED",
            "actual": None,
            "latency": 0.0,
            "error": None
        }
        
        try:
            # 1. Translate
            task = translator.translate(item["query"])
            
            # 2. Validate
            validation = validator.validate(task.expression)
            if not validation["is_valid"]:
                result_entry["error"] = f"Validation Failed: {validation['error']}"
                print(f"  ❌ Validation Failed: {validation['error']}")
                results.append(result_entry)
                continue
                
            # 3. Verify
            verification = verifier.verify_math(task.expression, task.claimed_answer)
            
            # Check correctness against EXPECTED answer (ground truth), not just self-consistency
            # We allow a small tolerance for floating point comparison
            calculated_value = verification["calculated_value"]
            expected_value = item["expected_answer"]
            
            is_correct_ground_truth = abs(calculated_value - expected_value) < 1e-9
            
            result_entry["actual"] = calculated_value
            result_entry["latency"] = time.time() - start_item
            
            if is_correct_ground_truth:
                result_entry["status"] = "PASSED"
                passed += 1
                print(f"  ✅ PASSED (Got {calculated_value})")
            else:
                result_entry["status"] = "FAILED"
                result_entry["error"] = f"Incorrect result. Expected {expected_value}, got {calculated_value}"
                print(f"  ❌ FAILED (Expected {expected_value}, got {calculated_value})")
                
        except Exception as e:
            result_entry["error"] = str(e)
            print(f"  ❌ ERROR: {e}")
            
        results.append(result_entry)
        print("-" * 30)
        
    total_time = time.time() - start_total
    accuracy = (passed / len(dataset)) * 100
    avg_latency = sum(r["latency"] for r in results) / len(dataset)
    
    print("\n" + "=" * 60)
    print("📊 EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Total Queries: {len(dataset)}")
    print(f"Passed:        {passed}")
    print(f"Failed:        {len(dataset) - passed}")
    print(f"Accuracy:      {accuracy:.1f}%")
    print(f"Total Time:    {total_time:.2f}s")
    print(f"Avg Latency:   {avg_latency:.2f}s")
    print("=" * 60)
    
    # Save detailed results
    with open("evaluation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Detailed results saved to evaluation_results.json")

if __name__ == "__main__":
    evaluate()
