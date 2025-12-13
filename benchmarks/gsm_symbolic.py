"""
GSM-Symbolic Generator: Replicating Apple's "Illusion of Thinking" Methodology.

This module generates variations of math problems by:
1. Changing proper names (e.g., "Sophie" -> "Liam")
2. Changing numbers (e.g., "5 apples" -> "12 apples")
3. Adding "distractor" clauses that don't affect the math but confuse LLMs.

Reference: "GSM-Symbolic: Understanding the Limitations of Mathematical Reasoning in Large Language Models"
"""

import random
from typing import List, Dict, Any

class GSMSymbolicGenerator:
    def __init__(self):
        self.names = ["Sophie", "Liam", "Emma", "Noah", "Olivia", "William", "Ava", "James", "Isabella", "Oliver"]
        self.items = ["apples", "oranges", "bananas", "books", "pencils", "toys", "candies", "coins"]
        
        # Templates based on GSM8K style problems
        self.templates = [
            {
                "id": "gsm_001",
                "template": "{name} has {n1} {item}. They eat {n2} {item}. Then they buy {n3} times as many as they have left. How many {item} do they have now?",
                "formula": lambda n1, n2, n3: (n1 - n2) + (n3 * (n1 - n2)),
                "constraints": {"n1": (10, 50), "n2": (1, 9), "n3": (2, 5)} # n1 > n2
            },
            {
                "id": "gsm_002",
                "template": "{name} reads {n1} pages on Monday. On Tuesday, they read {n2} more pages than Monday. On Wednesday, they read twice as many as Tuesday. How many pages did they read in total?",
                "formula": lambda n1, n2, n3: n1 + (n1 + n2) + (2 * (n1 + n2)), # n3 is not used in formula but might be in distractor
                "constraints": {"n1": (10, 30), "n2": (5, 15), "n3": (0, 0)}
            }
        ]

    def generate_batch(self, batch_size: int = 10, include_distractors: bool = False) -> List[Dict[str, Any]]:
        """Generate a batch of variations."""
        dataset = []
        
        for _ in range(batch_size):
            template = random.choice(self.templates)
            
            # Generate variables
            name = random.choice(self.names)
            item = random.choice(self.items)
            
            n1 = random.randint(*template["constraints"]["n1"])
            n2 = random.randint(*template["constraints"]["n2"])
            # Ensure n1 > n2 for subtraction
            while n1 <= n2:
                n1 = random.randint(*template["constraints"]["n1"])
                
            n3 = random.randint(*template["constraints"]["n3"])
            
            # Calculate ground truth
            answer = template["formula"](n1, n2, n3)
            
            # Format query
            query = template["template"].format(name=name, item=item, n1=n1, n2=n2, n3=n3)
            
            # Add distractor (Apple's key insight)
            if include_distractors:
                distractors = [
                    f" {name} also likes {random.choice(self.items)}.",
                    f" It was a sunny day.",
                    f" {name}'s friend gave them 0 {item}.", # Numeric distractor
                    f" They thought about buying {random.randint(1,5)} more but didn't."
                ]
                # Insert distractor before the question
                parts = query.split(". ")
                parts.insert(-1, random.choice(distractors).strip())
                query = ". ".join(parts)

            dataset.append({
                "id": f"{template['id']}_{random.randint(1000,9999)}",
                "domain": "math",
                "query": query,
                "expected_answer": float(answer),
                "complexity": "distractor" if include_distractors else "standard"
            })
            
        return dataset

if __name__ == "__main__":
    # Test generator
    gen = GSMSymbolicGenerator()
    batch = gen.generate_batch(batch_size=3, include_distractors=True)
    for item in batch:
        print(f"Q: {item['query']}")
        print(f"A: {item['expected_answer']}\n")
