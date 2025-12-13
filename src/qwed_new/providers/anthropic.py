"""
Anthropic Provider Implementation.
"""

import os
import json
from typing import Dict, Any, List
from anthropic import AnthropicFoundry
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.providers.base import LLMProvider

class AnthropicProvider(LLMProvider):
    """
    Provider for Anthropic Claude (via Azure AI Foundry).
    Uses "tool use" (function calling) to force structured output.
    """
    
    def __init__(self):
        # Anthropic via Azure AI Foundry
        self.endpoint = os.getenv("ANTHROPIC_ENDPOINT")
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.deployment = os.getenv("ANTHROPIC_DEPLOYMENT", "claude-sonnet-4-5")
        
        if not all([self.endpoint, self.api_key, self.deployment]):
            raise ValueError("Missing Anthropic environment variables")
            
        self.client = AnthropicFoundry(
            api_key=self.api_key,
            base_url=self.endpoint,
        )
        
        # Anthropic tool definition
        self.tool_schema = {
            "name": "submit_math_expression",
            "description": "Submit a mathematical expression and its calculated result.",
            "input_schema": MathVerificationTask.model_json_schema()
        }
    
    def translate(self, user_query: str) -> MathVerificationTask:
        system_prompt = """You are a mathematical expression translator.
Convert natural language math questions into formal mathematical expressions.
Rules:
1. Use Python math syntax
2. Do NOT use variable names (except constants)
3. Convert percentages to decimals
4. Always calculate the numerical answer
You MUST use the submit_math_expression tool."""
        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_query}
                ],
                tools=[self.tool_schema],
                tool_choice={"type": "tool", "name": "submit_math_expression"},
                temperature=0.0,
            )
            # We look for content blocks of type 'tool_use'
            tool_use = next((block for block in response.content if block.type == "tool_use"), None)
            
            if not tool_use:
                raise ValueError("Claude did not use the required tool")
            
            # tool_use.input is already a dictionary (Anthropic SDK parses JSON automatically)
            return MathVerificationTask(**tool_use.input)
            
        except Exception as e:
            raise ValueError(f"Anthropic translation failed: {str(e)}")

    def translate_logic_dsl(self, user_query: str) -> Dict[str, Any]:
        """
        Translate natural language to QWED-DSL format for secure Z3 verification.
        
        This method uses the new DSL format which is:
        - More secure (whitelist-based parsing, no eval())
        - More reliable (constrained format LLMs can generate correctly)
        - Easier to validate (S-expression structure)
        
        Returns:
            Dict with 'dsl_code' (the S-expression string) and 'variables'
        """
        tool_schema = {
            "name": "submit_qwed_logic",
            "description": "Submit a logic problem in QWED-Logic format (S-expressions).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "dsl_code": {
                        "type": "string",
                        "description": "The constraint in QWED-Logic S-expression format. Example: (AND (GT x 5) (LT y 10))"
                    },
                    "variables": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "type": {"type": "string", "enum": ["Int", "Bool", "Real"]}
                            }
                        },
                        "description": "List of variables with their types"
                    }
                },
                "required": ["dsl_code", "variables"]
            }
        }

        system_prompt = """You are a Logic Translator for the QWED Verification Protocol.
Your goal is to translate natural language claims into QWED-Logic format (S-Expressions).

1. OUTPUT FORMAT:
   - You must output valid S-Expressions ONLY.
   - All expressions must be enclosed in parentheses `(...)`.
   - NO Python code. NO Markdown backticks. NO Explanations.

2. GRAMMAR (Strict Whitelist):
   - Logic: (AND ...), (OR ...), (NOT ...), (IMPLIES a b), (IFF a b), (XOR a b)
   - Comparison: (EQ a b), (NEQ a b), (GT a b), (LT a b), (GTE a b), (LTE a b)
   - Math: (PLUS ...), (MINUS ...), (MULT ...), (DIV ...), (POW a b), (MOD a b)
   - Quantifiers: (FORALL x (expr)), (EXISTS x (expr))
   - Variables: Use string names for variables (e.g., 'x', 'total_cost', 'is_valid').

3. EXAMPLES:
   User: "If x is greater than 5 and y is less than 10, then z must be true."
   Output: (IMPLIES (AND (GT x 5) (LT y 10)) (EQ z True))

   User: "Everyone is happy."
   Output: (FORALL p (EQ (status p) happy))

   User: "Access is denied unless the user is admin."
   Output: (IFF (EQ access denied) (NOT (EQ user admin)))

   User: "Find x and y where x > y and x + y = 10."
   Output: (AND (GT x y) (EQ (PLUS x y) 10))

4. VARIABLES:
   - Infer variable types from context.
   - For numbers, use numeric literals directly.
   - For string comparisons, use unquoted identifiers.

BEGIN TRANSLATION.
"""

        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_query}],
                tools=[tool_schema],
                tool_choice={"type": "tool", "name": "submit_qwed_logic"},
                temperature=0.0,
            )
            
            tool_use = next((block for block in response.content if block.type == "tool_use"), None)
            if not tool_use:
                raise ValueError("Claude did not use the required tool")
            
            args_dict = tool_use.input
            print(f"DEBUG: Claude DSL Args: {args_dict}")
            
            return {
                "dsl_code": args_dict.get("dsl_code", ""),
                "variables": args_dict.get("variables", [])
            }
            
        except Exception as e:
            raise ValueError(f"Anthropic DSL translation failed: {str(e)}")

    def translate_logic(self, user_query: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask
        
        tool_schema = {
            "name": "submit_z3_problem_v2",
            "description": "Submit a logic or constraint satisfaction problem.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "vars_map": {
                        "type": "object",
                        "description": "Map of variable names to types (Int, Bool, Real). Example: {'x': 'Int'}",
                        "additionalProperties": {"type": "string"}
                    },
                    "constraints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of constraints in Python syntax"
                    },
                    "goal": {
                    }
                },
                "required": ["vars_map", "constraints"]
            }
        }
        
        system_prompt = """You are a Logic Translator for the Z3 Theorem Prover.
Convert natural language logic puzzles into variables and constraints.

CRITICAL: You MUST return a JSON object with EXACTLY these 3 fields:
1. "vars_map": A dictionary mapping names to types (e.g., {"x": "Int", "y": "Int", "P": "Bool"}). THIS IS REQUIRED.
2. "constraints": A list of Python boolean expressions. NO ASSIGNMENTS ('='). Use '==' for equality.
   - DO NOT use lists or arrays (e.g., "Houses = [1,2,3]" is INVALID). Use individual variables.
   - Use 'Bool' type for boolean logic puzzles.
   - Map categorical values to Integers (e.g., Red=1, Blue=2). DO NOT compare variables to strings.
   - USE `And(...)`, `Or(...)`, `Not(...)` for logic. DO NOT use `&`, `|`, `~`.
3. "goal": "SATISFIABILITY".
"""

        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_query}],
                tools=[tool_schema],
                tool_choice={"type": "tool", "name": "submit_z3_problem_v2"},
                temperature=0.0,
            )
            
            tool_use = next((block for block in response.content if block.type == "tool_use"), None)
            if not tool_use:
                raise ValueError("Claude did not use the required tool")
            
            args_dict = tool_use.input
            if 'vars_map' in args_dict:
                args_dict['variables'] = args_dict.pop('vars_map')
        except Exception as e:
            raise ValueError(f"Anthropic logic translation failed: {str(e)}")

    def refine_logic(self, user_query: str, previous_error: str) -> 'LogicVerificationTask':
        from qwed_new.core.schemas import LogicVerificationTask
        
        tool_schema = {
            "name": "submit_z3_problem_v2",
            "description": "Submit a logic or constraint satisfaction problem.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "vars_map": {
                        "type": "object",
                        "description": "Map of variable names to types (Int, Bool, Real). Example: {'x': 'Int'}",
                        "additionalProperties": {"type": "string"}
                    },
                    "constraints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of constraints in Python syntax"
                    },
                    "goal": {
                        "type": "string",
                        "description": "Goal of the problem",
                        "default": "SATISFIABILITY"
                    }
                },
                "required": ["vars_map", "constraints"]
            }
        }

        system_prompt = f"""You are a Logic Translator for the Z3 Theorem Prover.
You previously made a mistake. Please fix it based on the error message.

Error: "{previous_error}"

CRITICAL: You MUST return a JSON object with EXACTLY these 3 fields:
1. "vars_map": A dictionary mapping names to types.
2. "constraints": A list of Python boolean expressions. NO ASSIGNMENTS ('='). Use '==' for equality.
   - DO NOT use lists or arrays.
   - Use 'Bool' type for boolean logic puzzles.
   - Map categorical values to Integers.
   - USE `And(...)`, `Or(...)`, `Not(...)` for logic. DO NOT use `&`, `|`, `~`.
3. "goal": "SATISFIABILITY".
"""

        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_query}],
                tools=[tool_schema],
                tool_choice={"type": "tool", "name": "submit_z3_problem_v2"},
                temperature=0.0,
            )
            
            tool_use = next((block for block in response.content if block.type == "tool_use"), None)
            if not tool_use:
                raise ValueError("Claude did not use the required tool during refinement")
            
            args_dict = tool_use.input
            if 'vars_map' in args_dict:
                args_dict['variables'] = args_dict.pop('vars_map')
                
            return LogicVerificationTask(**args_dict)
            
        except Exception as e:
            raise ValueError(f"Anthropic logic refinement failed: {str(e)}")

    def translate_stats(self, query: str, columns: list[str]) -> str:
        """
        Generate Python code to verify a statistical claim about a dataset.
        """
        system_prompt = """
        You are a Python Data Science Expert.
        Your job is to write Python code using Pandas to verify a claim about a dataset.
        
        The dataset is loaded into a DataFrame named `df`.
        The columns are provided.
        
        Write a script that:
        1. Calculates the answer to the query.
        2. Assigns the final result to a variable named `result`.
        3. Does NOT use any external libraries other than `pandas`, `numpy`, `scipy`, `math`.
        4. Does NOT read any files (df is already loaded).
        
        Output ONLY the Python code. No markdown, no explanations.
        """
        
        user_prompt = f"""
        Columns: {columns}
        Query: {query}
        
        Write the Python code.
        """
        
        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": f"<user_query>{user_prompt}</user_query>"}
                ],
                temperature=0.0
            )
            
            content = response.content[0].text
            # Clean markdown
            if "```python" in content:
                content = content.split("```python")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
                
            return content
            
        except Exception as e:
            print(f"Stats Translation Error: {e}")
            raise

    def verify_fact(self, claim: str, context: str) -> dict:
        """
        Verify a claim against a context using citation-based checking.
        """
        tool_schema = {
            "name": "submit_fact_verification",
            "description": "Submit verification result for a claim.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["SUPPORTED", "REFUTED", "NOT_ENOUGH_INFO"]},
                    "reasoning": {"type": "string"},
                    "citations": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["verdict", "reasoning", "citations"]
            }
        }
        
        system_prompt = """
        You are a Fact Checking Engine.
        Your job is to verify a Claim against a provided Context.
        
        Rules:
        1. You must find EXACT QUOTES from the Context to support your verdict.
        2. If the Claim is fully supported by the Context, return "SUPPORTED".
        3. If the Claim contradicts the Context, return "REFUTED".
        4. If the Context does not contain enough info, return "NOT_ENOUGH_INFO".
        5. Do NOT make logical inferences beyond stated facts. Be conservative.
        
        You MUST use the submit_fact_verification tool.
        """
        
        user_prompt = f"""
        Context:
        {context}
        
        Claim:
        {claim}
        """
        
        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                tools=[tool_schema],
                tool_choice={"type": "tool", "name": "submit_fact_verification"},
                temperature=0.0,
            )
            
            tool_use = next((block for block in response.content if block.type == "tool_use"), None)
            if not tool_use:
                raise ValueError("Claude did not use the required tool")
                
            return tool_use.input
            
        except Exception as e:
            raise ValueError(f"Anthropic fact verification failed: {str(e)}")

    def verify_image(self, image_bytes: bytes, claim: str) -> dict:
        """
        Verify a claim against an image using Claude 3.5 Sonnet Vision.
        """
        import base64
        
        # Encode image
        base64_image = base64.b64encode(image_bytes).decode('utf-8')
        
        tool_schema = {
            "name": "submit_image_verification",
            "description": "Submit verification result for an image claim.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["SUPPORTED", "REFUTED", "NOT_ENOUGH_INFO"]},
                    "reasoning": {"type": "string"},
                    "confidence": {"type": "number"}
                },
                "required": ["verdict", "reasoning", "confidence"]
            }
        }
        
        system_prompt = """
        You are an Image Verification Engine.
        Your goal is to verify if a CLAIM is supported by the provided IMAGE.
        
        Rules:
        1. Analyze the image carefully (charts, text, objects).
        2. If the image evidence supports the claim, return SUPPORTED.
        3. If the image evidence contradicts the claim, return REFUTED.
        4. If the image is unclear or irrelevant, return NOT_ENOUGH_INFO.
        
        You MUST use the submit_image_verification tool.
        """
        
        try:
            response = self.client.messages.create(
                model=self.deployment,
                max_tokens=1024,
                system=system_prompt,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/jpeg",
                                    "data": base64_image
                                }
                            },
                            {
                                "type": "text",
                                "text": f"CLAIM: {claim}"
                            }
                        ]
                    }
                ],
                tools=[tool_schema],
                tool_choice={"type": "tool", "name": "submit_image_verification"},
                temperature=0.0,
            )
            
            tool_use = next((block for block in response.content if block.type == "tool_use"), None)
            if not tool_use:
                raise ValueError("Claude did not use the required tool")
                
            return tool_use.input
            
        except Exception as e:
            print(f"Error in verify_image: {e}")
            return {"verdict": "ERROR", "reasoning": str(e), "confidence": 0.0}
