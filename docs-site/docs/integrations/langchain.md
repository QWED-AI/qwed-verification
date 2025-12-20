---
sidebar_position: 1
---

# LangChain Integration

Use QWED with LangChain for verified AI chains and agents.

## Installation

```bash
pip install qwed-new langchain
```

## Quick Start

```python
from qwed_sdk.langchain import QWEDTool, QWEDVerificationCallback

# Add QWED as a tool
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI

agent = initialize_agent(
    tools=[QWEDTool()],
    llm=OpenAI(),
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
)

result = agent.run("Verify: Is 2+2 equal to 5?")
# Agent uses QWED tool to verify and corrects the answer
```

## Available Components

### QWEDTool

General-purpose verification tool:

```python
from qwed_sdk.langchain import QWEDTool

tool = QWEDTool(api_key="qwed_...")
print(tool.run("2+2=4"))
# ✅ VERIFIED: The statement is correct
```

### Specialized Tools

```python
from qwed_sdk.langchain import QWEDMathTool, QWEDLogicTool, QWEDCodeTool

tools = [
    QWEDMathTool(),   # Math expressions
    QWEDLogicTool(),  # QWED-Logic DSL
    QWEDCodeTool(),   # Code security
]
```

### QWEDVerificationCallback

Auto-verify all LLM outputs:

```python
from langchain.chains import LLMChain
from qwed_sdk.langchain import QWEDVerificationCallback

callback = QWEDVerificationCallback(
    verify_math=True,
    verify_code=True,
    log_results=True,
)

chain = LLMChain(
    llm=OpenAI(),
    prompt=prompt,
    callbacks=[callback]
)

result = chain.run("Calculate 15% of 200")
# [QWED] ✅ MATH: verified=True
```

### QWEDVerifiedChain

Wrap any chain with verification:

```python
from qwed_sdk.langchain import QWEDVerifiedChain

base_chain = LLMChain(llm=llm, prompt=prompt)
verified_chain = QWEDVerifiedChain(base_chain, auto_correct=True)

result = verified_chain.run("What is 2+2?")
print(result.output)    # "4"
print(result.verified)  # True
```

## LCEL Integration

Use with LangChain Expression Language:

```python
from langchain_core.runnables import RunnableLambda

def verify_output(text):
    from qwed_sdk import QWEDClient
    client = QWEDClient()
    result = client.verify(text)
    return text if result.verified else f"[UNVERIFIED] {text}"

chain = prompt | llm | RunnableLambda(verify_output)
```

## Best Practices

1. **Use callbacks for monitoring** — Track verification rates
2. **Use tools for agent autonomy** — Let agents verify themselves
3. **Use wrappers for guarantees** — Ensure all outputs are verified
