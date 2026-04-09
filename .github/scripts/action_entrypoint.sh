#!/bin/bash
set -e

# GitHub Action entrypoint for QWED

# Build command based on inputs using an array to avoid eval
ACTION="${QWED_ACTION:-${INPUT_ACTION:-verify}}"
QUERY="${QWED_QUERY:-${INPUT_QUERY:-}}"
if [ "$ACTION" = "verify" ] && [ -z "$QUERY" ]; then
  echo "::error::Missing query input. Set inputs.query (or QWED_QUERY)."
  exit 1
fi
CMD=("qwed" "$ACTION")
if [ "$ACTION" = "verify" ]; then
  CMD+=("$QUERY")
fi

PROVIDER="${QWED_PROVIDER:-${INPUT_PROVIDER:-}}"
MODEL="${QWED_MODEL:-${INPUT_MODEL:-}}"
MASK_PII="${QWED_MASK_PII:-${INPUT_MASK_PII:-false}}"
API_KEY="${QWED_API_KEY:-${INPUT_API_KEY:-}}"

LLM_OUTPUT="${QWED_LLM_OUTPUT:-${INPUT_LLM_OUTPUT:-}}"
ENGINE="${QWED_ENGINE:-${INPUT_ENGINE:-math}}"
PATHS="${QWED_PATHS:-${INPUT_PATHS:-.}}"
OUTPUT_FORMAT="${QWED_OUTPUT_FORMAT:-${INPUT_OUTPUT_FORMAT:-text}}"
FAIL_ON_FINDINGS="${QWED_FAIL_ON_FINDINGS:-${INPUT_FAIL_ON_FINDINGS:-true}}"

# Add provider
if [ -n "$PROVIDER" ]; then
    CMD+=(--provider "$PROVIDER")
fi

# Add model
if [ -n "$MODEL" ]; then
    CMD+=(--model "$MODEL")
fi

# Add PII masking
if [ "$MASK_PII" = "true" ]; then
    CMD+=(--mask-pii)
fi

if [ "$ACTION" = "verify" ]; then
    if [ -n "$LLM_OUTPUT" ]; then
        CMD+=(--llm-output "$LLM_OUTPUT")
    fi
    if [ -n "$ENGINE" ]; then
        CMD+=(--engine "$ENGINE")
    fi
else
    # Non-verify actions
    if [ -n "$PATHS" ]; then
        CMD+=(--paths "$PATHS")
    fi
    if [ -n "$OUTPUT_FORMAT" ]; then
        CMD+=(--output-format "$OUTPUT_FORMAT")
    fi
    if [ "$FAIL_ON_FINDINGS" = "true" ]; then
        CMD+=(--fail-on-findings)
    fi
fi

# Set API key as environment variable
if [ -n "$API_KEY" ]; then
    export QWED_API_KEY="$API_KEY"
    case "$PROVIDER" in
        openai)    export OPENAI_API_KEY="$API_KEY" ;;
        anthropic) export ANTHROPIC_API_KEY="$API_KEY" ;;
        gemini)    export GOOGLE_API_KEY="$API_KEY" ;;
    esac
fi

# Run verification and capture output
echo "🔬 Running QWED verification..."
OUTPUT=$("${CMD[@]}") || CMD_EXIT=$?
CMD_EXIT=${CMD_EXIT:-0}

echo "$OUTPUT"

# Parse output and set GitHub Action outputs
if [ "$ACTION" = "verify" ]; then
    # Extract verification result
    if echo "$OUTPUT" | grep -q "✅ VERIFIED"; then
        echo "verified=true" >> "$GITHUB_OUTPUT"
    elif echo "$OUTPUT" | grep -q "❌"; then
        echo "verified=false" >> "$GITHUB_OUTPUT"
    else
        echo "verified=false" >> "$GITHUB_OUTPUT"
    fi
else
    # Rely on process exit code for other tools
    if [ "$CMD_EXIT" -eq 0 ]; then
        echo "verified=true" >> "$GITHUB_OUTPUT"
    else
        echo "verified=false" >> "$GITHUB_OUTPUT"
    fi
fi

# Try to extract value and confidence (this is simplified)
# In production, you'd want to use JSON output
echo "value=See verification output above" >> $GITHUB_OUTPUT
echo "confidence=1.0" >> $GITHUB_OUTPUT
