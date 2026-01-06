#!/bin/bash
set -e

# GitHub Action entrypoint for QWED

# Build command based on inputs
CMD="qwed verify \"$QWED_QUERY\""

# Add provider
if [ -n "$QWED_PROVIDER" ]; then
    CMD="$CMD --provider $QWED_PROVIDER"
fi

# Add model
if [ -n "$QWED_MODEL" ]; then
    CMD="$CMD --model $QWED_MODEL"
fi

# Add PII masking
if [ "$QWED_MASK_PII" = "true" ]; then
    CMD="$CMD --mask-pii"
fi

# Set API key as environment variable
if [ -n "$QWED_API_KEY" ]; then
    export OPENAI_API_KEY="$QWED_API_KEY"
    export ANTHROPIC_API_KEY="$QWED_API_KEY"
fi

# Run verification and capture output
echo "🔬 Running QWED verification..."
OUTPUT=$(eval $CMD)

echo "$OUTPUT"

# Parse output and set GitHub Action outputs
# Extract verification result
if echo "$OUTPUT" | grep -q "✅ VERIFIED"; then
    echo "verified=true" >> $GITHUB_OUTPUT
elif echo "$OUTPUT" | grep -q "❌"; then
    echo "verified=false" >> $GITHUB_OUTPUT
else
    echo "verified=false" >> $GITHUB_OUTPUT
fi

# Try to extract value and confidence (this is simplified)
# In production, you'd want to use JSON output
echo "value=See verification output above" >> $GITHUB_OUTPUT
echo "confidence=1.0" >> $GITHUB_OUTPUT
