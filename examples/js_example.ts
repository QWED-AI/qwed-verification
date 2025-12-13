/**
 * QWED JavaScript SDK Example
 * Run with: ts-node examples/js_example.ts
 */
import { QwedClient } from '../sdk/javascript/src';

// 1. Initialize Client
const client = new QwedClient("demo_key", "http://localhost:8000");

async function runExamples() {
    console.log("Running QWED Examples...\n");

    // Math Example
    console.log("--- Math Verification ---");
    const mathQuery = "What is 15% of 200?";
    console.log(`Query: ${mathQuery}`);

    try {
        const mathResult = await client.verifyNaturalLanguage(mathQuery);
        console.log(`Status: ${mathResult.status}`);
        console.log(`Answer: ${mathResult.final_answer}`);
    } catch (error) {
        console.error("Error:", error);
    }

    // Fact Example
    console.log("\n--- Fact Verification ---");
    const claim = "Paris is in Germany";
    const context = "Paris is the capital and most populous city of France.";
    console.log(`Claim: ${claim}`);

    try {
        const factResult = await client.verifyFact(claim, context);
        console.log(`Verdict: ${factResult.verdict}`);
        console.log(`Reasoning: ${factResult.reasoning}`);
    } catch (error) {
        console.error("Error:", error);
    }
}

runExamples();
