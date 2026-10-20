// Example: Basic QWED Go SDK Usage
//
// This example demonstrates how to use the QWED Go SDK for
// verification of LLM outputs.
//
// Run: go run main.go

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	qwed "github.com/QWED-AI/qwed-verification/sdk-go/v7"
)

func main() {
	// Get API key from environment
	apiKey := os.Getenv("QWED_API_KEY")
	if apiKey == "" {
		apiKey = "demo_key" // For testing
	}

	// Create client with options
	client := qwed.NewClient(apiKey,
		qwed.WithBaseURL("http://localhost:8000"), // Or your API URL
		qwed.WithTimeout(30*time.Second),
	)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Example 1: Health Check
	fmt.Println("=== Health Check ===")
	health, err := client.Health(ctx)
	if err != nil {
		log.Printf("Health check failed: %v", err)
	} else {
		fmt.Printf("API Status: %v\n", health["status"])
	}

	// Example 2: Math Verification
	fmt.Println("\n=== Math Verification ===")
	mathResult, err := client.VerifyMath(ctx, "2 + 2 = 4")
	if err != nil {
		log.Printf("Math verification failed: %v", err)
	} else {
		fmt.Println(verdict(mathResult))
	}

	// Example 3: Logic Verification
	fmt.Println("\n=== Logic Verification ===")
	logicResult, err := client.VerifyLogic(ctx, "If A implies B, and A is true, then B must be true")
	if err != nil {
		log.Printf("Logic verification failed: %v", err)
	} else {
		fmt.Println(verdict(logicResult))
	}

	// Example 4: Code Security Check
	fmt.Println("\n=== Code Security Check ===")
	unsafeCode := `
def process_input(data):
    return eval(data)  # Dangerous!
`
	codeResult, err := client.VerifyCode(ctx, unsafeCode, "python")
	if err != nil {
		log.Printf("Code verification failed: %v", err)
	} else {
		fmt.Println(verdict(codeResult))
		switch {
		case codeResult.IsAdmitted():
			fmt.Println("Code passed verification")
		case codeResult.Status == qwed.StatusVerified && codeResult.Admission == qwed.AdmissionBlocked:
			// VERIFIED · BLOCKED: the verifier analysed the code and proved it unsafe.
			fmt.Println("⚠️  Security vulnerability detected!")
		default:
			// Not admitted for another reason: the verifier could not analyse
			// the code, so it is neither proven safe nor proven unsafe.
			fmt.Println("⚠️  Could not verify the code; do not run it")
		}
	}

	// Example 5: Fact Verification
	fmt.Println("\n=== Fact Verification ===")
	factResult, err := client.VerifyFact(ctx,
		"Paris is the capital of France",
		"France is a country in Western Europe. Its capital city is Paris, known for the Eiffel Tower.",
	)
	if err != nil {
		log.Printf("Fact verification failed: %v", err)
	} else {
		fmt.Println(verdict(factResult))
	}

	// Example 6: SQL Validation
	fmt.Println("\n=== SQL Validation ===")
	sqlResult, err := client.VerifySQL(ctx,
		"SELECT name, email FROM users WHERE id = 1",
		"CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(255))",
		"postgresql",
	)
	if err != nil {
		log.Printf("SQL verification failed: %v", err)
	} else {
		fmt.Println(verdict(sqlResult))
	}

	// Example 7: Batch Verification
	fmt.Println("\n=== Batch Verification ===")
	batchItems := []qwed.BatchItem{
		{Query: "2 + 2 = 4", Type: qwed.TypeMath},
		{Query: "3 * 3 = 9", Type: qwed.TypeMath},
		{Query: "10 / 2 = 5", Type: qwed.TypeMath},
	}
	batchResult, err := client.VerifyBatch(ctx, batchItems, nil)
	if err != nil {
		log.Printf("Batch verification failed: %v", err)
	} else {
		fmt.Printf("Job ID: %s, Status: %s, %d/%d items done\n",
			batchResult.JobID, batchResult.Status, batchResult.CompletedItems, batchResult.TotalItems)
		for _, item := range batchResult.Items {
			if item.Result != nil {
				fmt.Printf("  %s: %s\n", item.Query, verdict(item.Result))
			} else {
				fmt.Printf("  %s: %s %s\n", item.Query, item.Status, item.Error)
			}
		}
	}

	fmt.Println("\n✅ All examples completed!")
}

// verdict pairs the status with the admission decision, such as
// "VERIFIED · ADMIT". Only an admitted result is a pass: 2 + 2 = 5 is
// "VERIFIED · BLOCKED".
func verdict(r *qwed.VerificationResponse) string {
	admission := string(r.Admission)
	if admission == "" {
		admission = "no admission"
	}
	return fmt.Sprintf("%s · %s (admitted: %v) %s", r.Status, admission, r.IsAdmitted(), r.AgentMessage)
}
