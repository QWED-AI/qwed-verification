# QWED Frontend Integration Guide

**Target Audience**: Frontend Developers / AI Agents
**Backend URL**: `http://localhost:8002`
**Status**: Local Development

---

## 1. API Overview

QWED exposes a FastAPI backend with CORS enabled for all origins (`*`). You can call these endpoints directly from your React/Next.js frontend.

### Base Configuration
```typescript
const API_BASE_URL = "http://localhost:8002";
```

---

## 2. TypeScript Interfaces

Copy these interfaces to your frontend (e.g., `types/qwed.ts`) to ensure type safety.

```typescript
// Common Response Structure
export interface VerificationResult {
  status: "VERIFIED" | "CORRECTED" | "REFUTED" | "SUPPORTED" | "UNSAFE" | "SAFE";
  final_answer?: number | string | boolean;
  reasoning?: string;
  latency_ms?: number;
  // Additional fields depending on the engine
  verification?: {
    is_correct: boolean;
    calculated_value?: any;
    claimed_value?: any;
    diff?: number;
  };
  validation?: {
    is_valid: boolean;
    error?: string;
  };
}

// 1. Natural Language (Math/General)
export interface NaturalLanguageRequest {
  query: string;
  provider?: "azure_openai" | "anthropic"; // Defaults to azure_openai
}

// 2. Logic (Z3 Solver)
export interface LogicRequest {
  query: string;
}

// 3. Stats (CSV Analysis)
// Note: This requires FormData for file upload
export interface StatsRequest {
  query: string;
  file: File; 
}

// 4. Facts (RAG/Context)
export interface FactRequest {
  claim: string;
  context: string; // The document text to verify against
}

// 5. Code Security
export interface CodeRequest {
  code: string;
  language?: string; // Defaults to "python"
}

// History Log
export interface HistoryItem {
  id: number;
  timestamp: string;
  query: string;
  result: string; // JSON string
  is_verified: boolean;
  domain: string;
}
```

---

## 3. API Client Implementation

Here is a ready-to-use `api.ts` helper using `fetch`.

```typescript
// src/lib/api.ts

const BASE_URL = "http://localhost:8002";

export const QwedApi = {
  /**
   * Engine 1: Natural Language Verification (Math/General)
   * Auto-routes to Math Verifier if applicable.
   */
  verifyNaturalLanguage: async (query: string, provider = "azure_openai") => {
    const res = await fetch(`${BASE_URL}/verify/natural_language`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, provider }),
    });
    return res.json();
  },

  /**
   * Engine 2: Logic Verification (Z3 Solver)
   * Best for puzzles, constraints, and boolean logic.
   */
  verifyLogic: async (query: string) => {
    const res = await fetch(`${BASE_URL}/verify/logic`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
    });
    return res.json();
  },

  /**
   * Engine 3: Statistical Verification (Pandas)
   * Uploads a CSV and runs a query against it.
   */
  verifyStats: async (file: File, query: string) => {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("query", query);

    const res = await fetch(`${BASE_URL}/verify/stats`, {
      method: "POST",
      body: formData, // Content-Type is set automatically
    });
    return res.json();
  },

  /**
   * Engine 4: Fact Verification (Citation)
   * Checks a claim against a provided text context.
   */
  verifyFact: async (claim: string, context: string) => {
    const res = await fetch(`${BASE_URL}/verify/fact`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claim, context }),
    });
    return res.json();
  },

  /**
   * Engine 5: Code Security Verification
   * Scans code for vulnerabilities.
   */
  verifyCode: async (code: string, language = "python") => {
    const res = await fetch(`${BASE_URL}/verify/code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, language }),
    });
    return res.json();
  },

  /**
   * Get Verification History
   */
  getHistory: async () => {
    const res = await fetch(`${BASE_URL}/history`);
    return res.json();
  },
};
```

---

## 4. Integration Instructions for Agent

1.  **Install Dependencies**: No extra dependencies needed if using standard `fetch`. If using `axios`, install it.
2.  **Copy Types**: Create `src/types/qwed.ts` and paste the interfaces from Section 2.
3.  **Create Client**: Create `src/lib/api.ts` and paste the code from Section 3.
4.  **Usage in Components**:

    ```tsx
    import { useState } from 'react';
    import { QwedApi } from '../lib/api';

    export function VerificationComponent() {
      const [result, setResult] = useState(null);

      const handleVerify = async () => {
        // Example: Math
        const data = await QwedApi.verifyNaturalLanguage("What is 15% of 200?");
        setResult(data);
      };

      return (
        <div>
          <button onClick={handleVerify}>Verify</button>
          {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
        </div>
      );
    }
    ```

5.  **Handling File Uploads (Stats Engine)**:
    Ensure your file input passes the `File` object directly to `verifyStats`.

    ```tsx
    const handleFileUpload = async (e) => {
      const file = e.target.files[0];
      const data = await QwedApi.verifyStats(file, "Total revenue?");
      console.log(data);
    };
    ```

---

## 5. Troubleshooting

*   **Connection Refused**: Ensure the backend is running (`python -m uvicorn qwed_new.api.main:app --port 8002`).
*   **CORS Errors**: The backend is configured to allow `*`. If you see CORS errors, check if the backend crashed or if you are hitting the wrong port (e.g., 8000 instead of 8002).
*   **422 Validation Error**: Check your request body matches the interfaces exactly.
