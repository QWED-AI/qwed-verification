# Prompt for Gemini 3 (Google AI Studio)

**Context:**
I am building the website for **QWED** (Quantified Verification Engine for Deterministic AI). QWED is an enterprise-grade infrastructure layer that sits between raw LLMs (like GPT-4) and critical applications. It "verifies" LLM outputs using symbolic math, logic solvers, and security scanners to prevent hallucinations and exploits.

**Goal:**
Design a stunning, "infrastructure-grade" landing page and dashboard that feels like a mix of **Parallel.ai** (futuristic, dark mode, network visualizations) and **Cloudflare** (reliable, global, secure).

**Design Aesthetic:**
- **Theme**: "Deep Tech / Dark Mode". Backgrounds should be deep charcoal/black (`#0A0A0A`), not pure black.
- **Accents**: 
    - **Verified Green**: Neon green/teal (`#00FF9D`) for successful verifications.
    - **Blocked Red**: Sharp crimson (`#FF3333`) for security threats.
    - **Neural Blue**: Deep electric blue (`#3366FF`) for the "brain" aspect.
- **Typography**: Monospace fonts (like `JetBrains Mono` or `Fira Code`) for code/data, paired with a clean, geometric sans-serif (like `Inter` or `Space Grotesk`) for headlines.
- **Visual Motifs**: 
    - **Blueprints/Schematics**: Show the "internals" of the engine (nodes connecting, logic gates).
    - **Glassmorphism**: Subtle frosted glass effects for cards to show depth.
    - **Terminal/Code**: Heavy use of code snippets to show it's for developers.

**Key Sections to Design:**

1.  **Hero Section**:
    - **Headline**: "Your LLM Is Smart. But Is It Correct?" (Large, centered, gradient text).
    - **Subtext**: "The world's first Deterministic Verification Layer for Enterprise AI. Catch hallucinations, block injections, and prove correctness before deployment."
    - **Visual**: A split-screen terminal animation. Left side: Raw LLM output (hallucinating). Right side: QWED output (Verified/Corrected).
    - **CTAs**: "Start Verifying" (Primary, glowing) and "Read the Benchmark" (Secondary, outlined).

2.  **The "Engine Block" (Feature Grid)**:
    - Layout: A 3x2 bento grid showcasing the 6 Engines.
    - **Math Engine**: Icon of a formula. Text: "Symbolic computation via SymPy. No more math errors."
    - **Safety Engine**: Icon of a shield. Text: "AST-based security scanning. 100% injection detection."
    - **Logic Engine**: Icon of a puzzle piece. Text: "Z3 Solver integration. Paradoxes solved."
    - **SQL/Stats/Fact**: Smaller cards for data engines.
    - *Inspiration*: Parallel.ai's feature grid.

3.  **The "Illusion of Competence" (Problem Statement)**:
    - A graph showing "LLM Confidence" (High) vs "Actual Accuracy" (Low on hard tasks).
    - Text explaining that LLMs are probabilistic text predictors, not reasoning engines.

4.  **Interactive Playground (The "Hook")**:
    - A live input field where users can type "dangerous" queries.
    - Examples to click: "Calculate 5/0", "Drop Table Users", "Capital of Atlantis".
    - Show the **QWED Verdict** instantly (e.g., "🚫 BLOCKED: SQL Injection Detected").

5.  **Social Proof / Trust**:
    - "Certified Production Ready" badge.
    - Metrics: "92.6% Benchmark Pass Rate", "<10ms Latency Overhead".

6.  **Footer**:
    - Simple, developer-focused. Links to API Docs, GitHub, Status Page.

**Output Format:**
Please provide:
1.  **HTML Structure**: Semantic HTML5.
2.  **Tailwind CSS Classes**: Use Tailwind for styling (e.g., `bg-slate-900`, `text-transparent bg-clip-text bg-gradient-to-r`).
3.  **Animation Suggestions**: Where to add `framer-motion` or CSS animations (e.g., "Fade in up", "Pulse on hover").

**Tone**:
Serious, confident, engineering-focused. Avoid marketing fluff. Speak to CTOs and Lead Engineers.
