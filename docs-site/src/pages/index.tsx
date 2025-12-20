import type { ReactNode } from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import styles from './index.module.css';

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/">
            Get Started →
          </Link>
          <Link
            className="button button--outline button--lg"
            style={{ marginLeft: '1rem', color: 'white', borderColor: 'white' }}
            to="https://github.com/QWED-AI/qwed-verification">
            View on GitHub ⭐
          </Link>
        </div>
      </div>
    </header>
  );
}

function QuickInstall() {
  return (
    <section className={styles.quickInstall}>
      <div className="container">
        <Heading as="h2" className="text--center margin-bottom--lg">
          ⚡ Quick Install
        </Heading>
        <div className="row">
          <div className="col col--3">
            <div className={styles.installCard}>
              <strong>Python</strong>
              <code>pip install qwed-new</code>
            </div>
          </div>
          <div className="col col--3">
            <div className={styles.installCard}>
              <strong>TypeScript</strong>
              <code>npm install @qwed-ai/sdk</code>
            </div>
          </div>
          <div className="col col--3">
            <div className={styles.installCard}>
              <strong>Go</strong>
              <code>go get github.com/qwed-ai/qwed-go</code>
            </div>
          </div>
          <div className="col col--3">
            <div className={styles.installCard}>
              <strong>Rust</strong>
              <code>cargo add qwed</code>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Features() {
  const features = [
    {
      title: '🎯 Deterministic Verification',
      description: '100% accurate math and logic verification using SymPy and Z3. No hallucinations, just proofs.',
    },
    {
      title: '⚙️ 8 Verification Engines',
      description: 'Math, Logic, Code, SQL, Stats, Fact, Image, and Reasoning engines for comprehensive coverage.',
    },
    {
      title: '📦 Multi-Language SDKs',
      description: 'Official SDKs for Python, TypeScript, Go, and Rust. Use QWED in any stack.',
    },
    {
      title: '🔌 Framework Integrations',
      description: 'Native integrations with LangChain, LlamaIndex, and CrewAI for AI agent development.',
    },
    {
      title: '🔐 Cryptographic Attestations',
      description: 'JWT-based proofs with ES256 signatures. Verify that a verification occurred.',
    },
    {
      title: '🤖 Agent Verification',
      description: 'Pre-execution checks, budget enforcement, and activity logging for AI agents.',
    },
  ];

  return (
    <section className={styles.features}>
      <div className="container">
        <Heading as="h2" className="text--center margin-bottom--lg">
          ✨ Features
        </Heading>
        <div className="row">
          {features.map((feature, idx) => (
            <div key={idx} className="col col--4 margin-bottom--lg">
              <div className={styles.featureCard}>
                <Heading as="h3">{feature.title}</Heading>
                <p>{feature.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function CodeExample() {
  return (
    <section className={styles.codeExample}>
      <div className="container">
        <Heading as="h2" className="text--center margin-bottom--lg">
          🚀 See It In Action
        </Heading>
        <div className="row">
          <div className="col col--6">
            <div className={styles.codeBlock}>
              <div className={styles.codeHeader}>Python</div>
              <pre>{`from qwed_sdk import QWEDClient

client = QWEDClient(api_key="qwed_...")

# Verify math
result = client.verify_math("2+2=4")
print(result.verified)  # True

# Verify logic
result = client.verify_logic("(AND (GT x 5) (LT y 10))")
print(result.model)  # {"x": 6, "y": 9}

# Check code security
result = client.verify_code(code)
print(result.vulnerabilities)  # []`}</pre>
            </div>
          </div>
          <div className="col col--6">
            <div className={styles.codeBlock}>
              <div className={styles.codeHeader}>TypeScript</div>
              <pre>{`import { QWEDClient } from '@qwed-ai/sdk';

const client = new QWEDClient({ apiKey: 'qwed_...' });

// Verify math
const result = await client.verifyMath('2+2=4');
console.log(result.verified);  // true

// Verify logic
const logic = await client.verifyLogic('(AND (GT x 5))');
console.log(logic.model);  // { x: 6 }

// Batch verify
const batch = await client.verifyBatch([...]);
console.log(batch.summary.successRate);`}</pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Engines() {
  const engines = [
    { emoji: '🔢', name: 'Math', tech: 'SymPy + Calculus' },
    { emoji: '🧠', name: 'Logic', tech: 'Z3 + Quantifiers' },
    { emoji: '💻', name: 'Code', tech: 'Multi-Lang AST' },
    { emoji: '🗃️', name: 'SQL', tech: 'SQLGlot + Limits' },
    { emoji: '📊', name: 'Stats', tech: 'Wasm Sandbox' },
    { emoji: '📚', name: 'Fact', tech: 'TF-IDF' },
    { emoji: '🖼️', name: 'Image', tech: 'Deterministic' },
    { emoji: '💭', name: 'Reasoning', tech: 'Multi-LLM' },
  ];

  return (
    <section className={styles.engines}>
      <div className="container">
        <Heading as="h2" className="text--center margin-bottom--lg">
          🔧 Verification Engines
        </Heading>
        <div className={styles.engineGrid}>
          {engines.map((engine, idx) => (
            <div key={idx} className={styles.engineCard}>
              <span className={styles.engineEmoji}>{engine.emoji}</span>
              <strong>{engine.name}</strong>
              <small>{engine.tech}</small>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Integrations() {
  return (
    <section className={styles.integrations}>
      <div className="container">
        <Heading as="h2" className="text--center margin-bottom--lg">
          🔗 Integrations
        </Heading>
        <div className={styles.integrationsGrid}>
          <div className={styles.integrationCard}>
            <strong>🦜 LangChain</strong>
            <code>from qwed_sdk.langchain import QWEDTool</code>
          </div>
          <div className={styles.integrationCard}>
            <strong>🦙 LlamaIndex</strong>
            <code>from qwed_sdk.llamaindex import QWEDQueryEngine</code>
          </div>
          <div className={styles.integrationCard}>
            <strong>🚢 CrewAI</strong>
            <code>from qwed_sdk.crewai import QWEDVerifiedAgent</code>
          </div>
        </div>
      </div>
    </section>
  );
}

function Stats() {
  return (
    <section className={styles.stats}>
      <div className="container">
        <div className={styles.statsGrid}>
          <div className={styles.statCard}>
            <span className={styles.statNumber}>8</span>
            <span className={styles.statLabel}>Verification Engines</span>
          </div>
          <div className={styles.statCard}>
            <span className={styles.statNumber}>4</span>
            <span className={styles.statLabel}>Language SDKs</span>
          </div>
          <div className={styles.statCard}>
            <span className={styles.statNumber}>3</span>
            <span className={styles.statLabel}>Framework Integrations</span>
          </div>
          <div className={styles.statCard}>
            <span className={styles.statNumber}>100%</span>
            <span className={styles.statLabel}>Deterministic</span>
          </div>
        </div>
      </div>
    </section>
  );
}

function CTA() {
  return (
    <section className={styles.cta}>
      <div className="container text--center">
        <Heading as="h2">Ready to verify?</Heading>
        <p>Start building with deterministic AI verification today.</p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/">
            Read the Docs
          </Link>
          <Link
            className="button button--secondary button--lg"
            style={{ marginLeft: '1rem' }}
            to="/docs/getting-started/quickstart">
            Quick Start →
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title="Deterministic Verification for AI"
      description="QWED Protocol - The Deterministic Verification Protocol for AI. Verify math, logic, code, and SQL with 100% accuracy.">
      <HomepageHeader />
      <main>
        <Stats />
        <QuickInstall />
        <Features />
        <Engines />
        <CodeExample />
        <Integrations />
        <CTA />
      </main>
    </Layout>
  );
}
