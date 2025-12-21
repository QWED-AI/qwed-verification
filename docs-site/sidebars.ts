import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/quickstart',
        'getting-started/concepts',
        'getting-started/llm-configuration',
      ],
    },
    {
      type: 'category',
      label: 'Verification Engines',
      items: [
        'engines/overview',
        'engines/math',
        'engines/logic',
        'engines/code',
        'engines/sql',
      ],
    },
    {
      type: 'category',
      label: 'SDKs',
      items: [
        'sdks/overview',
        'sdks/python',
        'sdks/typescript',
        'sdks/go',
        'sdks/rust',
      ],
    },
    {
      type: 'category',
      label: 'Integrations',
      items: [
        'integrations/langchain',
        'integrations/llamaindex',
        'integrations/crewai',
      ],
    },
    {
      type: 'category',
      label: 'Protocol Specifications',
      items: [
        'specs/overview',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [
        'api/overview',
        'api/endpoints',
        'api/authentication',
        'api/dsl-reference',
        'api/errors',
        'api/rate-limits',
      ],
    },
    {
      type: 'category',
      label: 'Advanced',
      items: [
        'advanced/attestations',
        'advanced/agent-verification',
        'advanced/self-hosting',
      ],
    },
  ],
};

export default sidebars;

