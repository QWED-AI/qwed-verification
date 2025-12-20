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
        'engines/fact',
        'engines/stats',
      ],
    },
    {
      type: 'category',
      label: 'SDKs',
      link: {
        type: 'doc',
        id: 'sdks/overview',
      },
      items: [
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
      link: {
        type: 'doc',
        id: 'specs/overview',
      },
      items: [
        'specs/qwed-spec',
        'specs/attestation',
        'specs/agent',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      link: {
        type: 'doc',
        id: 'api/overview',
      },
      items: [
        'api/endpoints',
        'api/authentication',
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
        'advanced/custom-engines',
        'advanced/self-hosting',
      ],
    },
  ],
};

export default sidebars;
