import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'QWED Protocol',
  tagline: 'The Deterministic Verification Protocol for AI',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://docs.qwedai.com',
  baseUrl: '/',

  organizationName: 'QWED-AI',
  projectName: 'qwed-verification',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,

  onBrokenLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/QWED-AI/qwed-verification/tree/main/docs-site/',
          versions: {
            current: {
              label: 'v1.0.0',
            },
          },
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          editUrl: 'https://github.com/QWED-AI/qwed-verification/tree/main/docs-site/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/qwed-social-card.png',
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    // Algolia DocSearch - Apply at https://docsearch.algolia.com/apply/
    algolia: {
      appId: 'YOUR_APP_ID',
      apiKey: 'YOUR_SEARCH_API_KEY',
      indexName: 'qwedai',
      contextualSearch: true,
      searchPagePath: 'search',
    },
    navbar: {
      title: 'QWED',
      logo: {
        alt: 'QWED Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/docs/sdks/overview',
          label: 'SDKs',
          position: 'left',
        },
        {
          to: '/docs/specs/overview',
          label: 'Specs',
          position: 'left',
        },
        { to: '/blog', label: 'Blog', position: 'left' },
        {
          type: 'docsVersionDropdown',
          position: 'right',
        },
        {
          href: 'https://github.com/QWED-AI/qwed-verification',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/intro',
            },
            {
              label: 'API Reference',
              to: '/docs/api/overview',
            },
            {
              label: 'Protocol Specs',
              to: '/docs/specs/overview',
            },
          ],
        },
        {
          title: 'SDKs',
          items: [
            {
              label: 'Python',
              to: '/docs/sdks/python',
            },
            {
              label: 'TypeScript',
              to: '/docs/sdks/typescript',
            },
            {
              label: 'Go',
              to: '/docs/sdks/go',
            },
            {
              label: 'Rust',
              to: '/docs/sdks/rust',
            },
          ],
        },
        {
          title: 'Integrations',
          items: [
            {
              label: 'LangChain',
              to: '/docs/integrations/langchain',
            },
            {
              label: 'LlamaIndex',
              to: '/docs/integrations/llamaindex',
            },
            {
              label: 'CrewAI',
              to: '/docs/integrations/crewai',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/QWED-AI/qwed-verification',
            },
            {
              label: 'Twitter',
              href: 'https://twitter.com/qwed_ai',
            },
            {
              label: 'Contact',
              href: 'mailto:rahul@qwedai.com',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} QWED-AI. Built with ❤️ for deterministic AI.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['python', 'typescript', 'go', 'rust', 'bash'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;

