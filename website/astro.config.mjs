// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightMermaid from '@pasqal-io/starlight-client-mermaid';

export default defineConfig({
	integrations: [
		starlight({
			title: 'RAMP Protocol',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RAMP-Protocol/protocol' }],
			plugins: [starlightMermaid()],
			components: {
				Footer: './src/components/Footer.astro',
			},
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'What is RAMP?', slug: 'getting-started/what-is-ramp' },
						{ label: 'Live Demo', slug: 'getting-started/poc-walkthrough' },
						{ label: 'For Providers', slug: 'getting-started/for-providers' },
						{ label: 'For AI Agents', slug: 'getting-started/for-ai-agents' },
						{ label: 'How Money Flows', slug: 'getting-started/how-money-flows' },
					],
				},
				{
					label: 'Protocol',
					items: [
						{ label: 'Transaction Flow', slug: 'protocol/transaction-flow' },
						{ label: 'Standards Layering', slug: 'protocol/standards-layering' },
						{ label: 'Discovery Paths', slug: 'protocol/discovery-paths' },
						{ label: 'Resource Attestation', slug: 'protocol/content-attestation' },
						{ label: 'Authentication', slug: 'protocol/authentication' },
						{ label: 'Dispute Resolution', slug: 'protocol/dispute-resolution' },
						{ label: 'Extension Profiles', slug: 'protocol/extension-profiles' },
						{ label: 'Ext: News', slug: 'protocol/ext-news' },
						{ label: 'Ext: Academic', slug: 'protocol/ext-academic' },
						{ label: 'Ext: Legal', slug: 'protocol/ext-legal' },
						{ label: 'Ext: CoMP', slug: 'protocol/ext-comp' },
						{ label: 'Ext: C2PA', slug: 'protocol/ext-c2pa' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Proto: RAMP v1', slug: 'reference/proto-ramp' },
						{ label: 'ramp.json Example', slug: 'reference/ramp-json-example' },
						{ label: 'Changelog', slug: 'reference/changelog' },
					],
				},
			],
		}),
	],
});

