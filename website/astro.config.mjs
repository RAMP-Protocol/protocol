// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightMermaid from '@pasqal-io/starlight-client-mermaid';
import starlightLinksValidator from 'starlight-links-validator';
import remarkDirective from 'remark-directive';
import remarkProto from './plugins/remark-proto.mjs';
import remarkStandards from './plugins/remark-standards.mjs';

export default defineConfig({
	markdown: {
		// remarkProto: render proto-derived tables (::proto-enum / ::proto-vocab) from the
		//   descriptor AND autolink/validate every proto reference in one mdast pass — so a
		//   reference in a rendered table links like one in prose, and an unknown reference
		//   fails the build. See plugins/remark-proto.mjs + proto-schema.mjs.
		// remarkStandards: link the first mention of each external standard (RFC NNNN, C2PA,
		//   …) to its canonical source. Runs after remarkProto so generated tables link too.
		remarkPlugins: [remarkDirective, remarkProto, remarkStandards],
	},
	integrations: [
		starlight({
			title: 'RAMP Protocol',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RAMP-Protocol/protocol' }],
			plugins: [starlightMermaid(), starlightLinksValidator()],
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
						{ label: 'JSONL Ingestion', slug: 'protocol/jsonl-ingestion' },
						{ label: 'Exchange Manifest', slug: 'protocol/exchange-manifest' },
						{ label: 'Resource Attestation', slug: 'protocol/content-attestation' },
						{ label: 'Authentication', slug: 'protocol/authentication' },
						{ label: 'Role Composition', slug: 'protocol/role-composition' },
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
					label: 'Components',
					items: [
						{
							label: 'Edge Function',
							items: [
								{ label: 'Overview', slug: 'components/edge-function/overview' },
								{ label: 'CDN Adapters', slug: 'components/edge-function/cdn-adapters' },
								{ label: 'Signed URL Verification', slug: 'components/edge-function/signed-url-verification' },
								{ label: 'Bot Detection', slug: 'components/edge-function/bot-detection' },
								{ label: 'Composition', slug: 'components/edge-function/composition' },
								{ label: 'Deployment', slug: 'components/edge-function/deployment' },
							],
						},
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Proto: RAMP v1', slug: 'reference/proto-ramp' },
						{ label: 'Proto: Admin v1', slug: 'reference/proto-admin' },
						{ label: 'Standards & References', slug: 'reference/standards' },
						{ label: 'ramp.json Example', slug: 'reference/ramp-json-example' },
						{ label: 'Changelog', slug: 'reference/changelog' },
					],
				},
			],
		}),
	],
});

