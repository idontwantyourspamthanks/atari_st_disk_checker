<script setup lang="ts">
import { RouterLink } from 'vue-router'

const tools = [
	{
		to: '/text',
		name: 'Files',
		glyph: 'TX',
		blurb: 'Render ST text and images (PI1–PI3, TNY, SPU, NEO, IFF). Drop a .ST, .MSA, or .STX disk to pick a file out.',
	},
	{
		to: '/scan',
		name: 'Scan',
		glyph: 'VS',
		blurb: 'Batch-scan .ST / .MSA / .STX images — or a ZIP of them — for boot-sector viruses. Nothing leaves your machine.',
	},
] as const
</script>

<template>
	<section class="home">
		<header class="hero">
			<h1 class="hero__brand">DiskCheck</h1>
			<p class="hero__sub">Atari ST disks, in the browser.</p>
		</header>

		<nav class="tools" aria-label="Tools">
			<RouterLink
				v-for="(tool, i) in tools"
				:key="tool.to"
				:to="tool.to"
				class="tool"
				:style="{ '--delay': `${120 + i * 90}ms` }"
			>
				<span class="tool__glyph" aria-hidden="true">{{ tool.glyph }}</span>
				<span class="tool__name">{{ tool.name }}</span>
				<span class="tool__blurb">{{ tool.blurb }}</span>
			</RouterLink>
		</nav>
	</section>
</template>

<style scoped>
.home {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	min-height: calc(100vh - 6rem);
	padding: 1rem 0 2rem;
}

.hero {
	text-align: center;
	margin: 0 0 2.5rem;
	animation: rise-in 420ms ease-out both;
}

.hero__brand {
	font-size: var(--text-hero);
	letter-spacing: 0.04em;
	margin: 0;
	color: var(--color-ink);
	line-height: 1.2;
}

.hero__sub {
	font-size: 1.35rem;
	max-width: 28rem;
	margin: 0.85rem auto 0;
	color: var(--color-ink);
	opacity: 0.85;
}

.tools {
	display: grid;
	grid-template-columns: repeat(2, minmax(0, 1fr));
	gap: 1.25rem;
	width: 100%;
	max-width: 44rem;
}

.tool {
	display: grid;
	grid-template-rows: auto auto 1fr;
	gap: 0.5rem;
	background: var(--color-panel);
	border: 2px solid var(--color-ink);
	box-shadow: var(--shadow-gem);
	padding: 1.25rem 1.35rem;
	text-decoration: none;
	color: var(--color-ink);
	transition: transform 80ms, box-shadow 80ms;
	animation: rise-in 420ms ease-out both;
	animation-delay: var(--delay);
	min-height: 10rem;
}

.tool:hover {
	transform: translate(-2px, -2px);
	box-shadow: 6px 6px 0 var(--color-ink);
}

.tool:active {
	transform: translate(2px, 2px);
	box-shadow: 0 0 0 var(--color-ink);
}

.tool__glyph {
	font-family: var(--font-pixel);
	font-size: var(--text-sm);
	background: var(--color-st-green);
	color: var(--color-on-accent);
	border: 2px solid var(--color-ink);
	justify-self: start;
	padding: 0.2rem 0.45rem;
}

.tool__name {
	font-family: var(--font-pixel);
	font-size: var(--text-md);
	margin: 0.25rem 0 0;
}

.tool__blurb {
	font-size: 1.05rem;
	line-height: 1.35;
	opacity: 0.9;
}

@keyframes rise-in {
	from {
		opacity: 0;
		transform: translateY(10px);
	}
	to {
		opacity: 1;
		transform: translateY(0);
	}
}

@media (max-width: 640px) {
	.home {
		min-height: auto;
		justify-content: flex-start;
		padding-top: 1.5rem;
	}

	.hero__brand {
		font-size: var(--text-xl);
	}

	.tools {
		grid-template-columns: 1fr;
	}
}

@media (prefers-reduced-motion: reduce) {
	.hero,
	.tool {
		animation: none;
	}
}
</style>
