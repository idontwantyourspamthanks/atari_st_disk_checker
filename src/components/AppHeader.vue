<script setup lang="ts">
import { RouterLink, useRoute } from 'vue-router'

const route = useRoute()

const links = [
	{ to: '/',     label: 'Desk' },
	{ to: '/text', label: 'Files' },
	{ to: '/scan', label: 'Scan' },
] as const

function isActive(path: string): boolean {
	return path === '/' ? route.path === '/' : route.path.startsWith(path)
}
</script>

<template>
	<header class="app-header">
		<RouterLink to="/" class="app-header__brand">DiskCheck</RouterLink>
		<nav class="app-header__menu" aria-label="Primary">
			<RouterLink
				v-for="link in links"
				:key="link.to"
				:to="link.to"
				class="app-header__item"
				:class="{ 'app-header__item--active': isActive(link.to) }"
			>
				{{ link.label }}
			</RouterLink>
		</nav>
	</header>
</template>

<style scoped>
.app-header {
	display: flex;
	align-items: center;
	gap: 1.5rem;
	padding: 0.45rem 1rem;
	background: var(--color-panel-dim);
	color: var(--color-ink);
	border-bottom: 2px solid var(--color-ink);
	box-shadow: 0 2px 0 var(--color-ink);
	position: relative;
	z-index: 1;
}

.app-header__brand {
	font-family: var(--font-pixel);
	font-size: var(--text-md);
	color: var(--color-ink);
	text-decoration: none;
	padding: 0.3rem 0.55rem;
	background: var(--color-st-green);
	border: 2px solid var(--color-ink);
}

.app-header__brand:hover {
	background: var(--color-ink);
	color: var(--color-panel);
}

.app-header__menu {
	display: flex;
	gap: 0.35rem;
}

.app-header__item {
	font-family: var(--font-pixel);
	font-size: var(--text-sm);
	color: var(--color-ink);
	text-decoration: none;
	padding: 0.35rem 0.55rem;
	border: 2px solid transparent;
}

.app-header__item:hover {
	border-color: var(--color-ink);
	background: var(--color-panel);
}

.app-header__item--active {
	background: var(--color-ink);
	color: var(--color-panel);
	border-color: var(--color-ink);
}

@media (max-width: 600px) {
	.app-header {
		flex-wrap: wrap;
		gap: 0.75rem;
		padding: 0.5rem;
	}
	.app-header__menu {
		gap: 0.25rem;
	}
}
</style>
