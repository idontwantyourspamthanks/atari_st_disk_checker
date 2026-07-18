<script setup lang="ts">
import { RouterView } from 'vue-router'
import AppHeader from './components/AppHeader.vue'
import { useGlobalDropZone } from './composables/useDropZone'

const { isDragOver } = useGlobalDropZone()
</script>

<template>
	<AppHeader />
	<main class="app-main">
		<RouterView />
	</main>

	<div v-if="isDragOver" class="drop-overlay" aria-hidden="true">
		<div class="drop-overlay__panel">
			<div class="drop-overlay__glyph">↓</div>
			<div class="drop-overlay__msg">Drop anywhere</div>
		</div>
	</div>
</template>

<style scoped>
.app-main {
	flex: 1;
	width: 100%;
	max-width: 1100px;
	margin: 0 auto;
	padding: 2rem 1.5rem 4rem;
	position: relative;
	z-index: 1;
}

.drop-overlay {
	position: fixed;
	inset: 0;
	z-index: 9999;
	background: rgba(36, 112, 46, 0.92);
	display: flex;
	align-items: center;
	justify-content: center;
	pointer-events: none;
	border: 4px dashed var(--color-ink);
	box-shadow: inset 0 0 0 8px var(--color-bg);
}

.drop-overlay__panel {
	text-align: center;
	background: var(--color-panel);
	border: 2px solid var(--color-ink);
	box-shadow: var(--shadow-gem);
	padding: 2rem 2.5rem;
}

.drop-overlay__glyph {
	font-family: var(--font-pixel);
	font-size: 72px;
	color: var(--color-ink);
	margin-bottom: 1rem;
	line-height: 1;
	animation: bob 1s ease-in-out infinite alternate;
}

.drop-overlay__msg {
	font-family: var(--font-pixel);
	font-size: var(--text-md);
	color: var(--color-ink);
	letter-spacing: 0.06em;
}

@keyframes bob {
	from { transform: translateY(0); }
	to   { transform: translateY(8px); }
}

@media (prefers-reduced-motion: reduce) {
	.drop-overlay__glyph {
		animation: none;
	}
}
</style>
