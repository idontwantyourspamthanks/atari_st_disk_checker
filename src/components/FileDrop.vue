<script setup lang="ts">
import { ref } from 'vue'

const props = withDefaults(defineProps<{
	accept?: string
	multiple?: boolean
	label?: string
}>(), {
	accept: '',
	multiple: false,
	label: 'Click to choose a file',
})

const emit = defineEmits<{
	(e: 'select', files: File[]): void
}>()

const input = ref<HTMLInputElement | null>(null)

function onPick() {
	input.value?.click()
}

function onChange(e: Event) {
	const target = e.target as HTMLInputElement
	if (!target.files?.length) return
	emit('select', Array.from(target.files))
	target.value = '' // allow re-picking the same file
}
</script>

<template>
	<div
		class="file-drop"
		@click="onPick"
		role="button"
		tabindex="0"
		@keydown.enter.prevent="onPick"
		@keydown.space.prevent="onPick"
	>
		<input
			ref="input"
			type="file"
			class="file-drop__input"
			:accept="props.accept || undefined"
			:multiple="props.multiple"
			@change="onChange"
		/>
		<span class="file-drop__hint">Click to pick</span>
		<span class="file-drop__label">{{ props.label }}</span>
	</div>
</template>

<style scoped>
.file-drop {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	gap: 0.75rem;
	min-height: 9rem;
	padding: 2rem 1.5rem;
	background: var(--color-panel);
	border: 2px solid var(--color-ink);
	box-shadow: var(--shadow-gem);
	text-align: center;
	cursor: pointer;
	transition: transform 80ms, box-shadow 80ms, background 80ms;
}

.file-drop:hover,
.file-drop:focus-visible {
	background: var(--color-panel-dim);
	transform: translate(-2px, -2px);
	box-shadow: 6px 6px 0 var(--color-ink);
	outline: none;
}

.file-drop:active {
	transform: translate(2px, 2px);
	box-shadow: 0 0 0 var(--color-ink);
}

.file-drop__hint {
	font-family: var(--font-pixel);
	font-size: var(--text-sm);
	background: var(--color-st-green);
	color: var(--color-on-accent);
	border: 2px solid var(--color-ink);
	padding: 0.35rem 0.65rem;
}

.file-drop__label {
	font-family: var(--font-display);
	font-size: 1.15rem;
	color: var(--color-ink);
	max-width: 36rem;
	line-height: 1.35;
}

.file-drop__input {
	display: none;
}
</style>
