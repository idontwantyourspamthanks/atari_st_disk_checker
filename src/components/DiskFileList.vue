<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted, nextTick } from 'vue'
import type { Fat12Image, FileEntry } from '../lib/disk/fat12'

const props = defineProps<{ image: Fat12Image }>()
const emit = defineEmits<{
	(e: 'select', entry: FileEntry): void
	(e: 'close'): void
}>()

const files = computed(() =>
	[...props.image.listFiles()].sort((a, b) => a.path.localeCompare(b.path)),
)

const selected = ref(0)
const listEl = ref<HTMLUListElement | null>(null)

// Reset selection when the underlying disk image changes.
watch(() => props.image, () => { selected.value = 0 })

function selectIndex(i: number) {
	if (files.value.length === 0) return
	selected.value = Math.max(0, Math.min(i, files.value.length - 1))
	nextTick(scrollSelectedIntoView)
}

function scrollSelectedIntoView() {
	const list = listEl.value
	if (!list) return
	const row = list.querySelector<HTMLElement>(`[data-idx="${selected.value}"]`)
	// Guard for jsdom and any older browser that lacks scrollIntoView.
	if (row && typeof row.scrollIntoView === 'function') {
		row.scrollIntoView({ block: 'nearest' })
	}
}

function handleKey(e: KeyboardEvent) {
	// Don't hijack typing in form fields elsewhere on the page.
	const target = e.target as HTMLElement | null
	if (target && /^(input|textarea|select)$/i.test(target.tagName)) return
	if (files.value.length === 0) return

	switch (e.key) {
		case 'ArrowDown':  e.preventDefault(); selectIndex(selected.value + 1); break
		case 'ArrowUp':    e.preventDefault(); selectIndex(selected.value - 1); break
		case 'PageDown':   e.preventDefault(); selectIndex(selected.value + 10); break
		case 'PageUp':     e.preventDefault(); selectIndex(selected.value - 10); break
		case 'Home':       e.preventDefault(); selectIndex(0); break
		case 'End':        e.preventDefault(); selectIndex(files.value.length - 1); break
		case 'Enter':      e.preventDefault(); emit('select', files.value[selected.value]); break
		case 'Escape':     e.preventDefault(); emit('close'); break
	}
}

onMounted(() => { window.addEventListener('keydown', handleKey) })
onUnmounted(() => { window.removeEventListener('keydown', handleKey) })

function sizeLabel(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`
	const kb = bytes / 1024
	return kb < 1024 ? `${kb.toFixed(1)} KB` : `${(kb / 1024).toFixed(2)} MB`
}

function formatDate(date: Date | null): string {
	if (!date) return '—'
	return date.toISOString().slice(0, 10)
}
</script>

<template>
	<div>
		<p v-if="files.length === 0" class="disk-list__empty muted">
			No files in this image's FAT12 filesystem. (The boot sector may be
			corrupt or this may be a non-standard game disk.)
		</p>

		<p v-else class="disk-list__hint muted">
			{{ files.length }} file{{ files.length === 1 ? '' : 's' }} —
			<span class="kbd">↑</span>/<span class="kbd">↓</span> move
			<span class="kbd">Enter</span> open
			<span class="kbd">Esc</span> close
		</p>

		<ul
			v-if="files.length > 0"
			ref="listEl"
			class="disk-list"
			role="listbox"
			:aria-activedescendant="`row-${selected}`"
			tabindex="-1"
		>
			<li v-for="(f, i) in files" :key="f.path" role="option" :aria-selected="i === selected">
				<button
					type="button"
					class="disk-list__row"
					:class="{ 'disk-list__row--selected': i === selected }"
					:data-testid="`file-${f.path}`"
					:data-idx="i"
					:id="`row-${i}`"
					@focus="selected = i"
					@click="emit('select', f)"
				>
					<span class="disk-list__path">{{ f.path }}</span>
					<span class="disk-list__size">{{ sizeLabel(f.entry.size) }}</span>
					<span class="disk-list__date muted">{{ formatDate(f.entry.modified) }}</span>
				</button>
			</li>
		</ul>
	</div>
</template>

<style scoped>
.disk-list {
	list-style: none;
	margin: 0;
	padding: 0;
	max-height: 65vh;
	overflow-y: auto;
}

.disk-list__hint {
	font-family: var(--font-mono);
	font-size: 0.9rem;
	margin: 0 0 0.5rem 0;
	padding: 0.5rem 0.25rem 0 0.25rem;
}

.kbd {
	display: inline-block;
	background: var(--color-panel-dim);
	color: var(--color-ink);
	border: 1px solid var(--color-ink);
	padding: 0 0.35rem;
	margin: 0 0.1rem;
	font-family: var(--font-pixel);
	font-size: 0.7rem;
	line-height: 1.4;
}

.disk-list__row {
	display: grid;
	grid-template-columns: 1fr auto auto;
	gap: 1.5rem;
	align-items: baseline;
	width: 100%;
	background: transparent;
	border: 0;
	border-bottom: 1px solid #e0e0e0;
	color: var(--color-text-on-panel);
	padding: 0.6rem 0.25rem;
	font-family: var(--font-mono);
	font-size: 1.1rem;
	text-align: left;
	cursor: pointer;
	transition: background 60ms;
}

.disk-list__row:hover,
.disk-list__row:focus-visible,
.disk-list__row--selected {
	background: var(--color-st-green);
	color: #000;
	outline: none;
}

.disk-list__row:hover .disk-list__date,
.disk-list__row:focus-visible .disk-list__date,
.disk-list__row--selected .disk-list__date {
	color: #003300;
}

.disk-list__path {
	font-weight: bold;
	word-break: break-all;
}

.disk-list__size,
.disk-list__date {
	font-size: 0.95rem;
	white-space: nowrap;
}

.disk-list__empty {
	padding: 1.5rem 0.25rem;
	font-family: var(--font-mono);
}

@media (max-width: 600px) {
	.disk-list__row {
		grid-template-columns: 1fr;
		gap: 0.25rem;
		padding: 0.75rem 0.25rem;
	}
	.disk-list__size, .disk-list__date { font-size: 0.85rem; }
}
</style>
