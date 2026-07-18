<script setup lang="ts">
import { ref, computed } from 'vue'
import { decodeAtariST, sniffLineEndings, type LineEnding } from '../lib/charsets/decode'

interface Props {
	/** Display name for the title bar. */
	name: string
	/** Raw Atari ST bytes to decode. */
	bytes: Uint8Array
	/**
	 * Where the bytes came from. When 'disk', a "Back to list" button is
	 * shown alongside Close — the parent wires that to clearing its text
	 * selection without closing the disk image.
	 */
	origin: 'raw' | 'disk'
}

const props = defineProps<Props>()
const emit = defineEmits<{
	(e: 'close'): void
	(e: 'back'): void
}>()

const normaliseEol = ref(true)
const copyLabel = ref('Copy as UTF-8')

const decoded = computed<string>(() =>
	decodeAtariST(props.bytes, { normaliseEol: normaliseEol.value }),
)

const lineEnding = computed<LineEnding>(() => sniffLineEndings(props.bytes))

const sizeLabel = computed(() => {
	const kb = props.bytes.length / 1024
	return kb < 1024 ? `${kb.toFixed(1)} KB` : `${(kb / 1024).toFixed(2)} MB`
})

async function copyOut() {
	await navigator.clipboard.writeText(decoded.value)
	copyLabel.value = 'Copied ✓'
	setTimeout(() => { copyLabel.value = 'Copy as UTF-8' }, 1500)
}

function download() {
	const blob = new Blob([decoded.value], { type: 'text/plain;charset=utf-8' })
	const url = URL.createObjectURL(blob)
	const a = document.createElement('a')
	a.href = url
	a.download = props.name.replace(/\.[^.]+$/, '') + '.utf8.txt'
	a.click()
	URL.revokeObjectURL(url)
}
</script>

<template>
	<article class="gem-window">
		<header class="gem-window__title">
			<span>{{ name }}</span>
			<div class="cluster">
				<button v-if="origin === 'disk'" type="button" @click="emit('back')">↑ List</button>
				<button type="button" @click="emit('close')">Close</button>
			</div>
		</header>

		<dl class="meta cluster">
			<div><dt>Size</dt><dd>{{ sizeLabel }}</dd></div>
			<div><dt>Bytes</dt><dd>{{ bytes.length.toLocaleString() }}</dd></div>
			<div><dt>Line endings</dt><dd>{{ lineEnding }}</dd></div>
			<div>
				<dt>Normalise EOL</dt>
				<dd>
					<label class="toggle">
						<input v-model="normaliseEol" type="checkbox" />
						CR / CRLF → LF
					</label>
				</dd>
			</div>
		</dl>

		<div class="cluster actions">
			<button class="btn" type="button" @click="copyOut">{{ copyLabel }}</button>
			<button class="btn btn--secondary" type="button" @click="download">Download .utf8.txt</button>
		</div>

		<pre class="st-text" data-testid="rendered-text" aria-label="rendered text output">{{ decoded }}</pre>
	</article>
</template>

<style scoped>
.meta {
	font-family: var(--font-mono);
	font-size: 1rem;
	margin: 0 0 1rem 0;
	align-items: flex-start;
}

.meta dt {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
	margin-bottom: 0.25rem;
}

.meta dd { margin: 0; }

.toggle {
	display: inline-flex;
	gap: 0.5rem;
	align-items: center;
	cursor: pointer;
}

.toggle input { accent-color: var(--color-st-green); }

.actions { margin: 0 0 1rem 0; }

.st-text {
	margin: 0;
	max-height: 60vh;
}
</style>
