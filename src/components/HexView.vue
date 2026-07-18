<script setup lang="ts">
import { computed } from 'vue'
import { getBootSector, getImageBytes } from '../lib/scan/bootSector'
import { isBootSectorExecutable } from '../lib/scan/bootSector'

const props = withDefaults(defineProps<{
	image: Uint8Array
	highlightOffsets?: number[]
}>(), {
	highlightOffsets: () => [],
})

const ROW_BYTES = 16

interface Row {
	offset: number
	/** Pre-formatted hex string for display — 16 bytes, 8+8 with space between. */
	hex: string
	ascii: string
	isHighlighted: boolean
	highlightedByteIndices: number[]
}

function formatHexLine(bytes: number[]): string {
	// 16 bytes in two groups of 8, like a classic hex editor.
	return bytes.map((b, i) => {
		const sep = (i > 0 && i % 8 === 0) ? ' ' : (i > 0 ? ' ' : '')
		return sep + b.toString(16).padStart(2, '0').toUpperCase()
	}).join('')
}

const rows = computed<Row[]>(() => {
	let boot: Uint8Array
	try {
		boot = getBootSector(props.image)
	} catch {
		// If the image is too short to contain a boot sector, show what's
		// there rather than crash. The scanner already reported the error.
		boot = getImageBytes(props.image).subarray(0, 512)
	}

	const out: Row[] = []
	for (let r = 0; r < boot.length; r += ROW_BYTES) {
		const slice = Array.from(boot.subarray(r, r + ROW_BYTES))
		const ascii = slice
			.map(b => (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '·')
			.join('')

		// Determine which bytes in THIS row are highlighted.
		const highlightedByteIndices: number[] = []
		for (let i = 0; i < slice.length; i++) {
			if (highlightSet.value.has(r + i)) highlightedByteIndices.push(i)
		}

		const isHighlighted = highlightedByteIndices.length > 0
		out.push({
			offset: r,
			hex: formatHexLine(slice),
			ascii,
			isHighlighted,
			highlightedByteIndices,
		})
	}
	return out
})

const highlightSet = computed(() => new Set(props.highlightOffsets))

const executable = computed(() => {
	try {
		return isBootSectorExecutable(getBootSector(props.image))
	} catch {
		return false
	}
})
</script>

<template>
	<div class="hex" role="region" aria-label="Boot sector in hex">
		<p class="hex__status muted">
			Boot sector checksum: {{ executable ? 'executable (0x1234)' : 'not executable' }}
		</p>
		<pre class="hex__body"><code><span
			v-for="row in rows"
			:key="row.offset"
			class="hex__row"
			:class="{ 'hex__row--highlight': row.isHighlighted }"
		><span class="hex__offset">{{ row.offset.toString(16).padStart(8, '0').toUpperCase() }}</span><span class="hex__hex">{{ row.hex }}</span><span class="hex__ascii">{{ row.ascii }}</span></span>
</code></pre>
	</div>
</template>

<style scoped>
.hex {
	font-family: var(--font-mono);
	font-size: 0.9rem;
	line-height: 1.3;
	background: #1a1a1a;
	color: #d0d0d0;
	border-top: 2px solid var(--color-ink);
	margin: 0;
}

.hex__status {
	padding: 0.5rem 0.75rem;
	margin: 0;
	border-bottom: 1px solid #333;
	font-size: 0.8rem;
	color: #aaa;
}

.hex__body {
	margin: 0;
	padding: 0.5rem 0.75rem;
	overflow-x: auto;
	white-space: pre;
}

.hex__row {
	display: block;
	padding: 1px 0;
}

.hex__row--highlight {
	background: rgba(196, 122, 0, 0.28);
	box-shadow: inset 2px 0 0 var(--color-warning);
}

.hex__offset {
	color: #888;
	display: inline-block;
	min-width: 8.5rem;
}

.hex__hex {
	display: inline-block;
	min-width: 50rem;
}

.hex__byte--highlight {
	background: var(--color-warning);
	color: #000;
	font-weight: bold;
}

.hex__ascii {
	color: #6ecf78;
	opacity: 0.85;
}

@media (max-width: 900px) {
	.hex__body {
		font-size: 0.75rem;
	}
	.hex__offset { min-width: 6rem; }
	.hex__hex { min-width: 0; }
}
</style>