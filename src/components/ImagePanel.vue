<script setup lang="ts">
import { ref, computed, watch, onMounted, nextTick } from 'vue'
import { parseImage, type DecodedImage } from '../lib/images/parsers'

interface Props {
	name: string
	bytes: Uint8Array
	origin: 'raw' | 'disk'
}

const props = defineProps<Props>()
const emit = defineEmits<{
	(e: 'close'): void
	(e: 'back'): void
}>()

const ZOOM_LEVELS = [1, 2, 4, 8] as const
const zoom = ref(4) // default to 4× — 320×200 is tiny at 1×

const canvas = ref<HTMLCanvasElement | null>(null)
const parseError = ref<string | null>(null)

const decoded = computed<DecodedImage | null>(() => {
	parseError.value = null
	try {
		return parseImage(props.bytes, props.name)
	} catch (e) {
		parseError.value = e instanceof Error ? e.message : String(e)
		return null
	}
})

const paletteSwatches = computed(() => {
	const pal = decoded.value?.palette ?? []
	// Spectrum images can have hundreds of unique colours — cap the swatch
	// strip so the UI stays readable.
	return pal.length > 64 ? pal.slice(0, 64) : pal
})

onMounted(render)
watch([decoded, zoom], () => nextTick(render))

function render() {
	const img = decoded.value
	const c = canvas.value
	if (!img || !c) return

	c.width = img.width
	c.height = img.height
	const ctx = c.getContext('2d')
	if (!ctx) return

	// Pre-compute palette as a flat RGB table so the inner loop has no
	// string parsing. Three bytes per entry.
	const rgb = new Uint8Array(img.palette.length * 3)
	img.palette.forEach((hex, i) => {
		rgb[i * 3]     = parseInt(hex.slice(1, 3), 16)
		rgb[i * 3 + 1] = parseInt(hex.slice(3, 5), 16)
		rgb[i * 3 + 2] = parseInt(hex.slice(5, 7), 16)
	})

	const imageData = ctx.createImageData(img.width, img.height)
	const data = imageData.data
	for (let i = 0; i < img.pixels.length; i++) {
		const idx = img.pixels[i]
		const off = idx * 3
		data[i * 4]     = rgb[off]
		data[i * 4 + 1] = rgb[off + 1]
		data[i * 4 + 2] = rgb[off + 2]
		data[i * 4 + 3] = 255
	}
	ctx.putImageData(imageData, 0, 0)
}

function downloadPng() {
	const c = canvas.value
	if (!c) return
	c.toBlob((blob) => {
		if (!blob) return
		const url = URL.createObjectURL(blob)
		const a = document.createElement('a')
		a.href = url
		a.download = props.name.replace(/\.[^.]+$/, '') + '.png'
		a.click()
		URL.revokeObjectURL(url)
	}, 'image/png')
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

		<p v-if="parseError" class="error">
			Could not parse image: {{ parseError }}
		</p>

		<template v-else-if="decoded">
			<dl class="meta cluster">
				<div><dt>Format</dt><dd>{{ decoded.format.toUpperCase() }}</dd></div>
				<div><dt>Dimensions</dt><dd>{{ decoded.width }}×{{ decoded.height }}</dd></div>
				<div><dt>Palette</dt><dd>{{ decoded.palette.length }} colours</dd></div>
				<div><dt>Zoom</dt>
					<dd>
						<div class="zoom-cluster">
							<button
								v-for="z in ZOOM_LEVELS"
								:key="z"
								type="button"
								class="zoom-btn"
								:class="{ 'zoom-btn--active': zoom === z }"
								@click="zoom = z"
							>{{ z }}×</button>
						</div>
					</dd>
				</div>
			</dl>

			<dl class="palette">
				<dt>Palette</dt>
				<dd>
					<span
						v-for="(hex, i) in paletteSwatches"
						:key="i"
						class="palette__swatch"
						:style="{ background: hex }"
						:title="`${i}: ${hex}`"
					>{{ i }}</span>
				</dd>
			</dl>

			<div class="cluster actions">
				<button class="btn" type="button" @click="downloadPng">Download .PNG</button>
			</div>

			<div class="canvas-wrap" :style="{ '--zoom': zoom }">
				<canvas ref="canvas" class="pixel-canvas"></canvas>
			</div>
		</template>
	</article>
</template>

<style scoped>
.error {
	color: var(--color-danger);
	font-family: var(--font-mono);
	padding: 0.75rem 1rem;
	margin: 0;
}

.meta {
	font-family: var(--font-mono);
	font-size: 1rem;
	margin: 0;
	padding: 0.75rem 1rem;
	align-items: flex-start;
}

.meta dt {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
	margin-bottom: 0.25rem;
}

.meta dd { margin: 0; }

.zoom-cluster {
	display: inline-flex;
	gap: 0.25rem;
}

.zoom-btn {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	background: #eee;
	color: #000;
	border: 2px solid #000;
	padding: 0.25rem 0.5rem;
	cursor: pointer;
}

.zoom-btn:hover { background: #ddd; }

.zoom-btn--active {
	background: var(--color-st-green);
	color: #000;
}

.palette {
	display: flex;
	align-items: flex-start;
	gap: 1rem;
	padding: 0.5rem 1rem;
	margin: 0;
	font-family: var(--font-mono);
	font-size: 0.85rem;
	border-top: 1px solid #e0e0e0;
}

.palette dt {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
	margin-bottom: 0.25rem;
	flex-shrink: 0;
}

.palette dd {
	margin: 0;
	display: flex;
	flex-wrap: wrap;
	gap: 2px;
}

.palette__swatch {
	display: inline-block;
	width: 1.5rem;
	height: 1.5rem;
	font-family: var(--font-pixel);
	font-size: 7px;
	color: #fff;
	text-shadow: 0 0 2px #000;
	text-align: center;
	line-height: 1.5rem;
	border: 1px solid #000;
}

.actions { padding: 0 1rem; }

.canvas-wrap {
	padding: 1rem;
	display: flex;
	justify-content: center;
	background: #111;
	overflow: auto;
}

.pixel-canvas {
	image-rendering: pixelated;
	image-rendering: crisp-edges;
	width: calc(320px * var(--zoom, 1));
	height: calc(200px * var(--zoom, 1));
	max-width: none;
	border: 2px solid var(--color-st-green);
	box-shadow: 0 0 0 2px #000;
}

@media (max-width: 600px) {
	.meta { font-size: 0.9rem; }
	.palette__swatch { width: 1.2rem; height: 1.2rem; line-height: 1.2rem; }
}
</style>
