<script setup lang="ts">
import { ref, shallowRef, computed } from 'vue'
import FileDrop from '../components/FileDrop.vue'
import DiskFileList from '../components/DiskFileList.vue'
import TextPanel from '../components/TextPanel.vue'
import ImagePanel from '../components/ImagePanel.vue'
import { openDiskImage } from '../lib/disk/diskImage'
import type { Fat12Image, FileEntry } from '../lib/disk/fat12'
import { imageKindFromName } from '../lib/images/parsers'
import { useDropHandler } from '../composables/useDropZone'

interface DiskSource {
	fileName: string
	image: Fat12Image
}

interface TextSource {
	name: string
	bytes: Uint8Array
	origin: 'raw' | 'disk'
}

interface ImageSource {
	name: string
	bytes: Uint8Array
	origin: 'raw' | 'disk'
}

type FileKind = 'disk-image' | 'image' | 'text'

const disk = shallowRef<DiskSource | null>(null)
const text = ref<TextSource | null>(null)
const image = ref<ImageSource | null>(null)
const error = ref<string | null>(null)

// Computed view-model so the template can use a single clean `v-if` per
// state. Vue's template type-narrowing doesn't always carry through `&&`
// chains; computing the visible state up front sidesteps that.
const visibleDisk = computed<DiskSource | null>(() =>
	disk.value && !text.value && !image.value ? disk.value : null,
)

function classifyByName(name: string): FileKind {
	if (looksLikeDiskImage(name)) return 'disk-image'
	if (imageKindFromName(name) !== null) return 'image'
	return 'text'
}

async function onFiles(files: File[]) {
	error.value = null
	const file = files[0]
	if (!file) return

	try {
		const bytes = new Uint8Array(await file.arrayBuffer())
		const kind = classifyByName(file.name)
		if (kind === 'disk-image') {
			openAsDisk(file.name, bytes)
		} else if (kind === 'image') {
			image.value = { name: file.name, bytes, origin: 'raw' }
			text.value = null
			disk.value = null
		} else {
			text.value = { name: file.name, bytes, origin: 'raw' }
			image.value = null
			disk.value = null
		}
	} catch (e) {
		error.value = `${file.name}: ${e instanceof Error ? e.message : String(e)}`
	}
}

function looksLikeDiskImage(name: string): boolean {
	const lower = name.toLowerCase()
	return lower.endsWith('.st') || lower.endsWith('.msa') || lower.endsWith('.stx')
}

function openAsDisk(fileName: string, bytes: Uint8Array) {
	const opened = openDiskImage(bytes)
	disk.value = { fileName, image: opened.image }
	text.value = null
	image.value = null
}

function pickFileFromDisk(entry: FileEntry) {
	if (!disk.value) return
	try {
		const bytes = disk.value.image.readFile(entry.entry)
		const name = entry.path.replace(/^\//, '')
		const kind = classifyByName(name)
		if (kind === 'image') {
			image.value = { name, bytes, origin: 'disk' }
			text.value = null
		} else {
			text.value = { name, bytes, origin: 'disk' }
			image.value = null
		}
	} catch (e) {
		error.value = `Could not read ${entry.path}: ${e instanceof Error ? e.message : String(e)}`
	}
}

function backToList() {
	text.value = null
	image.value = null
}

function closeAll() {
	disk.value = null
	text.value = null
	image.value = null
	error.value = null
}

// Window-wide drop: receive files dropped anywhere on the page.
useDropHandler(onFiles)
</script>

<template>
	<section class="stack">
		<div>
			<h1>File Renderer</h1>
			<p class="muted">
				Drop an Atari ST text file, an image (<code>.PI1</code>/<code>.PI2</code>/<code>.PI3</code>,
				<code>.TNY</code>, <code>.SPU</code>, <code>.NEO</code>, <code>.IFF</code>), or a <code>.st</code> /
				<code>.msa</code> / <code>.stx</code> disk image to pick a file out of. Bytes are
				decoded in-browser — nothing leaves your machine.
			</p>
		</div>

		<FileDrop
			v-if="!disk && !text && !image"
			accept=".txt,.tos,.asc,.doc,.pi1,.pi2,.pi3,.tny,.tn1,.tn2,.tn3,.spu,.spl,.neo,.ne,.iff,.ilbm,.st,.msa,.stx"
			label="Drop an ST text file, image, or .ST / .MSA / .STX disk image — or click to pick"
			@select="onFiles"
		/>

		<p v-if="error" class="error">{{ error }}</p>

		<article v-if="visibleDisk" class="gem-window">
			<header class="gem-window__title">
				<span>{{ visibleDisk.fileName }} — pick a file</span>
				<button type="button" @click="closeAll">Close</button>
			</header>
			<DiskFileList
				:image="visibleDisk.image"
				@select="pickFileFromDisk"
				@close="closeAll"
			/>
		</article>

		<TextPanel
			v-if="text"
			:name="text.name"
			:bytes="text.bytes"
			:origin="text.origin"
			@close="closeAll"
			@back="backToList"
		/>

		<ImagePanel
			v-if="image"
			:name="image.name"
			:bytes="image.bytes"
			:origin="image.origin"
			@close="closeAll"
			@back="backToList"
		/>

		<!-- If the user is viewing a file from a disk, keep the disk image
		     loaded in the background so "back to list" works. -->
		<p
			v-if="disk && (text?.origin === 'disk' || image?.origin === 'disk')"
			class="disk-banner muted"
		>
			From disk image: <code>{{ disk.fileName }}</code>
		</p>
	</section>
</template>

<style scoped>
.error {
	color: var(--color-danger);
	font-family: var(--font-mono);
}

.disk-banner {
	font-family: var(--font-mono);
	font-size: 0.95rem;
	margin: 0;
}
</style>
