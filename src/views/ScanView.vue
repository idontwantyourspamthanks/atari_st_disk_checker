<script setup lang="ts">
import { ref, computed } from 'vue'
import FileDrop from '../components/FileDrop.vue'
import ScanReportCard from '../components/ScanReportCard.vue'
import { scanImage, type ScanReport } from '../lib/scan/scanner'
import { extractDiskImagesFromZip } from '../lib/scan/zip'
import { reportsToJson, reportsToCsv, downloadTextFile } from '../lib/scan/export'
import { useDropHandler } from '../composables/useDropZone'

const reports = ref<ScanReport[]>([])
const error = ref<string | null>(null)
const skipped = ref<string[]>([])
const isScanning = ref(false)
/** Images completed / total in the current batch (null when idle). */
const scanProgress = ref<{ done: number; total: number } | null>(null)

const summary = computed(() => {
	const r = reports.value
	return {
		total:      r.length,
		clean:      r.filter(x => x.status === 'clean').length,
		protected:  r.filter(x => x.status === 'protected').length,
		suspicious: r.filter(x => x.status === 'suspicious').length,
		infected:   r.filter(x => x.status === 'infected').length,
		error:      r.filter(x => x.status === 'error').length,
	}
})

// Sort reports so the most-concerning ones surface to the top.
const severityRank: Record<ScanReport['status'], number> = {
	infected: 0, suspicious: 1, protected: 2, error: 3, clean: 4,
}
const sortedReports = computed(() =>
	[...reports.value].sort((a, b) => severityRank[a.status] - severityRank[b.status]),
)

/** Let the browser paint between images so big ZIP batches stay responsive. */
function yieldToUi(): Promise<void> {
	return new Promise(resolve => {
		requestAnimationFrame(() => resolve())
	})
}

async function onFiles(files: File[]) {
	error.value = null
	reports.value = []
	skipped.value = []
	isScanning.value = true
	scanProgress.value = null

	try {
		type Job = { bytes: Uint8Array; name: string }
		const jobs: Job[] = []

		for (const file of files) {
			const bytes = new Uint8Array(await file.arrayBuffer())
			const lower = file.name.toLowerCase()

			if (lower.endsWith('.zip')) {
				const zip = extractDiskImagesFromZip(bytes)
				if (zip.error) {
					error.value = `${file.name}: ${zip.error}`
					continue
				}
				for (const entry of zip.entries) {
					jobs.push({ bytes: entry.bytes, name: entry.name })
				}
				skipped.value.push(...zip.skipped)
			} else {
				jobs.push({ bytes, name: file.name })
			}
		}

		const collected: ScanReport[] = []
		scanProgress.value = { done: 0, total: jobs.length }

		for (let i = 0; i < jobs.length; i++) {
			const job = jobs[i]!
			collected.push(scanImage(job.bytes, job.name))
			reports.value = collected.slice()
			scanProgress.value = { done: i + 1, total: jobs.length }
			// Yield every image so the summary/cards can paint mid-batch.
			await yieldToUi()
		}
	} catch (e) {
		error.value = e instanceof Error ? e.message : String(e)
	} finally {
		isScanning.value = false
		scanProgress.value = null
	}
}

function clear() {
	reports.value = []
	error.value = null
	skipped.value = []
}

function exportJson() {
	const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
	downloadTextFile(reportsToJson(reports.value), `diskcheck-report-${stamp}.json`, 'application/json')
}

function exportCsv() {
	const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
	downloadTextFile(reportsToCsv(reports.value), `diskcheck-report-${stamp}.csv`, 'text/csv')
}

// Window-wide drop: receive files dropped anywhere on the page.
useDropHandler(onFiles)
</script>

<template>
	<section class="stack">
		<div>
			<h1>Virus Scan</h1>
			<p class="muted">
				Drop <code>.st</code> / <code>.msa</code> / <code>.stx</code> disk images, or a
				<code>.zip</code> archive of them. Each image's boot sector is
				checked for known viruses, boot protectors, and behavioural
				heuristics. Nothing leaves your browser.
			</p>
		</div>

		<FileDrop
			v-if="reports.length === 0 && !error && !isScanning"
			accept=".st,.msa,.stx,.zip"
			multiple
			label="Drop .ST / .MSA / .STX / .ZIP — or click to pick"
			@select="onFiles"
		/>

		<p v-if="isScanning && scanProgress" class="scan-progress gem-window">
			Scanning
			<strong>{{ scanProgress.done }}</strong>
			/
			<strong>{{ scanProgress.total }}</strong>
			…
		</p>

		<p v-if="error" class="error">{{ error }}</p>

		<section v-if="reports.length > 0" class="stack">
			<div class="summary gem-window">
				<header class="gem-window__title">
					<span>Summary</span>
					<div class="summary__actions">
						<button type="button" class="summary__export" :disabled="isScanning" @click="exportJson">JSON</button>
						<button type="button" class="summary__export" :disabled="isScanning" @click="exportCsv">CSV</button>
						<button type="button" :disabled="isScanning" @click="clear">Clear</button>
					</div>
				</header>
				<dl class="summary__grid">
					<div><dt>Scanned</dt><dd>{{ summary.total }}</dd></div>
					<div class="summary--clean"><dt>Clean</dt><dd>{{ summary.clean }}</dd></div>
					<div class="summary--protected"><dt>Protected</dt><dd>{{ summary.protected }}</dd></div>
					<div class="summary--suspicious"><dt>Suspicious</dt><dd>{{ summary.suspicious }}</dd></div>
					<div class="summary--infected"><dt>Infected</dt><dd>{{ summary.infected }}</dd></div>
					<div v-if="summary.error > 0" class="summary--error"><dt>Errors</dt><dd>{{ summary.error }}</dd></div>
				</dl>
				<p v-if="skipped.length > 0" class="summary__skipped muted">
					Ignored {{ skipped.length }} non-disk file{{ skipped.length === 1 ? '' : 's' }}
					from the archive{{ skipped.length === 1 ? '' : 's' }}.
				</p>
			</div>

			<div class="reports">
				<ScanReportCard
					v-for="report in sortedReports"
					:key="report.fileName"
					:report="report"
				/>
			</div>
		</section>
	</section>
</template>

<style scoped>
.error {
	color: var(--color-danger);
	font-family: var(--font-mono);
}

.scan-progress {
	margin: 0;
	padding: 0.75rem 1rem;
	font-family: var(--font-pixel);
	font-size: var(--text-sm);
	color: var(--color-ink);
}

.scan-progress strong {
	font-family: var(--font-mono);
	font-size: 1.25rem;
	color: var(--color-st-green);
}

.summary__grid {
	display: flex;
	flex-wrap: wrap;
	gap: 1rem 2rem;
	margin: 0;
	font-family: var(--font-mono);
}

.summary__grid > div {
	min-width: 5rem;
}

.summary__grid dt {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
	margin-bottom: 0.25rem;
}

.summary__grid dd {
	margin: 0;
	font-family: var(--font-pixel);
	font-size: var(--text-lg);
}

.summary--clean dd      { color: var(--color-st-green); }
.summary--protected dd  { color: #2a6f97; }
.summary--suspicious dd { color: var(--color-warning); }
.summary--infected dd   { color: var(--color-danger); }
.summary--error dd      { color: var(--color-muted); }

.summary__skipped {
	margin: 0.75rem 0 0 0;
	font-size: 0.9rem;
}

.summary__actions {
	display: inline-flex;
	gap: 0.35rem;
}

.summary__export {
	background: var(--color-panel);
	border: 2px solid var(--color-ink);
	color: var(--color-ink);
}

.summary__actions button:disabled {
	opacity: 0.45;
	cursor: not-allowed;
}

.reports {
	display: grid;
	gap: 1rem;
}

@media (max-width: 600px) {
	.summary__grid {
		gap: 0.75rem 1.5rem;
	}
	.summary__grid dd { font-size: var(--text-md); }
}
</style>
