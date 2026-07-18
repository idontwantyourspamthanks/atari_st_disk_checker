<script setup lang="ts">
import { computed, ref } from 'vue'
import type { ScanReport, ScanStatus } from '../lib/scan/scanner'
import HexView from './HexView.vue'

const props = defineProps<{ report: ScanReport }>()

const statusLabel = computed(() => props.report.status.toUpperCase())

const statusGlyph: Record<ScanStatus, string> = {
	clean: 'OK',
	protected: 'PR',
	suspicious: '??',
	infected: '!!',
	error: 'XX',
}

const showHex = ref(false)

// Aggregate every finding's highlightOffsets into a single list for the
// hex viewer — so toggling the view shows all the bytes any detector
// flagged, regardless of which finding the user is currently reading.
const highlightOffsets = computed(() => {
	const seen = new Set<number>()
	for (const f of props.report.findings) {
		if (f.highlightOffsets) for (const o of f.highlightOffsets) seen.add(o)
	}
	return [...seen].sort((a, b) => a - b)
})

function toHex(n: number): string {
	return '0x' + n.toString(16).toUpperCase().padStart(4, '0')
}

function formatBytes(n: number): string {
	if (n < 1024) return `${n} B`
	const kb = n / 1024
	return kb < 1024 ? `${kb.toFixed(1)} KB` : `${(kb / 1024).toFixed(2)} MB`
}

function toggleHex() {
	showHex.value = !showHex.value
}

function infectionLabel(status: NonNullable<ScanReport['findings'][number]['infectionStatus']>): string {
	switch (status) {
		case 'infected':          return 'INFECTED'
		case 'probably-infected': return 'PROBABLE'
		case 'immunized':         return 'IMMUNIZED'
		case 'unclear':           return 'UNCLEAR'
	}
}
</script>

<template>
	<article class="scan-card" :class="`scan-card--${report.status}`" :data-testid="`scan-${report.fileName}`">
		<header class="scan-card__header">
			<span class="scan-card__glyph" aria-hidden="true">{{ statusGlyph[report.status] }}</span>
			<div class="scan-card__title">
				<span class="scan-card__name">{{ report.fileName }}</span>
				<span class="scan-card__status">{{ statusLabel }}</span>
			</div>
			<span class="scan-card__format">{{ report.format }}</span>
		</header>

		<p v-if="report.error" class="scan-card__error">
			Could not scan: {{ report.error }}
		</p>

		<dl v-else class="scan-card__meta">
			<div><dt>Image size</dt><dd>{{ formatBytes(report.imageBytes) }}</dd></div>
			<div><dt>Boot checksum</dt><dd>{{ toHex(report.bootSectorChecksum) }}</dd></div>
			<div>
				<dt>TOS would execute</dt>
				<dd>{{ report.bootSectorExecutable ? 'yes' : 'no' }}</dd>
			</div>
		</dl>

		<button
			v-if="report.bootSector && !showHex"
			type="button"
			class="scan-card__hex-toggle"
			@click="toggleHex"
		>Show boot sector</button>

		<HexView
			v-else-if="report.bootSector && showHex"
			:image="report.bootSector"
			:highlight-offsets="highlightOffsets"
		/>

		<ul v-if="report.findings.length > 0" class="scan-card__findings">
			<li
				v-for="finding in report.findings"
				:key="finding.name"
				:class="`finding finding--${finding.severity} finding--${finding.kind}`"
			>
				<div class="finding__head">
					<span class="finding__kind">{{
						finding.kind === 'signature' ? 'VIRUS'
						: finding.kind === 'protector' ? 'PROT'
						: 'FLAG'
					}}</span>
					<span class="finding__name">{{ finding.name }}</span>
					<span
						v-if="finding.infectionStatus"
						class="finding__infection"
						:class="`finding__infection--${finding.infectionStatus}`"
					>{{ infectionLabel(finding.infectionStatus) }}</span>
				</div>
				<p class="finding__detail">{{ finding.detail }}</p>
			</li>
		</ul>

		<p v-else-if="!report.error" class="scan-card__nofindings muted">
			No signatures matched and no heuristics tripped. Boot sector looks like
			a standard data-disk sector.
		</p>
	</article>
</template>

<style scoped>
.scan-card {
	background: var(--color-panel);
	color: var(--color-ink);
	border: 2px solid var(--color-ink);
	box-shadow: var(--shadow-gem);
	padding: 0;
	margin: 0;
}

.scan-card--clean      { border-color: var(--color-st-green);  box-shadow: 4px 4px 0 var(--color-st-green-dim); }
.scan-card--protected  { border-color: #2a6f97;               box-shadow: 4px 4px 0 #1b4d6a; }
.scan-card--suspicious { border-color: var(--color-warning);   box-shadow: 4px 4px 0 #8a5500; }
.scan-card--infected   { border-color: var(--color-danger);    box-shadow: 4px 4px 0 #7a1818; }
.scan-card--error      { border-color: var(--color-ink);       box-shadow: var(--shadow-gem); }

.scan-card__header {
	display: flex;
	align-items: center;
	gap: 0.75rem;
	padding: 0.75rem 1rem;
	border-bottom: 2px solid var(--color-ink);
	background: var(--color-panel-dim);
}

.scan-card--clean .scan-card__header      { background: var(--color-st-green-soft); }
.scan-card--protected .scan-card__header  { background: rgba(42, 111, 151, 0.15); }
.scan-card--suspicious .scan-card__header { background: rgba(196, 122, 0, 0.18); }
.scan-card--infected .scan-card__header   { background: rgba(196, 40, 40, 0.15); }
.scan-card--error .scan-card__header      { background: var(--color-panel-dim); }

.scan-card__glyph {
	font-family: var(--font-pixel);
	font-size: var(--text-md);
	min-width: 2.5rem;
	text-align: center;
}

.scan-card--clean .scan-card__glyph      { color: var(--color-st-green); }
.scan-card--protected .scan-card__glyph  { color: #2a6f97; }
.scan-card--suspicious .scan-card__glyph { color: var(--color-warning); }
.scan-card--infected .scan-card__glyph   { color: var(--color-danger); }
.scan-card--error .scan-card__glyph      { color: var(--color-ink); }

.scan-card__title {
	display: flex;
	flex-direction: column;
	flex: 1;
	min-width: 0;
}

.scan-card__name {
	font-family: var(--font-mono);
	font-size: 1.05rem;
	color: var(--color-ink);
	word-break: break-all;
}

.scan-card__status {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	margin-top: 0.25rem;
}

.scan-card--clean .scan-card__status      { color: var(--color-st-green); }
.scan-card--protected .scan-card__status  { color: #2a6f97; }
.scan-card--suspicious .scan-card__status { color: var(--color-warning); }
.scan-card--infected .scan-card__status   { color: var(--color-danger); }

.scan-card__format {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
	text-transform: uppercase;
}

.scan-card__error {
	margin: 0;
	padding: 0.75rem 1rem;
	font-family: var(--font-mono);
	color: var(--color-danger);
}

.scan-card__meta {
	display: flex;
	flex-wrap: wrap;
	gap: 1rem 2rem;
	margin: 0;
	padding: 0.75rem 1rem;
	font-family: var(--font-mono);
	font-size: 0.95rem;
}

.scan-card__meta dt {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
	margin-bottom: 0.25rem;
}

.scan-card__meta dd { margin: 0; }

.scan-card__hex-toggle {
	display: block;
	width: 100%;
	background: transparent;
	border: 0;
	border-top: 2px solid var(--color-panel-dim);
	border-bottom: 2px solid var(--color-panel-dim);
	color: var(--color-muted);
	font-family: var(--font-mono);
	font-size: 0.9rem;
	padding: 0.5rem 1rem;
	cursor: pointer;
	text-align: left;
}

.scan-card__hex-toggle:hover {
	background: var(--color-st-green-soft);
	color: var(--color-st-green);
}

.scan-card__findings {
	list-style: none;
	margin: 0;
	padding: 0;
}

.finding {
	padding: 0.75rem 1rem;
	border-top: 1px solid var(--color-panel-dim);
}

.finding--high    { background: rgba(196, 40, 40, 0.08); }
.finding--medium  { background: rgba(196, 122, 0, 0.08); }
.finding--low     { background: var(--color-st-green-soft); }
.finding--info    { background: rgba(42, 111, 151, 0.08); }

.finding--protector .finding__kind { background: #2a6f97; color: #fff; }

.finding__head {
	display: flex;
	align-items: baseline;
	gap: 0.75rem;
	margin-bottom: 0.4rem;
	flex-wrap: wrap;
}

.finding__kind {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	padding: 0.15rem 0.4rem;
	background: var(--color-ink);
	color: var(--color-panel);
}

.finding--high .finding__kind   { background: var(--color-danger); color: #fff; }
.finding--medium .finding__kind { background: var(--color-warning); color: #000; }
.finding--low .finding__kind    { background: var(--color-st-green); color: var(--color-on-accent); }

.finding__name {
	font-family: var(--font-pixel);
	font-size: var(--text-sm);
	color: var(--color-ink);
}

.finding__infection {
	margin-left: auto;
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	padding: 0.15rem 0.4rem;
	border: 1px solid;
}

.finding__infection--infected          { color: var(--color-danger);   border-color: var(--color-danger);  background: rgba(196, 40, 40, 0.12); }
.finding__infection--probably-infected { color: var(--color-warning);  border-color: var(--color-warning); background: rgba(196, 122, 0, 0.12); }
.finding__infection--immunized         { color: var(--color-st-green); border-color: var(--color-st-green); background: var(--color-st-green-soft); }
.finding__infection--unclear           { color: var(--color-muted);    border-color: var(--color-muted);    background: rgba(61, 92, 64, 0.12); }

.finding__detail {
	margin: 0;
	font-family: var(--font-mono);
	font-size: 0.95rem;
	line-height: 1.4;
	color: var(--color-ink);
	opacity: 0.9;
}

.scan-card__nofindings {
	padding: 0.75rem 1rem;
	margin: 0;
	font-family: var(--font-mono);
	font-size: 0.95rem;
}

@media (max-width: 600px) {
	.scan-card__header {
		flex-wrap: wrap;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
	}
	.scan-card__meta, .finding, .scan-card__nofindings, .scan-card__error {
		padding: 0.5rem 0.75rem;
	}
}
</style>
