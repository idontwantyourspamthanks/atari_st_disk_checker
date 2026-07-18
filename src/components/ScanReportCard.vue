<script setup lang="ts">
import { computed, ref } from 'vue'
import type { ScanFinding, ScanReport, ScanStatus } from '../lib/scan/scanner'
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
/** One control expands every finding's detail for this disk image. */
const detailsOpen = ref(false)

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

function toggleDetails() {
	detailsOpen.value = !detailsOpen.value
}

function infectionLabel(status: NonNullable<ScanFinding['infectionStatus']>): string {
	switch (status) {
		case 'infected':          return 'INFECTED'
		case 'probably-infected': return 'PROBABLE'
		case 'immunized':         return 'IMMUNIZED'
		case 'unclear':           return 'UNCLEAR'
	}
}

/** Compact kind glyph — colour comes from severity/kind CSS. */
function kindIcon(kind: ScanFinding['kind']): string {
	switch (kind) {
		case 'signature': return '!'
		case 'protector': return 'P'
		case 'sandbox':   return 'E'
		case 'heuristic': return '?'
	}
}

function kindLabel(kind: ScanFinding['kind']): string {
	switch (kind) {
		case 'signature': return 'Virus signature'
		case 'protector': return 'Boot protector'
		case 'sandbox':   return 'Sandbox execution'
		case 'heuristic': return 'Heuristic flag'
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

		<div v-if="report.findings.length > 0" class="scan-card__findings-wrap">
			<div class="scan-card__findings-bar">
				<span class="scan-card__findings-count">
					{{ report.findings.length }}
					{{ report.findings.length === 1 ? 'finding' : 'findings' }}
				</span>
				<button
					type="button"
					class="scan-card__details-toggle"
					:aria-expanded="detailsOpen"
					@click="toggleDetails"
				>{{ detailsOpen ? 'Hide details' : 'Show details' }}</button>
			</div>

			<ul class="scan-card__findings">
				<li
					v-for="(finding, index) in report.findings"
					:key="`${index}-${finding.kind}-${finding.name}`"
					:class="`finding finding--${finding.severity} finding--${finding.kind}`"
				>
					<div class="finding__tldr">
						<span
							class="finding__icon"
							:title="kindLabel(finding.kind)"
							:aria-label="kindLabel(finding.kind)"
						>{{ kindIcon(finding.kind) }}</span>
						<span class="finding__name">{{ finding.name }}</span>
						<span
							v-if="finding.infectionStatus"
							class="finding__infection"
							:class="`finding__infection--${finding.infectionStatus}`"
						>{{ infectionLabel(finding.infectionStatus) }}</span>
					</div>
					<p v-if="detailsOpen" class="finding__detail">{{ finding.detail }}</p>
				</li>
			</ul>
		</div>

		<p v-else-if="!report.error" class="scan-card__nofindings muted">
			No signatures, heuristics, or sandbox residency checks tripped.
			Boot sector looks like a standard data-disk sector.
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

.scan-card__findings-wrap {
	border-top: 2px solid var(--color-panel-dim);
}

.scan-card__findings-bar {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: 0.75rem;
	padding: 0.4rem 1rem;
	background: var(--color-panel-dim);
}

.scan-card__findings-count {
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	color: var(--color-muted);
}

.scan-card__details-toggle {
	background: transparent;
	border: 1px solid var(--color-ink);
	color: var(--color-ink);
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	padding: 0.25rem 0.5rem;
	cursor: pointer;
	box-shadow: var(--shadow-gem-sm);
}

.scan-card__details-toggle:hover {
	background: var(--color-panel);
}

.scan-card__details-toggle:focus-visible {
	outline: 2px solid var(--color-st-green);
	outline-offset: 2px;
}

.scan-card__findings {
	list-style: none;
	margin: 0;
	padding: 0;
}

.finding {
	padding: 0.45rem 1rem;
	border-top: 1px solid var(--color-panel-dim);
	border-left: 4px solid transparent;
}

.finding--high    { border-left-color: var(--color-danger);  background: rgba(196, 40, 40, 0.06); }
.finding--medium  { border-left-color: var(--color-warning); background: rgba(196, 122, 0, 0.06); }
.finding--low     { border-left-color: var(--color-st-green); background: var(--color-st-green-soft); }
.finding--info    { border-left-color: #2a6f97; background: rgba(42, 111, 151, 0.06); }

.finding__tldr {
	display: flex;
	align-items: center;
	gap: 0.6rem;
	min-width: 0;
}

.finding__icon {
	flex: 0 0 auto;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 1.5rem;
	height: 1.5rem;
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	background: var(--color-ink);
	color: var(--color-panel);
}

.finding--high .finding__icon   { background: var(--color-danger); color: #fff; }
.finding--medium .finding__icon { background: var(--color-warning); color: #000; }
.finding--low .finding__icon    { background: var(--color-st-green); color: var(--color-on-accent); }
.finding--info .finding__icon   { background: #2a6f97; color: #fff; }

.finding--protector.finding--info .finding__icon,
.finding--protector .finding__icon { background: #2a6f97; color: #fff; }
.finding--sandbox .finding__icon { background: #5a4a8a; color: #fff; }

.finding__name {
	flex: 1;
	min-width: 0;
	font-family: var(--font-pixel);
	font-size: var(--text-sm);
	color: var(--color-ink);
	line-height: 1.35;
}

.finding__infection {
	flex: 0 0 auto;
	font-family: var(--font-pixel);
	font-size: var(--text-xs);
	padding: 0.15rem 0.35rem;
	border: 1px solid;
}

.finding__infection--infected          { color: var(--color-danger);   border-color: var(--color-danger);  background: rgba(196, 40, 40, 0.12); }
.finding__infection--probably-infected { color: var(--color-warning);  border-color: var(--color-warning); background: rgba(196, 122, 0, 0.12); }
.finding__infection--immunized         { color: var(--color-st-green); border-color: var(--color-st-green); background: var(--color-st-green-soft); }
.finding__infection--unclear           { color: var(--color-muted);    border-color: var(--color-muted);    background: rgba(61, 92, 64, 0.12); }

.finding__detail {
	margin: 0.45rem 0 0 2.1rem;
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
	.scan-card__meta,
	.finding,
	.scan-card__nofindings,
	.scan-card__error,
	.scan-card__findings-bar {
		padding-left: 0.75rem;
		padding-right: 0.75rem;
	}
	.finding__detail {
		margin-left: 0;
	}
}
</style>
