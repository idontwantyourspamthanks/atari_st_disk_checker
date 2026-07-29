/**
 * Corpus harvester, stage 2: classify stage-1 candidates with the real
 * scanner, dedupe by boot-sector SHA-1 (against the existing corpus too),
 * and copy survivors into diskimages/ using the corpus naming convention.
 *
 * Gated: only runs when DISKCHECK_HARVEST=1 — plain `npm test` skips.
 *
 *   DISKCHECK_HARVEST=1 npx vitest run src/lib/scan/harvest.probe.spec.ts
 */
import { describe, it, expect } from 'vitest'
import {
	existsSync, readFileSync, readdirSync, writeFileSync, copyFileSync,
} from 'node:fs'
import { join, extname, basename } from 'node:path'
import { createHash } from 'node:crypto'
import { scanImage } from './scanner'

const RUN = process.env.DISKCHECK_HARVEST === '1'
const corpusDir = join(import.meta.dirname, '..', '..', '..', '..', 'diskimages')
const staging = join(corpusDir, '_staging')
const LABEL = 'axf1' // AxelF CD1; bump per CD
const OTHER_SAMPLE_EVERY = 50
const OTHER_CAP = 20

function slug(s: string): string {
	return s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().replace(/\s+/g, ' ')
}

function bootSha(bytes: Uint8Array): string | null {
	try {
		const report = scanImage(bytes, 'probe')
		if (!report.bootSector) return null
		return createHash('sha1').update(report.bootSector).digest('hex')
	} catch {
		return null
	}
}

describe('corpus harvest stage 2', () => {
	it('classifies candidates into diskimages/', () => {
		if (!RUN) return
		const candPath = join(staging, 'candidates.json')
		if (!existsSync(candPath)) return
		const candidates = JSON.parse(readFileSync(candPath, 'utf8')) as
			{ path: string; source: string }[]

		// Boot-sector hashes already in the corpus — don't duplicate.
		const known = new Set<string>()
		for (const f of readdirSync(corpusDir).filter(f => /\.(st|msa|stx)$/i.test(f))) {
			const sha = bootSha(new Uint8Array(readFileSync(join(corpusDir, f))))
			if (sha) known.add(sha)
		}

		const manifest: string[] = ['file,class,status,findings,sha1,source']
		let kept = 0, cleanSeen = 0, otherKept = 0
		const counts = { infected: 0, protected: 0, suspicious: 0, clean: 0, error: 0, dupe: 0 }

		for (const c of candidates) {
			let bytes: Uint8Array
			try {
				bytes = new Uint8Array(readFileSync(c.path))
			} catch { counts.error++; continue }
			const report = scanImage(bytes, basename(c.path))
			const sha = report.bootSector
				? createHash('sha1').update(report.bootSector).digest('hex')
				: null
			if (!sha || known.has(sha)) { counts.dupe++; continue }

			const liveSigs = report.findings
				.filter(f => f.kind === 'signature' && f.infectionStatus !== 'immunized')
				.map(f => f.name)
			const prots = report.findings.filter(f => f.kind === 'protector').map(f => f.name)

			let cls: string | null = null
			let name = ''
			if (report.status === 'infected') {
				cls = 'virus'
				name = liveSigs.length > 0 ? slug(liveSigs.join(' ')) : 'unknown'
			} else if (report.status === 'protected') {
				cls = 'prot'
				name = prots.length > 0 ? slug(prots[0]!) : 'unknown'
			} else if (report.status === 'suspicious') {
				// Safe side: never let an ambiguous disk become an "other" control.
				cls = 'virus'
				name = liveSigs.length > 0 ? slug(liveSigs.join(' ')) : 'unknown'
			} else if (report.status === 'clean') {
				cleanSeen++
				if (cleanSeen % OTHER_SAMPLE_EVERY === 0 && otherKept < OTHER_CAP) {
					cls = 'other'
					name = 'clean'
					otherKept++
				}
			}
			counts[report.status === 'error' ? 'error' : report.status]++
			if (!cls) continue

			known.add(sha)
			kept++
			const ext = extname(c.path).toLowerCase() || '.st'
			const file = `${cls} ${name} ${LABEL}-${String(kept).padStart(4, '0')}${ext}`
			copyFileSync(c.path, join(corpusDir, file))
			const findings = report.findings.map(f => f.name).join('|').replace(/,/g, ';')
			manifest.push(`"${file}",${cls},${report.status},"${findings}",${sha},"${c.source.replace(/"/g, "'")}"`)
		}

		writeFileSync(join(staging, 'manifest.csv'), manifest.join('\n') + '\n')
		console.log('harvest:', JSON.stringify(counts), `kept=${kept}`)
		// Sanity: whatever we kept must not break the corpus contract.
		expect(kept).toBeGreaterThan(0)
	})
})
