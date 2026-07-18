/**
 * Corpus check against diskimages/ — named by content class:
 *   virus*  → expect infected + a plausible signature (when we have one)
 *   prot*   → expect protected (named protector), not a false virus infection
 *   other*  → must NOT be infected
 *
 * Skips cleanly when the folder is absent (CI without the corpus).
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { scanImage } from './scanner'

const dir = join(import.meta.dirname, '..', '..', '..', 'diskimages')

describe('diskimages corpus', () => {
	it('classifies virus / protector / other images without silly false infections', () => {
		if (!existsSync(dir)) return

		const files = readdirSync(dir).filter(f => /\.(st|msa|stx)$/i.test(f)).sort()
		expect(files.length).toBeGreaterThan(10)

		const falseInfections: string[] = []
		const virusMisses: string[] = []
		const protectorMisses: string[] = []
		const summary: string[] = []

		// Archive labels say protector but boot is live Ghost.
		const knownInfectedLabels = new Set([
			'prot medway boys virus free (not ste compatible) H196.MSA',
			'prot smiley virus free H166.MSA',
		])

		for (const file of files) {
			const report = scanImage(new Uint8Array(readFileSync(join(dir, file))), file)
			const liveSigs = report.findings
				.filter(f => f.kind === 'signature' && f.infectionStatus !== 'immunized')
				.map(f => f.name)
			const prots = report.findings.filter(f => f.kind === 'protector').map(f => f.name)

			const kind = file.startsWith('virus') ? 'VIRUS'
				: file.startsWith('prot') ? 'PROT'
				: file.startsWith('other') ? 'OTHER'
				: 'UNK'

			summary.push(
				`${kind} ${report.status.padEnd(11)} ${file.slice(0, 48).padEnd(48)} ` +
				`v=[${liveSigs.join('|') || '-'}] p=[${prots.join('|') || '-'}]`,
			)

			if (kind === 'OTHER') {
				if (report.status === 'infected' || liveSigs.length > 0) {
					falseInfections.push(`${file} → ${report.status} [${liveSigs.join(', ')}]`)
				}
			}

			if (kind === 'PROT') {
				if (knownInfectedLabels.has(file)) {
					if (!liveSigs.includes('Ghost A')) {
						virusMisses.push(`${file} labelled protector but should detect Ghost A`)
					}
					continue
				}
				if (report.status === 'infected' || liveSigs.length > 0) {
					falseInfections.push(`${file} → ${report.status} [${liveSigs.join(', ')}]`)
				}
				// Prefer named protected over blank suspicious when branding exists.
				if (report.status === 'suspicious' && prots.length === 0) {
					// Silent / demo bootblocks with no antivirus branding are fine.
					// MPH has no readable branding; skip it.
					if (/mph virus free/i.test(file)) continue
					if (/virus free|antivirus|anti.?ghost|sagrotan|uvk|protector/i.test(file)) {
						protectorMisses.push(`${file} → ${report.status} (no protector match)`)
					}
				}
			}

			if (kind === 'VIRUS') {
				const expectNamed =
					/ghost a/i.test(file) || /ghost g/i.test(file) || /signum/i.test(file) ||
					/goblin/i.test(file) || /finland/i.test(file)
				if (expectNamed && report.status !== 'infected') {
					virusMisses.push(`${file} → ${report.status} [${liveSigs.join(', ')}]`)
				}
				if (/ghost a/i.test(file) && !liveSigs.includes('Ghost A')) {
					virusMisses.push(`${file} missing Ghost A (${liveSigs.join(', ')})`)
				}
				if (/signum/i.test(file) && !liveSigs.includes('Signum A')) {
					virusMisses.push(`${file} missing Signum A (${liveSigs.join(', ')})`)
				}
				if (/goblin/i.test(file) && !liveSigs.includes('Goblin')) {
					virusMisses.push(`${file} missing Goblin (${liveSigs.join(', ')})`)
				}
				if (/finland/i.test(file) && !liveSigs.includes('Finland')) {
					virusMisses.push(`${file} missing Finland (${liveSigs.join(', ')})`)
				}
			}
		}

		console.log(summary.join('\n'))

		expect(falseInfections, `false infections:\n${falseInfections.join('\n')}`).toEqual([])
		expect(virusMisses, `virus misses:\n${virusMisses.join('\n')}`).toEqual([])
		expect(protectorMisses, `protector misses:\n${protectorMisses.join('\n')}`).toEqual([])
	})
})
