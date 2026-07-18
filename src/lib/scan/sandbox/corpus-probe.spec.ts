/**
 * Corpus probe for the boot sandbox. Keep as a diagnostic; assertions for
 * known-good images live in bootSandbox.spec.ts.
 */
import { describe, it } from 'vitest'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { getBootSector } from '../bootSector'
import { runBootSandbox } from './bootSandbox'

const DIR = '/home/ryan/Code/diskcheck/diskimages'

describe('sandbox corpus probe', () => {
	it('reports halt reasons for virus* images', () => {
		if (!existsSync(DIR)) return
		const files = readdirSync(DIR).filter(f => f.startsWith('virus ')).sort()
		const rows: string[] = []
		for (const f of files) {
			const bytes = new Uint8Array(readFileSync(join(DIR, f)))
			let boot: Uint8Array
			try {
				boot = getBootSector(bytes)
			} catch (e) {
				rows.push(`${f}: ERROR ${e}`)
				continue
			}
			const r = runBootSandbox(boot)
			rows.push(
				[
					f.replace(/^virus /, '').slice(0, 36).padEnd(36),
					r.haltReason.padEnd(12),
					String(r.instructions).padStart(6),
					r.resetProofMagic ? 'π' : '-',
					r.resetProofVector ? 'RV' : '--',
					(r.hooks.join(',') || '-').slice(0, 28),
					(r.error ?? '').slice(0, 60),
				].join(' | '),
			)
		}
		// eslint-disable-next-line no-console
		console.log('\n' + rows.join('\n') + '\n')
	})
})
