/**
 * One-shot protector + virus corpus probe for the boot sandbox.
 */
import { describe, it } from 'vitest'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { getBootSector } from '../bootSector'
import { runBootSandbox } from './bootSandbox'

const DIR = '/home/ryan/Code/diskcheck/diskimages'

describe('sandbox full corpus probe', () => {
	it('summarises virus* and prot* sandbox outcomes', () => {
		if (!existsSync(DIR)) return
		const files = readdirSync(DIR)
			.filter(f => f.startsWith('virus ') || f.startsWith('prot '))
			.sort()

		const summary = { return: 0, limit: 0, loop: 0, unsupported: 0, error: 0, notExec: 0 }
		const interesting: string[] = []

		for (const f of files) {
			let boot: Uint8Array
			try {
				boot = getBootSector(new Uint8Array(readFileSync(join(DIR, f))))
			} catch (e) {
				interesting.push(`${f}: decode ${e}`)
				continue
			}
			const r = runBootSandbox(boot)
			const key = r.haltReason === 'not-executable' ? 'notExec' : r.haltReason
			if (key in summary) (summary as Record<string, number>)[key]++

			const tag = f.startsWith('virus') ? 'V' : 'P'
			const line = [
				tag,
				f.replace(/^(virus|prot) /, '').slice(0, 34).padEnd(34),
				r.haltReason.padEnd(12),
				String(r.instructions).padStart(6),
				r.resetProofMagic ? 'π' : '-',
				r.resetProofVector ? 'RV' : '--',
				(r.hooks.join(',') || '-').slice(0, 20),
				(r.memorySignatures?.map(s => s.name).join(',') || '-').slice(0, 24),
				(r.error ?? '').slice(0, 50),
			].join(' | ')

			if (
				tag === 'V' ||
				r.haltReason === 'unsupported' ||
				r.haltReason === 'loop' ||
				r.resetProofMagic ||
				(r.hooks?.length ?? 0) > 0 ||
				(r.memorySignatures?.length ?? 0) > 0
			) {
				interesting.push(line)
			}
		}

		// eslint-disable-next-line no-console
		console.log('\nSUMMARY', summary)
		// eslint-disable-next-line no-console
		console.log(interesting.join('\n') + '\n')
	})
})
