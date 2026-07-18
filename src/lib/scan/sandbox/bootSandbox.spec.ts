import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { runBootSandbox } from './bootSandbox'
import {
	getBootSector,
	BOOT_SECTOR_SIZE,
	ST_BOOT_SECTOR_EXE_SUM,
} from '../bootSector'

const GHOST_PATH =
	'/home/ryan/Code/diskcheck/diskimages/virus ghost a 0706 Copia MONKEY1.st'

function fixChecksum(boot: Uint8Array): void {
	let sum = 0
	for (let i = 0; i < 254; i++) {
		sum = (sum + ((boot[i * 2]! << 8) | boot[i * 2 + 1]!)) & 0xffff
	}
	const last = ((boot[0x1fe]! << 8) | boot[0x1ff]!) & 0xffff
	const tuning = (ST_BOOT_SECTOR_EXE_SUM - sum - last) & 0xffff
	boot[0x1fc] = tuning >> 8
	boot[0x1fd] = tuning & 0xff
}

function trivialRtsBoot(): Uint8Array {
	const boot = new Uint8Array(BOOT_SECTOR_SIZE)
	boot[0] = 0x60
	boot[1] = 0x1c
	boot[0x0b] = 0x00
	boot[0x0c] = 0x02
	boot[0x0d] = 2
	boot[0x15] = 0xfd
	boot[0x16] = 5
	boot[0x1e] = 0x4e
	boot[0x1f] = 0x75
	fixChecksum(boot)
	return boot
}

describe('runBootSandbox', () => {
	it('does not run a non-executable boot sector', () => {
		const boot = new Uint8Array(512)
		const result = runBootSandbox(boot)
		expect(result.ran).toBe(false)
		expect(result.haltReason).toBe('not-executable')
	})

	it('returns to TOS on a trivial BRA+RTS boot', () => {
		const result = runBootSandbox(trivialRtsBoot())
		expect(result.ran).toBe(true)
		expect(result.haltReason).toBe('return')
		expect(result.writes).toEqual([])
	})

	it('observes Ghost A installing reset-proof residency + hdv_bpb', function () {
		if (!existsSync(GHOST_PATH)) {
			this.skip()
			return
		}

		const image = new Uint8Array(readFileSync(GHOST_PATH))
		const boot = getBootSector(image)
		const result = runBootSandbox(boot)

		expect(result.ran).toBe(true)
		expect(result.haltReason).toBe('return')
		expect(result.instructions).toBeGreaterThan(0)
		expect(result.resetProofMagic).toBe(true)
		expect(result.resetProofVector).toBe(true)
		expect(result.hooks).toContain('hdv_bpb')
		expect(result.writes.some(w => w.addr === 0x0426 && w.value === 0x31415926)).toBe(true)
	})
})
