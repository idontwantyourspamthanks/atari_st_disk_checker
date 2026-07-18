import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { runBootSandbox, scanDirtyMemory, markDirtyRange, shouldScanHighRam, BOOT_LOAD_ADDR } from './bootSandbox'
import {
	getBootSector,
	BOOT_SECTOR_SIZE,
	ST_BOOT_SECTOR_EXE_SUM,
} from '../bootSector'

const DISKIMAGES = '/home/ryan/Code/diskcheck/diskimages'

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

function loadVirus(name: string): Uint8Array | null {
	const path = `${DISKIMAGES}/${name}`
	if (!existsSync(path)) return null
	return getBootSector(new Uint8Array(readFileSync(path)))
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
		const boot = loadVirus('virus ghost a 0706 Copia MONKEY1.st')
		if (!boot) {
			this.skip()
			return
		}

		const result = runBootSandbox(boot)
		expect(result.haltReason).toBe('return')
		expect(result.resetProofMagic).toBe(true)
		expect(result.resetProofVector).toBe(true)
		expect(result.hooks).toContain('hdv_bpb')
		expect(result.writes.some(w => w.addr === 0x0426 && w.value === 0x31415926)).toBe(true)
	})

	it('observes Finland (zero-disguise entry) installing reset-proof + hdv_bpb', function () {
		const boot = loadVirus('virus finland virus H013.MSA')
		if (!boot) {
			this.skip()
			return
		}

		const result = runBootSandbox(boot)
		expect(result.haltReason).toBe('return')
		expect(result.resetProofMagic).toBe(true)
		expect(result.resetProofVector).toBe(true)
		expect(result.hooks).toContain('hdv_bpb')
	})

	it('observes Goblin installing reset-proof residency + hdv_bpb', function () {
		const boot = loadVirus('virus goblin a H456.MSA')
		if (!boot) {
			this.skip()
			return
		}

		const result = runBootSandbox(boot)
		expect(result.haltReason).toBe('return')
		expect(result.resetProofMagic).toBe(true)
		expect(result.resetProofVector).toBe(true)
		expect(result.hooks).toContain('hdv_bpb')
	})

	it('observes Signum hooking hdv_bpb', function () {
		const boot = loadVirus('virus signum pbl a H087.MSA')
		if (!boot) {
			this.skip()
			return
		}

		const result = runBootSandbox(boot)
		expect(result.haltReason).toBe('return')
		expect(result.hooks).toContain('hdv_bpb')
	})

	it('finds Goblin signature in relocated RAM after sandbox run', function () {
		const boot = loadVirus('virus goblin a H456.MSA')
		if (!boot) {
			this.skip()
			return
		}
		const result = runBootSandbox(boot)
		expect(result.memorySignatures.some(h => h.name === 'Goblin')).toBe(true)
		expect(result.memorySignatures.some(h => h.windowBase !== 0x4000)).toBe(true)
	})

	it('runs the Demoniak Trace-bit bootblock without unsupported opcodes', function () {
		const boot = loadVirus('prot fuck to regis demoniak H327.MSA')
		if (!boot) {
			this.skip()
			return
		}
		const result = runBootSandbox(boot)
		expect(result.haltReason).not.toBe('unsupported')
		expect(result.haltReason).not.toBe('error')
		expect(result.ran).toBe(true)
	})

	it('records resvalid when a MOVE.L overlaps from $424', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1c
		boot[0x0b] = 0x00
		boot[0x0c] = 0x02
		boot[0x0d] = 2
		boot[0x15] = 0xfd
		boot[0x16] = 5
		// At $1E: MOVE.L #$31415926, $424 — overlaps resvalid at $426
		const code = [
			0x23, 0xfc, 0x31, 0x41, 0x59, 0x26, 0x00, 0x00, 0x04, 0x24,
			0x4e, 0x75,
		]
		boot.set(code, 0x1e)
		fixChecksum(boot)

		const result = runBootSandbox(boot)
		expect(result.ran).toBe(true)
		expect(result.writes.some(w => w.addr === 0x0426)).toBe(true)
	})

	it('finds signatures at mid-RAM when trap-copy pages are marked dirty', () => {
		const mem = new Uint8Array(0x10_0000)
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		// Ghost bytes-scan needle
		boot[0x80] = 0x20
		boot[0x81] = 0x3c
		boot[0x82] = 0x31
		boot[0x83] = 0x41
		boot[0x84] = 0x59
		boot[0x85] = 0x26
		mem.set(boot, BOOT_LOAD_ADDR)
		const dest = 0x6000
		mem.set(boot, dest)

		const dirtyPages = new Set<number>()
		// Without dirty marks, mid-RAM is outside the high-RAM scan band.
		expect(scanDirtyMemory(mem, dirtyPages, boot).some(h => h.windowBase === dest)).toBe(false)

		markDirtyRange(dirtyPages, dest, BOOT_SECTOR_SIZE)
		const hits = scanDirtyMemory(mem, dirtyPages, boot)
		expect(hits.some(h => h.windowBase === dest && h.name === 'Ghost A')).toBe(true)
	})

	it('skips the high-RAM band unless residency is hinted', () => {
		const mem = new Uint8Array(0x10_0000)
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0x80] = 0x20
		boot[0x81] = 0x3c
		boot[0x82] = 0x31
		boot[0x83] = 0x41
		boot[0x84] = 0x59
		boot[0x85] = 0x26
		const high = 0x10_0000 - 0x1000
		mem.set(boot, high)

		const dirtyPages = new Set<number>()
		expect(shouldScanHighRam(dirtyPages, [])).toBe(false)
		expect(
			scanDirtyMemory(mem, dirtyPages, boot, { scanHighRam: false }).some(
				h => h.windowBase === high,
			),
		).toBe(false)
		expect(
			scanDirtyMemory(mem, dirtyPages, boot, { scanHighRam: true }).some(
				h => h.windowBase === high && h.name === 'Ghost A',
			),
		).toBe(true)

		expect(
			shouldScanHighRam(dirtyPages, [
				{ addr: 0x0426, name: 'resvalid', value: 0x31415926, atInstruction: 1 },
			]),
		).toBe(true)
	})
})
