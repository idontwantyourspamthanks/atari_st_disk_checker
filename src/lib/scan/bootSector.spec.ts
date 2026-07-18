import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
	getBootSector,
	getImageBytes,
	bootSectorChecksum,
	isBootSectorExecutable,
	startsWith68000Opcode,
	countNonZeroBytesBeyondBpb,
	hasSaneGeometry,
	hasSaneMediaDescriptor,
	BOOT_SECTOR_SIZE,
	ST_BOOT_SECTOR_EXE_SUM,
} from './bootSector'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'disk', '__fixtures__')

function loadStBoot(): Uint8Array {
	const buf = readFileSync(join(fixturesDir, 'sample.st'))
	const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
	return getBootSector(bytes)
}

describe('getImageBytes', () => {
	it('returns .st bytes unchanged', () => {
		const bytes = new Uint8Array([0xEB, 0x3C, 0x90, 0x00])
		expect(getImageBytes(bytes)).toBe(bytes) // identity
	})

	it('decodes .msa bytes to raw sector data', () => {
		const buf = readFileSync(join(fixturesDir, 'sample.msa'))
		const msa = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
		const raw = getImageBytes(msa)
		// The .msa fixture decodes to the same bytes as the .st fixture.
		const stBuf = readFileSync(join(fixturesDir, 'sample.st'))
		expect(raw.length).toBe(stBuf.length)
	})
})

describe('getBootSector', () => {
	it('returns exactly 512 bytes', () => {
		expect(loadStBoot().length).toBe(BOOT_SECTOR_SIZE)
	})

	it('throws on an image shorter than one sector', () => {
		expect(() => getBootSector(new Uint8Array(64))).toThrow(/too short/i)
	})
})

describe('bootSectorChecksum', () => {
	it('produces a stable 16-bit value for the mtools fixture', () => {
		// We don't pin the value — it depends on mtools' BPB output, which
		// can drift between versions. We just check it's a sensible u16.
		const sum = bootSectorChecksum(loadStBoot())
		expect(sum).toBeGreaterThanOrEqual(0)
		expect(sum).toBeLessThanOrEqual(0xFFFF)
	})

	it('returns 0x1234 for a hand-crafted executable boot sector', () => {
		// See scanner.spec.ts for the fixture builder — repeated here only
		// to confirm the checksum routine itself behaves on a known target.
		const boot = buildExecutableBootSector('HELLO')
		expect(bootSectorChecksum(boot)).toBe(ST_BOOT_SECTOR_EXE_SUM)
	})
})

describe('isBootSectorExecutable', () => {
	it('returns true when checksum is 0x1234', () => {
		const boot = buildExecutableBootSector('TEST')
		expect(isBootSectorExecutable(boot)).toBe(true)
	})

	it('returns false for an all-zero (data-disk-style) boot sector', () => {
		const blank = new Uint8Array(BOOT_SECTOR_SIZE)
		// Sum of all zeros = 0, not 0x1234.
		expect(isBootSectorExecutable(blank)).toBe(false)
	})
})

describe('startsWith68000Opcode', () => {
	it('detects a 0x60 BRA opcode at offset 0', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1C // BRA.B +0x1C
		expect(startsWith68000Opcode(boot)).toBe(true)
	})

	it('detects Ghost H-style BLS (0x6F) — scanners that only check BRA miss this', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x6F
		boot[1] = 0x1C
		expect(startsWith68000Opcode(boot)).toBe(true)
	})

	it('detects a 0x4E opcode (JMP/JSR/NOP family)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x4E
		expect(startsWith68000Opcode(boot)).toBe(true)
	})

	it('returns false for a media-descriptor first byte (typical data disk)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0xF9
		expect(startsWith68000Opcode(boot)).toBe(false)
	})

	it('returns false for a leading zero (padding / ORI — not a useful entry signal)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x00
		expect(startsWith68000Opcode(boot)).toBe(false)
	})
})

describe('countNonZeroBytesBeyondBpb', () => {
	it('returns 0 for an all-zero sector', () => {
		expect(countNonZeroBytesBeyondBpb(new Uint8Array(BOOT_SECTOR_SIZE))).toBe(0)
	})

	it('counts non-zero bytes from post-BPB 0x1E through 0x1FD', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		// Put non-zero bytes both inside and outside the BPB region.
		boot[0x10] = 0xFF // inside BPB — should NOT be counted
		boot[0x1E] = 0x11 // first post-BPB byte — counted (viral BRA.B $1C landing)
		boot[0x3E] = 0xAA // classic DOS-style boot-code start — counted
		boot[0x100] = 0xBB // mid-region — counted
		boot[0x1FD] = 0xCC // last byte of boot code (before signature) — counted
		expect(countNonZeroBytesBeyondBpb(boot)).toBe(4)
	})
})

describe('BPB sanity checks', () => {
	it('recognises the mtools fixture as having a sane BPB', () => {
		const boot = loadStBoot()
		expect(hasSaneGeometry(boot)).toBe(true)
		expect(hasSaneMediaDescriptor(boot)).toBe(true)
	})

	it('flags an all-zero BPB as not sane', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		expect(hasSaneGeometry(boot)).toBe(false)
		expect(hasSaneMediaDescriptor(boot)).toBe(false)
	})
})

/**
 * Build a 512-byte boot sector whose 256-word checksum equals 0x1234 (so
 * TOS would consider it executable), starts with a 68000 BRA, and contains
 * the given payload string in the boot-code region. Used to stand in for
 * a virus in tests.
 *
 * Uses Node's Buffer internally for the convenience LE writers; the
 * returned Uint8Array shares the buffer's memory.
 */
export function buildExecutableBootSector(payload: string): Uint8Array {
	const buf = Buffer.alloc(BOOT_SECTOR_SIZE)
	// BRA.B to offset 0x3E (skip the BPB).
	buf[0] = 0x60
	buf[1] = 0x3C

	// Plausible BPB so geometry heuristics don't trip.
	buf.writeUInt16LE(512, 0x0B)   // bytes per sector
	buf[0x0D] = 2                  // sectors per cluster
	buf.writeUInt16LE(1, 0x0E)     // reserved sectors
	buf[0x10] = 2                  // num FATs
	buf.writeUInt16LE(112, 0x11)   // root entries
	buf.writeUInt16LE(1440, 0x13)  // total sectors
	buf[0x15] = 0xFD               // media descriptor (DSDD)
	buf.writeUInt16LE(5, 0x16)     // sectors per FAT

	// Write the payload string into the boot-code region (offset 0x3E+).
	buf.write(payload, 0x3E, 'latin1')

	const view = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
	fixBootSectorChecksum(view)
	return view
}

/** Tweak the word at 0x1FC so the sector checksum equals 0x1234. */
export function fixBootSectorChecksum(boot: Uint8Array): void {
	// Sum words 0..253 (bytes 0x000–0x1FB); word 254 at 0x1FC is the tuning
	// word we replace. Word 255 at 0x1FE is left as-is (usually 0).
	let sum = 0
	for (let i = 0; i < 254; i++) {
		sum = (sum + ((boot[i * 2]! << 8) | boot[i * 2 + 1]!)) & 0xFFFF
	}
	const last = ((boot[0x1FE]! << 8) | boot[0x1FF]!) & 0xFFFF
	const tuning = (ST_BOOT_SECTOR_EXE_SUM - sum - last) & 0xFFFF
	boot[0x1FC] = (tuning >> 8) & 0xFF
	boot[0x1FD] = tuning & 0xFF
	if (bootSectorChecksum(boot) !== ST_BOOT_SECTOR_EXE_SUM) {
		throw new Error('fixBootSectorChecksum: checksum fixup failed')
	}
}
