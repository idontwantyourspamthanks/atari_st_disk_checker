import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { runHeuristics } from './heuristics'
import { buildExecutableBootSector, fixBootSectorChecksum } from './bootSector.spec'
import { BOOT_SECTOR_SIZE } from './bootSector'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'disk', '__fixtures__')

function loadStBoot(): Uint8Array {
	const buf = readFileSync(join(fixturesDir, 'sample.st'))
	const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
	return bytes.subarray(0, BOOT_SECTOR_SIZE)
}

describe('runHeuristics', () => {
	it('returns no high/medium findings for the mtools-generated clean data disk', () => {
		// The mtools fixture is a freshly-formatted FAT12 data disk: its
		// boot sector is non-executable (so no boot-code findings), and it
		// has a valid BPB. This is the realistic "clean" baseline.
		const findings = runHeuristics(loadStBoot())
		const concerning = findings.filter(f => f.severity === 'high' || f.severity === 'medium')
		expect(concerning).toEqual([])
	})

	it('flags a high-severity finding for an executable boot sector with 68000 code', () => {
		const boot = buildExecutableBootSector('PAYLOAD')
		const findings = runHeuristics(boot)

		const high = findings.find(f => f.id === 'boot-code-present')
		expect(high).toBeDefined()
		expect(high!.severity).toBe('high')
		expect(high!.headline).toMatch(/executable boot sector/i)
		expect(high!.detail).toContain('68000')
	})

	it('treats Ghost H-style BLS entry (0x6F) as recognised 68000 entry code', () => {
		const boot = buildExecutableBootSector('GHOSTH')
		boot[0] = 0x6F // BLS.S — same displacement as BRA for Ghost H
		// Re-fix checksum after mutating the entry byte.
		fixBootSectorChecksum(boot)

		const findings = runHeuristics(boot)
		const high = findings.find(f => f.id === 'boot-code-present')
		expect(high).toBeDefined()
		expect(high!.severity).toBe('high')
		expect(high!.headline).toContain('68000 entry code')
	})

	it('flags high severity for executable + dense code even with a disguise entry byte', () => {
		// Wolf-style: UVK immunization/start word $EB34 — not in our opcode list,
		// but a full viral body must still trip the high heuristic.
		const boot = buildExecutableBootSector('WOLFDISGUISE_PAYLOAD_BYTES')
		boot[0] = 0xEB
		boot[1] = 0x34
		fixBootSectorChecksum(boot)

		const findings = runHeuristics(boot)
		const high = findings.find(f => f.id === 'boot-code-present')
		expect(high).toBeDefined()
		expect(high!.severity).toBe('high')
		expect(high!.headline).toContain('substantial code')
		expect(high!.detail).toMatch(/unrecognised entry byte \(0xeb\)/i)
	})

	it('flags bare resvalid π as medium (Anti-Ghost detectors embed it too)', () => {
		const boot = buildExecutableBootSector('X')
		boot[0x40] = 0x31
		boot[0x41] = 0x41
		boot[0x42] = 0x59
		boot[0x43] = 0x26
		fixBootSectorChecksum(boot)

		const findings = runHeuristics(boot)
		const magic = findings.find(f => f.id === 'resvalid-magic')
		expect(magic).toBeDefined()
		expect(magic!.severity).toBe('medium')
		expect(magic!.detail).toContain('0x40')
	})

	it('escalates resvalid π to high when Ghost MOVE.L #π,D0 is also present', () => {
		const boot = buildExecutableBootSector('X')
		boot.set([0x20, 0x3C, 0x31, 0x41, 0x59, 0x26], 0x40)
		fixBootSectorChecksum(boot)

		const findings = runHeuristics(boot)
		const magic = findings.find(f => f.id === 'resvalid-magic')
		expect(magic).toBeDefined()
		expect(magic!.severity).toBe('high')
		expect(magic!.detail).toMatch(/MOVE\.L/i)
	})

	it('flags geometry when bytes-per-sector is not 512', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		// Buffer is a Node global; safe to use in vitest.
		Buffer.from(boot.buffer, boot.byteOffset, boot.byteLength).writeUInt16LE(1024, 0x0B)
		boot[0x15] = 0xFD

		const findings = runHeuristics(boot)
		const geo = findings.find(f => f.id === 'odd-geometry')
		expect(geo).toBeDefined()
		expect(geo!.severity).toBe('low')
	})

	it('flags an unusual media descriptor', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		const buf = Buffer.from(boot.buffer, boot.byteOffset, boot.byteLength)
		buf.writeUInt16LE(512, 0x0B)
		boot[0x0D] = 2
		buf.writeUInt16LE(5, 0x16)
		boot[0x15] = 0x42 // not a standard FAT12 media descriptor

		const findings = runHeuristics(boot)
		const md = findings.find(f => f.id === 'odd-media-descriptor')
		expect(md).toBeDefined()
		expect(md!.headline).toContain('0x42')
	})

	it('returns findings sorted by severity (high → low)', () => {
		// Construct a boot sector that triggers both a high and a low finding.
		const boot = buildExecutableBootSector('X')
		boot[0x15] = 0x42 // also trip the media-descriptor check

		const findings = runHeuristics(boot)
		const severities = findings.map(f => f.severity)
		expect(severities).toEqual([...severities].sort(bySeverityOrder))
	})
})

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 } as const
function bySeverityOrder(a: keyof typeof SEVERITY_ORDER, b: keyof typeof SEVERITY_ORDER): number {
	return SEVERITY_ORDER[a] - SEVERITY_ORDER[b]
}
