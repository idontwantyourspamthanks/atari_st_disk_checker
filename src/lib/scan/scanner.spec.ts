import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { scanImage, synthesise, type ScanFinding } from './scanner'
import { buildExecutableBootSector, fixBootSectorChecksum } from './bootSector.spec'
import { BOOT_SECTOR_SIZE, ST_BOOT_SECTOR_EXE_SUM } from './bootSector'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'disk', '__fixtures__')

function loadStBytes(): Uint8Array {
	const buf = readFileSync(join(fixturesDir, 'sample.st'))
	return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

describe('scanImage — clean fixture', () => {
	it('returns "clean" status for the mtools-generated data disk', () => {
		const report = scanImage(loadStBytes(), 'sample.st')

		// mtools produces a non-executable boot sector on a freshly formatted
		// data disk, so no high/medium heuristics should fire.
		expect(report.status).toBe('clean')
		expect(report.format).toBe('st')
		expect(report.findings.filter(f => f.severity === 'high')).toEqual([])
		expect(report.bootSectorExecutable).toBe(false)
		expect(report.imageBytes).toBe(720 * 1024)
		expect(report.error).toBeUndefined()
	})

	it('records the boot sector checksum for diagnostic display', () => {
		const report = scanImage(loadStBytes(), 'sample.st')
		expect(report.bootSectorChecksum).toBeGreaterThanOrEqual(0)
		expect(report.bootSectorChecksum).toBeLessThanOrEqual(0xFFFF)
	})
})

describe('scanImage — virus detection', () => {
	it('identifies a real Ghost-infected cover disk without Lazy Lion / Gotcha false positives', () => {
		const ghostPath = '/home/ryan/Videos/AtariST/CoverDisks/Ghost_0706_Copia_MONKEY1.st'
		let buf: Buffer
		try {
			buf = readFileSync(ghostPath)
		} catch {
			// Optional fixture — skip when the user's cover-disk archive is absent.
			return
		}

		const report = scanImage(new Uint8Array(buf), 'Ghost_0706_Copia_MONKEY1.st')
		const names = report.findings.filter(f => f.kind === 'signature').map(f => f.name)

		expect(names).toContain('Ghost A')
		expect(names).not.toContain('Puke A')
		expect(names).not.toContain('Upside Down')
		expect(names).not.toContain('Anti-ACA')
		expect(names).not.toContain('Gotcha Xeno')
		expect(report.status).toBe('infected')
	})

	it('flags a "suspicious" boot sector with executable code but no known signature', () => {
		// Build a bootable image whose sector 0 has 68000 code and the right
		// checksum, but no virus signature string. Heuristics should fire.
		const boot = buildExecutableBootSector('NO-SIGNATURE-PAYLOAD-HERE')
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'suspicious.img')

		expect(report.status).toBe('suspicious')
		expect(report.bootSectorExecutable).toBe(true)
		expect(report.bootSectorChecksum).toBe(ST_BOOT_SECTOR_EXE_SUM)

		const heuristicFindings = report.findings.filter(f => f.kind === 'heuristic')
		expect(heuristicFindings.length).toBeGreaterThan(0)
		expect(heuristicFindings.some(f => f.severity === 'high')).toBe(true)
	})

	it('returns "infected" when a known signature is present', () => {
		// Goblin carries an ASCII pattern for "Green Goblins".
		const boot = buildExecutableBootSector('Green Goblins Strike Again')
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'goblin.st')

		expect(report.status).toBe('infected')
		const sig = report.findings.find(f => f.kind === 'signature')
		expect(sig).toBeDefined()
		expect(sig!.name).toBe('Goblin')
		expect(sig!.detail).toContain('Goblin')
	})

	it('reports both signature and heuristic findings for an infected image', () => {
		const boot = buildExecutableBootSector('X')
		boot.set([0x20, 0x3C, 0x31, 0x41, 0x59, 0x26], 0x80)
		fixBootSectorChecksum(boot)
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'ghost.st')

		expect(report.status).toBe('infected')
		expect(report.findings.some(f => f.kind === 'signature' && f.name === 'Ghost A')).toBe(true)
		expect(report.findings.some(f => f.kind === 'heuristic')).toBe(true)
	})

	it('emits sandbox findings for the real Ghost A corpus image', () => {
		const ghostPath = '/home/ryan/Code/diskcheck/diskimages/virus ghost a 0706 Copia MONKEY1.st'
		let buf: Buffer
		try {
			buf = readFileSync(ghostPath)
		} catch {
			return
		}

		const report = scanImage(new Uint8Array(buf), 'ghost.st')
		const sandbox = report.findings.filter(f => f.kind === 'sandbox')
		expect(sandbox.some(f => f.name.includes('reset-proof'))).toBe(true)
		expect(sandbox.some(f => f.name.includes('vector hook'))).toBe(true)
		expect(report.status).toBe('infected')
	})
})

describe('scanImage — error handling', () => {
	it('returns "error" status when the image is too short to contain a boot sector', () => {
		const report = scanImage(new Uint8Array(64), 'tiny.dat')
		expect(report.status).toBe('error')
		expect(report.error).toMatch(/too short/i)
		expect(report.findings).toEqual([])
	})

	it('decodes MSA images transparently before scanning', () => {
		const buf = readFileSync(join(fixturesDir, 'sample.msa'))
		const msa = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)

		const report = scanImage(msa, 'sample.msa')

		expect(report.format).toBe('msa')
		expect(report.status).toBe('clean')
		// imageBytes should reflect the DECODED size, not the compressed size.
		expect(report.imageBytes).toBe(720 * 1024)
	})

	it('decodes STX images transparently before scanning', () => {
		const buf = readFileSync(join(fixturesDir, 'sample.stx'))
		const stx = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)

		const report = scanImage(stx, 'sample.stx')

		expect(report.format).toBe('stx')
		expect(report.status).toBe('clean')
		expect(report.imageBytes).toBe(720 * 1024)
	})
})

describe('scanImage — immunized vs infected disambiguation', () => {
	/**
	 * Build a non-executable boot sector (so TOS won't boot from it) that
	 * carries a virus-signature byte pattern at a known offset. This is
	 * the classic "vaccinated clean disk" shape.
	 *
	 * `executable=false` is forced because the buildExecutableBootSector
	 * helper tunes the checksum up to 0x1234. We instead start from
	 * all zeros (checksum 0) and stamp only the signature bytes.
	 */
	function buildImmunizedBootSector(atOffset: number, bytes: number[]): Uint8Array {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		// Plausible (but non-executable) BPB so geometry heuristics don't trip.
		const buf = Buffer.from(boot.buffer, boot.byteOffset, boot.byteLength)
		buf.writeUInt16LE(512, 0x0B)
		boot[0x0D] = 2
		buf.writeUInt16LE(1, 0x0E)
		boot[0x10] = 2
		buf.writeUInt16LE(112, 0x11)
		buf.writeUInt16LE(1440, 0x13)
		boot[0x15] = 0xFD
		buf.writeUInt16LE(5, 0x16)
		// Now stamp the immunization signature.
		for (let i = 0; i < bytes.length; i++) boot[atOffset + i] = bytes[i]
		// Boot sector starts with the signature, so it's clearly non-executable.
		return boot
	}

	it('flags a non-executable boot sector with a Goblin payload string as "immunized"', () => {
		const boot = buildImmunizedBootSector(0x40, [...Buffer.from('Green Goblins', 'latin1')])
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'immunized.st')

		expect(report.status).not.toBe('infected')

		const sig = report.findings.find(f => f.kind === 'signature' && f.name === 'Goblin')
		expect(sig).toBeDefined()
		expect(sig!.infectionStatus).toBe('immunized')
		expect(sig!.detail).toContain('immunized')
		expect(sig!.severity).toBe('low')
	})

	it('classifies an executable boot sector with 68000 entry code and a signature as "infected"', () => {
		// buildExecutableBootSector gives us an executable sector with the
		// checksum tuned to 0x1234. Putting "Green Goblins" inside means
		// the Goblin signature matches AND the boot code is genuinely viral.
		const boot = buildExecutableBootSector('Green Goblins Strike Again')
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'goblin.st')

		expect(report.status).toBe('infected')
		const goblin = report.findings.find(f => f.kind === 'signature' && f.name === 'Goblin')
		expect(goblin).toBeDefined()
		expect(goblin!.infectionStatus).toBe('infected')
		expect(goblin!.severity).toBe('high')
	})

	it('does not let an immunized disk inflate the overall scan status to infected', () => {
		const boot = buildImmunizedBootSector(0x40, [...Buffer.from('Green Goblins', 'latin1')])
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'immunized.st')

		expect(report.status).toBe('clean')
	})
})

describe('scanImage — heuristic ↔ signature synthesis', () => {
	it('annotates an infected signature finding as confirmed by the boot-code heuristic', () => {
		// An executable boot sector with the Goblin ASCII string: both the
		// signature matcher AND the boot-code heuristic should fire.
		const boot = buildExecutableBootSector('Green Goblins Strike Again')
		const image = new Uint8Array(BOOT_SECTOR_SIZE)
		image.set(boot, 0)

		const report = scanImage(image, 'goblin.st')

		const goblin = report.findings.find(f =>
			f.kind === 'signature' && f.name === 'Goblin',
		)
		expect(goblin).toBeDefined()
		expect(goblin!.detail).toContain('Confirmed by the executable-boot-sector heuristic.')
	})

	it('does NOT add confirmation text to immunized matches (no boot code to corroborate)', () => {
		// Non-executable disk with a Goblin payload string (immunization-shaped).
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		const buf = Buffer.from(boot.buffer, boot.byteOffset, boot.byteLength)
		buf.writeUInt16LE(512, 0x0B)
		boot[0x0D] = 2
		buf.writeUInt16LE(1, 0x0E)
		boot[0x10] = 2
		buf.writeUInt16LE(112, 0x11)
		buf.writeUInt16LE(1440, 0x13)
		boot[0x15] = 0xFD
		buf.writeUInt16LE(5, 0x16)
		boot.set(Buffer.from('Green Goblins', 'latin1'), 0x40)

		const report = scanImage(boot, 'immunized.st')

		const sig = report.findings.find(f => f.kind === 'signature' && f.name === 'Goblin')
		expect(sig).toBeDefined()
		expect(sig!.detail).not.toContain('Confirmed by')
	})

	it('no longer attributes BRA.B $38 boots to Signum (shared with protectors)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x38

		const bootCodeFinding: ScanFinding = {
			kind: 'heuristic',
			name: 'Executable boot sector',
			detail: 'Original detail.',
			severity: 'high',
		}
		synthesise([bootCodeFinding], [], [{ id: 'boot-code-present', headline: '', detail: '', severity: 'high' }], boot)

		expect(bootCodeFinding.detail).toBe('Original detail.')
	})

	it('does not attribute BRA.B $1C boots to Lazy Lion (shared with Ghost)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1C

		const bootCodeFinding: ScanFinding = {
			kind: 'heuristic',
			name: 'Executable boot sector',
			detail: 'Original detail.',
			severity: 'high',
		}
		synthesise([bootCodeFinding], [], [{ id: 'boot-code-present', headline: '', detail: '', severity: 'high' }], boot)

		expect(bootCodeFinding.detail).toBe('Original detail.')
	})

	it('does not annotate when neither signatures nor boot-code heuristic are present', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		const finding: ScanFinding = {
			kind: 'heuristic',
			name: 'Some other heuristic',
			detail: 'Original.',
			severity: 'low',
		}
		synthesise([finding], [], [{ id: 'odd-geometry', headline: '', detail: '', severity: 'low' }], boot)
		expect(finding.detail).toBe('Original.')
	})

	it('names a Sagrotan-style protector bootblock as protected, not infected', () => {
		const boot = buildExecutableBootSector('SAGROTAN 4.12 Bootprogramm')
		const report = scanImage(boot, 'sagrotan.st')
		expect(report.status).toBe('protected')
		expect(report.findings.some(f => f.kind === 'protector' && f.name === 'Sagrotan')).toBe(true)
		expect(report.findings.filter(f => f.kind === 'signature')).toEqual([])
	})

	it('does not let a protector string outrank high sandbox residency', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1c
		boot[0x0b] = 0x00
		boot[0x0c] = 0x02
		boot[0x0d] = 2
		boot[0x15] = 0xfd
		boot[0x16] = 5
		// Reset-proof install + hdv_bpb hook
		const code = [
			0x23, 0xfc, 0x31, 0x41, 0x59, 0x26, 0x00, 0x00, 0x04, 0x26, // MOVE.L #π,$426
			0x23, 0xfc, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x04, 0x72, // MOVE.L #$5000,$472
			0x4e, 0x75,
		]
		boot.set(code, 0x1e)
		// Protector needle in unused tail — must not force status=protected
		const needle = 'SAGROTAN'
		for (let i = 0; i < needle.length; i++) boot[0x100 + i] = needle.charCodeAt(i)
		fixBootSectorChecksum(boot)

		const report = scanImage(boot, 'hostile-with-sagrotan-string.st')
		expect(report.findings.some(f => f.kind === 'protector')).toBe(true)
		const sandbox = report.findings.filter(f => f.kind === 'sandbox')
		expect(sandbox.some(f => f.severity === 'high')).toBe(true)
		expect(report.status).toBe('suspicious')
	})
})
