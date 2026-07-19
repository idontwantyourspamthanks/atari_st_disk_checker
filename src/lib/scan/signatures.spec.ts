import { describe, it, expect } from 'vitest'
import { matchSignatures, matchPattern, parseMaskedHex, SIGNATURES } from './signatures'
import { BOOT_SECTOR_SIZE } from './bootSector'

describe('matchSignatures', () => {
	it('returns no matches for an empty boot sector', () => {
		expect(matchSignatures(new Uint8Array(BOOT_SECTOR_SIZE))).toEqual([])
	})

	it('matches Signum A only when BRA.B $38 AND the body entry at $3A are present', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x38
		// Protector-style: BRA only — must NOT name Signum.
		expect(matchSignatures(boot).map(m => m.signature.name)).not.toContain('Signum A')

		boot.set([0x41, 0xFA, 0xFF, 0xC4], 0x3A)
		expect(matchSignatures(boot).map(m => m.signature.name)).toContain('Signum A')
	})

	it('does not treat BRA.B $38 alone as DJA', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x38
		expect(matchSignatures(boot).map(m => m.signature.name)).not.toContain('DJA')
	})

	it('matches an ASCII pattern case-insensitively (Chopin payload)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set(Buffer.from("fuck! you've got a virus", 'latin1'), 0x80)

		const matches = matchSignatures(boot)
		expect(matches.map(m => m.signature.name)).toContain('Chopin')
	})

	it('matches Ghost via MOVE.L #$31415926,D0 — not bare π or BRA.B $1C', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1C
		boot.set([0x26, 0x3C, 0x00, 0x00], 0x1E)
		// Bare π (as Anti-Ghost CMP immediate) must not match.
		boot.set([0x31, 0x41, 0x59, 0x26], 0x36)
		expect(matchSignatures(boot).map(m => m.signature.name)).not.toContain('Ghost A')

		// Ghost's own MOVE.L #π,D0
		boot.set([0x20, 0x3C, 0x31, 0x41, 0x59, 0x26], 0x34)
		const names = matchSignatures(boot).map(m => m.signature.name)
		expect(names).toContain('Ghost A')
		expect(names).not.toContain('Puke A')
		expect(names).not.toContain('Upside Down')
		expect(names).not.toContain('Anti-ACA')
		expect(names).not.toContain('Gotcha Xeno')
	})

	it('does not treat BRA.B $1C alone as Lazy Lion (too common)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1C

		expect(matchSignatures(boot)).toEqual([])
	})

	it('matches Finland via leading $00000000 + BRA.B $18 and Toubab credit', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x00, 0x00, 0x00, 0x00, 0x60, 0x18], 0)
		boot.set(Buffer.from('Coding: Toubab*30/08/90', 'latin1'), 0x100)
		expect(matchSignatures(boot).map(m => m.signature.name)).toContain('Finland')
	})

	it('does not name Finland from Toubab credit alone (Pure Energy reuses it)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot[0] = 0x60
		boot[1] = 0x1C
		boot.set(Buffer.from('Coding: Toubab*30/08/90', 'latin1'), 0x100)
		expect(matchSignatures(boot).map(m => m.signature.name)).not.toContain('Finland')
	})

	it('returns the offset where the Ghost MOVE.L match was found', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x20, 0x3C, 0x31, 0x41, 0x59, 0x26], 0x40)

		const match = matchSignatures(boot).find(m => m.signature.name === 'Ghost A')
		expect(match).toBeDefined()
		expect(match!.offset).toBe(0x40)
	})

	it('does not treat AVK immunization longs as Goblin without the payload string', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x27, 0x18, 0x28, 0x18], 0x1A2)
		expect(matchSignatures(boot).map(m => m.signature.name)).not.toContain('Goblin')

		boot.set(Buffer.from('Green Goblins', 'latin1'), 0x40)
		expect(matchSignatures(boot).filter(m => m.signature.name === 'Goblin')).toHaveLength(1)
	})

	it('does not match a string that only partially fits in the sector', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set(Buffer.from('PENTAGO', 'latin1'), BOOT_SECTOR_SIZE - 7)
		expect(matchSignatures(boot)).toEqual([])
	})

	it('every signature has a name, family, patterns array, and confidence', () => {
		expect(SIGNATURES.length).toBeGreaterThan(20)
		for (const sig of SIGNATURES) {
			expect(sig.name.length).toBeGreaterThan(0)
			expect(sig.family.length).toBeGreaterThan(0)
			expect(Array.isArray(sig.patterns)).toBe(true)
			expect(sig.confidence).toMatch(/^(verified|probable|speculative)$/)
		}
	})

	it('every signature with byte patterns has valid offsets and non-empty bytes', () => {
		for (const sig of SIGNATURES) {
			for (const p of sig.patterns) {
				if (p.kind === 'bytes') {
					expect(p.offset).toBeGreaterThanOrEqual(0)
					expect(p.offset).toBeLessThan(BOOT_SECTOR_SIZE)
					expect(p.bytes.length).toBeGreaterThan(0)
					expect(p.offset + p.bytes.length).toBeLessThanOrEqual(BOOT_SECTOR_SIZE)
				} else if (p.kind === 'bytes-scan') {
					expect(p.bytes.length).toBeGreaterThan(0)
					expect(p.bytes.length).toBeLessThanOrEqual(BOOT_SECTOR_SIZE)
				} else if (p.kind === 'masked') {
					const parsed = parseMaskedHex(p.hex)
					expect(parsed.bytes.length).toBeGreaterThan(0)
					expect(parsed.bytes.length).toBeLessThanOrEqual(BOOT_SECTOR_SIZE)
					// An all-wildcard pattern matches everything — never useful.
					expect(parsed.mask.some(m => m !== 0)).toBe(true)
					if (p.offset !== undefined) {
						expect(p.offset).toBeGreaterThanOrEqual(0)
						expect(p.offset + parsed.bytes.length).toBeLessThanOrEqual(BOOT_SECTOR_SIZE)
					}
				} else {
					expect(p.text.length).toBeGreaterThan(0)
				}
			}
		}
	})
})

describe('masked patterns', () => {
	it('matches an exact hex sequence', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x20, 0x3c, 0x31, 0x41, 0x59, 0x26], 0x40)
		expect(matchPattern(boot, { kind: 'masked', hex: '20 3C 31 41 59 26' })).toBe(0x40)
	})

	it('matches with ?? wildcard bytes (scan anywhere)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		// MOVE.L #π,Dn — the data register varies between Ghost variants.
		boot.set([0x2a, 0x3c, 0x31, 0x41, 0x59, 0x26], 0x80) // MOVE.L #π,D5
		expect(matchPattern(boot, { kind: 'masked', hex: '2? 3C 31 41 59 26' })).toBe(0x80)
	})

	it('matches nibble wildcards (H? and ?H)', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x60, 0x1c], 0) // BRA.B $1C
		expect(matchPattern(boot, { kind: 'masked', hex: '6? ??' })).toBe(0)
		expect(matchPattern(boot, { kind: 'masked', hex: '?0 1C' })).toBe(0)
		expect(matchPattern(boot, { kind: 'masked', hex: '4? 1C' })).toBe(-1)
	})

	it('honours the anchor offset when set', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x60, 0x38], 0)
		boot.set([0x60, 0x38], 0x40)
		expect(matchPattern(boot, { kind: 'masked', hex: '60 38', offset: 0 })).toBe(0)
		expect(matchPattern(boot, { kind: 'masked', hex: '60 38', offset: 0x20 })).toBe(-1)
	})

	it('does not match when an exact nibble differs', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0x20, 0x3c, 0x31, 0x41, 0x59, 0x27], 0x40) // π+1
		expect(matchPattern(boot, { kind: 'masked', hex: '20 3C 31 41 59 26' })).toBe(-1)
	})

	it('masked Ghost π-write does not match the bare π longword', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		// Bare π only (Anti-Ghost CMP immediate) — no preceding 2? 3C opcode.
		boot.set([0x31, 0x41, 0x59, 0x26], 0x36)
		expect(matchPattern(boot, { kind: 'masked', hex: '2? 3C 31 41 59 26' })).toBe(-1)
	})

	it('parses hex case-insensitively and rejects malformed tokens', () => {
		expect(parseMaskedHex('2a 3C ?? 4?')).toEqual({
			bytes: [0x2a, 0x3c, 0x00, 0x40],
			mask: [0xff, 0xff, 0x00, 0xf0],
		})
		expect(() => parseMaskedHex('20 3')).toThrow()
		expect(() => parseMaskedHex('zz zz')).toThrow()
		expect(() => parseMaskedHex('')).toThrow()
	})

	it('does not run past the end of the sector', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set([0xaa], BOOT_SECTOR_SIZE - 1)
		expect(matchPattern(boot, { kind: 'masked', hex: 'AA BB' })).toBe(-1)
		expect(matchPattern(boot, { kind: 'masked', hex: 'AA BB', offset: BOOT_SECTOR_SIZE - 1 })).toBe(-1)
	})
})
