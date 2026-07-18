import { describe, it, expect } from 'vitest'
import { matchProtectors, PROTECTORS } from './protectors'
import { BOOT_SECTOR_SIZE } from './bootSector'

describe('matchProtectors', () => {
	it('returns no matches for an empty boot sector', () => {
		expect(matchProtectors(new Uint8Array(BOOT_SECTOR_SIZE))).toEqual([])
	})

	it('matches Sagrotan by branding string', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set(Buffer.from('SAGROTAN 4.12', 'latin1'), 0x40)
		const names = matchProtectors(boot).map(m => m.protector.name)
		expect(names).toContain('Sagrotan')
	})

	it('matches Medway Boys Protector', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set(Buffer.from('The Medway Boys Protector II', 'latin1'), 0x80)
		expect(matchProtectors(boot).map(m => m.protector.name)).toContain('Medway Boys Protector')
	})

	it('matches the generic virus-free catch-all', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set(Buffer.from('THIS DISK IS VIRUS FREE', 'latin1'), 0x50)
		expect(matchProtectors(boot).some(m => m.protector.family === 'Generic')).toBe(true)
	})

	it('is case-insensitive', () => {
		const boot = new Uint8Array(BOOT_SECTOR_SIZE)
		boot.set(Buffer.from('sagrotan', 'latin1'), 0x20)
		expect(matchProtectors(boot).map(m => m.protector.name)).toContain('Sagrotan')
	})

	it('every protector has a name, family, and at least one pattern', () => {
		expect(PROTECTORS.length).toBeGreaterThan(15)
		for (const p of PROTECTORS) {
			expect(p.name.length).toBeGreaterThan(0)
			expect(p.family.length).toBeGreaterThan(0)
			expect(p.patterns.length).toBeGreaterThan(0)
		}
	})
})
