import { describe, it, expect } from 'vitest'
import { detectFormat } from './diskImage'

describe('detectFormat', () => {
	it('returns "msa" when the first two bytes are the 0x0E0F magic', () => {
		const bytes = new Uint8Array([0x0E, 0x0F, 0x00, 0x00])
		expect(detectFormat(bytes)).toBe('msa')
	})

	it('returns "stx" when the buffer starts with RSY\\0', () => {
		const bytes = new Uint8Array([0x52, 0x53, 0x59, 0x00, 0x03, 0x00])
		expect(detectFormat(bytes)).toBe('stx')
	})

	it('returns "st" for a buffer that does not start with a known magic', () => {
		const bytes = new Uint8Array([0xEB, 0x3C, 0x90, 0x00])
		expect(detectFormat(bytes)).toBe('st')
	})

	it('returns "st" for a buffer shorter than 2 bytes', () => {
		expect(detectFormat(new Uint8Array([0x0E]))).toBe('st')
	})

	it('returns "st" for an empty buffer', () => {
		expect(detectFormat(new Uint8Array(0))).toBe('st')
	})
})

// openDiskImage's happy path is exercised end-to-end by the integration spec
// against the mtools-generated .st and hand-encoded .msa fixtures. The only
// remaining unit-level guarantee is its rejection of an unreadable boot
// sector — which is what the FAT12Image constructor already validates, so we
// don't duplicate the assertion here.

