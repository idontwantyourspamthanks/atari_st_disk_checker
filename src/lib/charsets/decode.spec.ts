import { describe, it, expect } from 'vitest'
import { decodeAtariST, sniffLineEndings } from './decode'

describe('decodeAtariST', () => {
	it('maps ASCII bytes (0x20–0x7E) to themselves', () => {
		const ascii = 'Hello, Atari ST!'
		const bytes = Uint8Array.from(ascii, (c) => c.charCodeAt(0))
		expect(decodeAtariST(bytes)).toBe(ascii)
	})

	it('decodes the ST pound sign at 0x9C to U+00A3', () => {
		// 0x9C in the ST charset is the £ symbol per ATARIST.TXT.
		const bytes = Uint8Array.of(0x9C)
		expect(decodeAtariST(bytes)).toBe('£')
	})

	it('decodes the ST sharp-s at 0x9E to U+00DF (ß)', () => {
		const bytes = Uint8Array.of(0x9E)
		expect(decodeAtariST(bytes)).toBe('ß')
	})

	it('decodes Hebrew Alef at 0xC2 to U+05D0 (א)', () => {
		// The ST charset placed the Hebrew alphabet at 0xC2–0xDE.
		const bytes = Uint8Array.of(0xC2)
		expect(decodeAtariST(bytes)).toBe('א')
	})

	it('preserves CR and LF by default (no normalisation)', () => {
		const bytes = Uint8Array.of(0x41, 0x0D, 0x0A, 0x42) // A\r\nB
		expect(decodeAtariST(bytes)).toBe('A\r\nB')
	})

	it('normalises CRLF to LF when requested', () => {
		const bytes = Uint8Array.of(0x41, 0x0D, 0x0A, 0x42)
		expect(decodeAtariST(bytes, { normaliseEol: true })).toBe('A\nB')
	})

	it('normalises a lone CR to LF when requested', () => {
		const bytes = Uint8Array.of(0x41, 0x0D, 0x42)
		expect(decodeAtariST(bytes, { normaliseEol: true })).toBe('A\nB')
	})

	it('handles empty input', () => {
		expect(decodeAtariST(new Uint8Array(0))).toBe('')
	})

	it('follows the official Consortium mapping for the 0x00–0x1F range', () => {
		// The Unicode Consortium's ATARIST.TXT maps ST control bytes to their
		// ASCII equivalents (e.g. 0x0B → U+000B VERTICAL TABULATION), even
		// though the ST ROM font drew visible glyphs there. We follow the
		// official mapping so output matches iconv / Recode. A future
		// "ST-font mode" could render the glyphs instead.
		expect(decodeAtariST(Uint8Array.of(0x0B)).codePointAt(0)).toBe(0x0B)
	})
})

describe('sniffLineEndings', () => {
	it('returns "none" when there are no line breaks', () => {
		expect(sniffLineEndings(Uint8Array.of(0x41, 0x42, 0x43))).toBe('none')
	})

	it('detects CRLF', () => {
		expect(sniffLineEndings(Uint8Array.of(0x41, 0x0D, 0x0A, 0x42))).toBe('crlf')
	})

	it('detects LF', () => {
		expect(sniffLineEndings(Uint8Array.of(0x41, 0x0A, 0x42))).toBe('lf')
	})

	it('detects lone CR', () => {
		expect(sniffLineEndings(Uint8Array.of(0x41, 0x0D, 0x42))).toBe('cr')
	})

	it('picks the dominant style on a mixed file', () => {
		const bytes = Uint8Array.of(
			0x41, 0x0D, 0x0A, // one CRLF
			0x42, 0x0A,      // one LF
			0x43, 0x0A,      // another LF
			0x44,
		)
		expect(sniffLineEndings(bytes)).toBe('lf')
	})
})
