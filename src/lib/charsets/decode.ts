import { ATARI_ST_TO_UNICODE } from './atariST'

/**
 * Decode a sequence of Atari ST bytes into a JavaScript string, mapping each
 * byte through the official Unicode Consortium ATARIST.TXT table.
 *
 * The Atari ST character set (TOS) is an 8-bit single-byte encoding: every
 * byte maps to exactly one Unicode codepoint. Note that the Consortium's
 * mapping preserves ASCII control codepoints for the 0x00–0x1F range — even
 * though the ST's ROM font drew visible glyphs there (arrows, bell, the
 * "Bob Dobbs" easter egg). A future "ST-font mode" could render those glyphs
 * directly; for now we follow the official mapping so output matches iconv
 * and GNU Recode.
 *
 * Line endings: ST software commonly wrote CRLF (DOS convention) but raw
 * serial output sometimes used LF only. The decoder does not normalise by
 * default; pass `{ normaliseEol: true }` to collapse CR/CRLF to LF.
 */
export function decodeAtariST(
	bytes: Uint8Array,
	options: { normaliseEol?: boolean } = {},
): string {
	const normalise = options.normaliseEol ?? false
	const codepoints: number[] = []

	for (let i = 0; i < bytes.length; i++) {
		const byte = bytes[i]

		// CRLF → LF when normalising. We peek ahead rather than emit CR then
		// strip it afterwards, so the output stream stays single-pass.
		if (normalise && byte === 0x0d && bytes[i + 1] === 0x0a) {
			codepoints.push(0x0a) // LF
			i++ // consume the CR, let the loop consume the LF
			continue
		}
		if (normalise && byte === 0x0d) {
			codepoints.push(0x0a)
			continue
		}

		codepoints.push(ATARI_ST_TO_UNICODE[byte])
	}

	// String.fromCodePoint is happy with a regular array of numbers.
	return String.fromCodePoint(...codepoints)
}

/**
 * sniffLineEndings — report which line terminators a byte stream uses.
 * Returns the dominant style so the UI can show it without forcing a choice.
 */
export type LineEnding = 'crlf' | 'lf' | 'cr' | 'none'

export function sniffLineEndings(bytes: Uint8Array): LineEnding {
	let crlf = 0
	let lf = 0
	let cr = 0

	for (let i = 0; i < bytes.length; i++) {
		const b = bytes[i]
		if (b === 0x0a) lf++
		else if (b === 0x0d && bytes[i + 1] === 0x0a) {
			crlf++
			i++
		} else if (b === 0x0d) {
			cr++
		}
	}

	const max = Math.max(crlf, lf, cr)
	if (max === 0) return 'none'
	if (crlf === max) return 'crlf'
	if (lf === max) return 'lf'
	return 'cr'
}
