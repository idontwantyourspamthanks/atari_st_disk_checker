import { describe, it, expect } from 'vitest'
import { parseShortName, parseFatTimestamp } from './fat12'

describe('parseShortName', () => {
	function entry(name: string, ext: string): Uint8Array {
		const out = new Uint8Array(11)
		out.fill(0x20) // pad with spaces
		for (let i = 0; i < name.length && i < 8; i++) out[i] = name.charCodeAt(i)
		for (let i = 0; i < ext.length && i < 3; i++) out[8 + i] = ext.charCodeAt(i)
		return out
	}

	it('joins basename and extension with a dot', () => {
		expect(parseShortName(entry('README', 'TXT'))).toBe('README.TXT')
	})

	it('returns the basename alone when there is no extension', () => {
		expect(parseShortName(entry('AUTO', ''))).toBe('AUTO')
	})

	it('trims trailing space padding', () => {
		expect(parseShortName(entry('FOO', 'B'))).toBe('FOO.B')
	})

	it('preserves "." and ".." directory entries', () => {
		// "." is encoded as ".       " (dot + 7 spaces) with no extension.
		const dot = new Uint8Array(11).fill(0x20)
		dot[0] = 0x2E // '.'
		expect(parseShortName(dot)).toBe('.')

		const dotDot = new Uint8Array(11).fill(0x20)
		dotDot[0] = 0x2E; dotDot[1] = 0x2E
		expect(parseShortName(dotDot)).toBe('..')
	})

	it('restores a literal 0xE5 first byte (encoded as 0x05)', () => {
		// A real file starting with 0xE5 would be mistaken for a deleted entry,
		// so FAT stores it as 0x05 in the first byte. parseShortName restores it.
		const e = entry('_AUTOEXE', 'BAT')
		e[0] = 0x05
		expect(parseShortName(e)).toBe('\u00E5AUTOEXE.BAT')
		// And critically: it must not mutate the caller's buffer.
		expect(e[0]).toBe(0x05)
	})
})

describe('parseFatTimestamp', () => {
	it('returns null when both date and time are zero', () => {
		expect(parseFatTimestamp(0, 0)).toBeNull()
	})

	it('decodes a known date/time', () => {
		// 1991-08-23, 14:35:30
		// date: year=11 (1991-1980), month=8, day=23
		//   packed: (11<<9) | (8<<5) | 23 = 0x3A97
		// time: hours=14, minutes=35, seconds=30 -> secs/2 = 15
		//   packed: (14<<11) | (35<<5) | 15 = 0x74CF
		const date = (11 << 9) | (8 << 5) | 23
		const time = (14 << 11) | (35 << 5) | 15
		const out = parseFatTimestamp(date, time)
		expect(out).not.toBeNull()
		expect(out!.getFullYear()).toBe(1991)
		expect(out!.getMonth()).toBe(7) // 0-indexed; August = 7
		expect(out!.getDate()).toBe(23)
		expect(out!.getHours()).toBe(14)
		expect(out!.getMinutes()).toBe(35)
		expect(out!.getSeconds()).toBe(30)
	})

	it('handles the earliest representable date (1980-01-01)', () => {
		const date = (0 << 9) | (1 << 5) | 1
		expect(parseFatTimestamp(date, 0)?.getFullYear()).toBe(1980)
	})
})
