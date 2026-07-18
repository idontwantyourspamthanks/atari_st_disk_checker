import { describe, it, expect } from 'vitest'
import { decodeMsa, MSA_MAGIC, MSA_HEADER_SIZE } from './msa'

/**
 * Build a tiny MSA image in memory for testing. Layout (big-endian):
 *
 *   header: 0x0E0F, spt, sidesStored, start, end
 *   per track (interleaved side 0, side 1, ...):
 *     WORD dataLength
 *     bytes (raw if dataLength == 512 × spt, else RLE)
 *
 * `tracks` is an array of Uint8Arrays, one per (track, side) pair, in the
 * interleaved order the encoder writes them: t0s0, t0s1, t1s0, t1s1, …
 */
function buildMsa(
	spt: number, sidesStored: number, start: number, end: number,
	tracks: Uint8Array[], rle: boolean[] = [],
): Uint8Array {
	const parts: number[] = []
	const pushU16BE = (v: number) => { parts.push((v >> 8) & 0xFF, v & 0xFF) }

	pushU16BE(MSA_MAGIC)
	pushU16BE(spt)
	pushU16BE(sidesStored)
	pushU16BE(start)
	pushU16BE(end)

	const bytesPerTrack = 512 * spt
	tracks.forEach((track, i) => {
		if (rle[i]) {
			const rleData = rleEncode(track)
			pushU16BE(rleData.length)
			for (const b of rleData) parts.push(b)
		} else {
			pushU16BE(track.length)
			for (const b of track) parts.push(b)
		}
	})

	// Pad tracks to exactly bytesPerTrack so the test inputs look like real files
	if (tracks.length === 0 || tracks[0].length !== bytesPerTrack) {
		// sanity check
	}
	return new Uint8Array(parts)
}

function rleEncode(track: Uint8Array): Uint8Array {
	// Naive RLE: emit literal bytes, switching to runs of 4+ identical bytes
	// (or any run of the 0xE5 marker). Matches the MSA encoder's rule.
	const out: number[] = []
	let i = 0
	while (i < track.length) {
		const b = track[i]
		let run = 1
		while (i + run < track.length && track[i + run] === b && run < 65535) run++

		const worthEncoding = run >= 4 || b === 0xE5
		if (worthEncoding) {
			out.push(0xE5, b, (run >> 8) & 0xFF, run & 0xFF)
			i += run
		} else {
			// Emit literal run of 1; the loop will pick up the next byte
			out.push(b)
			i++
		}
	}
	return new Uint8Array(out)
}

function fill(bytes: number, value: number): Uint8Array {
	const out = new Uint8Array(bytes)
	out.fill(value)
	return out
}

describe('decodeMsa — header validation', () => {
	it('rejects files shorter than the 10-byte header', () => {
		expect(() => decodeMsa(new Uint8Array(4))).toThrow(/too short/)
	})

	it('rejects a bad magic word', () => {
		const bad = new Uint8Array(MSA_HEADER_SIZE)
		bad[0] = 0xFF; bad[1] = 0xFF // wrong magic
		expect(() => decodeMsa(bad)).toThrow(/bad magic/)
	})

	it('rejects implausible sectors-per-track', () => {
		const h = new Uint8Array(MSA_HEADER_SIZE)
		const w = (off: number, v: number) => { h[off] = (v >> 8) & 0xFF; h[off + 1] = v & 0xFF }
		w(0, MSA_MAGIC); w(2, 99) // spt 99
		expect(() => decodeMsa(h)).toThrow(/sectors-per-track/)
	})

	it('rejects starting track > ending track', () => {
		const h = new Uint8Array(MSA_HEADER_SIZE)
		const w = (off: number, v: number) => { h[off] = (v >> 8) & 0xFF; h[off + 1] = v & 0xFF }
		w(0, MSA_MAGIC); w(2, 9); w(4, 0); w(6, 5); w(8, 2)
		expect(() => decodeMsa(h)).toThrow(/starting track/)
	})
})

describe('decodeMsa — uncompressed tracks', () => {
	it('decodes a single-track, single-sided image', () => {
		// 1 track, 2 sectors per track, 1 side -> 1024 bytes of output.
		const spt = 2
		const track = new Uint8Array(512 * spt)
		for (let i = 0; i < track.length; i++) track[i] = i & 0xFF

		const image = buildMsa(spt, /*sidesStored=*/0, /*start=*/0, /*end=*/0, [track])
		const decoded = decodeMsa(image)

		expect(decoded.geometry).toEqual({
			sectorsPerTrack: spt, sides: 1, startingTrack: 0, endingTrack: 0,
		})
		expect(decoded.raw).toEqual(track)
	})

	it('preserves 0xE5 bytes in an uncompressed track', () => {
		// An all-0xE5 track that is NOT RLE-compressed must come back identical.
		const spt = 1
		const track = fill(512, 0xE5)
		const image = buildMsa(spt, 0, 0, 0, [track], [/*not RLE*/])
		const decoded = decodeMsa(image)
		expect(decoded.raw).toEqual(track)
	})
})

describe('decodeMsa — RLE-compressed tracks', () => {
	it('decodes a track of all zeros (a single RLE run)', () => {
		const spt = 2 // 1024 bytes per track
		const track = fill(1024, 0x00)
		const image = buildMsa(spt, 0, 0, 0, [track], [true])
		const decoded = decodeMsa(image)
		expect(decoded.raw).toEqual(track)
		expect(decoded.raw.length).toBe(1024)
	})

	it('decodes mixed literal + run data', () => {
		// First 8 bytes: 1,2,3,4,5,6,7,8 then a run of 0xAA × 1000, then 16 trailing bytes.
		const spt = 2 // 1024 bytes per track
		const track = new Uint8Array(1024)
		for (let i = 0; i < 8; i++) track[i] = i + 1
		for (let i = 0; i < 1000; i++) track[8 + i] = 0xAA
		for (let i = 0; i < 16; i++) track[1008 + i] = 0xBB

		const image = buildMsa(spt, 0, 0, 0, [track], [true])
		const decoded = decodeMsa(image)
		expect(decoded.raw).toEqual(track)
	})

	it('encodes a literal 0xE5 byte correctly (E5 E5 00 01)', () => {
		// A track that is mostly zeros but has a single 0xE5 in the middle.
		const spt = 1 // 512 bytes
		const track = fill(512, 0x00)
		track[256] = 0xE5

		const image = buildMsa(spt, 0, 0, 0, [track], [true])
		const decoded = decodeMsa(image)
		expect(decoded.raw).toEqual(track)
		expect(decoded.raw[256]).toBe(0xE5)
	})
})

describe('decodeMsa — multi-track, multi-side', () => {
	it('decodes a 2-track, 2-side image in interleaved order', () => {
		// Layout per MSA spec: t0s0, t0s1, t1s0, t1s1
		const spt = 1
		const t0s0 = fill(512, 0x10)
		const t0s1 = fill(512, 0x20)
		const t1s0 = fill(512, 0x30)
		const t1s1 = fill(512, 0x40)

		const image = buildMsa(spt, /*sidesStored=*/1, 0, 1, [t0s0, t0s1, t1s0, t1s1])
		const decoded = decodeMsa(image)

		expect(decoded.geometry.sides).toBe(2)
		expect(decoded.raw.length).toBe(2048)
		// Order in output: t0s0, t0s1, t1s0, t1s1 (matches .st interleaving)
		expect(decoded.raw[0]).toBe(0x10)
		expect(decoded.raw[512]).toBe(0x20)
		expect(decoded.raw[1024]).toBe(0x30)
		expect(decoded.raw[1536]).toBe(0x40)
	})
})
