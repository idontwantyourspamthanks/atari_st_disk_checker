#!/usr/bin/env node
// Generates small Atari ST image fixtures for the parser tests:
//
//   src/lib/images/__fixtures__/sample.pi1   — Degas Elite, 320×200,  16 colours
//   src/lib/images/__fixtures__/sample.pi2   — Degas Elite, 640×200,   4 colours
//   src/lib/images/__fixtures__/sample.pi3   — Degas Elite, 640×400,   2 colours
//   src/lib/images/__fixtures__/sample.cp1   — Degas Elite compressed, 320×200
//   src/lib/images/__fixtures__/sample.tny   — Tiny Stuff, 320×200, 16 colours
//   src/lib/images/__fixtures__/sample.spu   — Spectrum 512, 320×200
//   src/lib/images/__fixtures__/sample.neo   — NeoChrome, 320×200, 16 colours
//   src/lib/images/__fixtures__/sample.iff   — IFF/ILBM, 320×200, 4 bitplanes
//
// Each fixture encodes a known pattern: vertical colour stripes (palette
// index = column // stripeWidth, where stripeWidth = width / paletteSize),
// so the tests can verify the right pixel lands at the right coordinate
// after decoding.

import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'src', 'lib', 'images', '__fixtures__')

// A canonical 16-colour ST palette (the famous "rainbow" desktop palette).
// Stored as 16-bit big-endian STe colour words (RRRrGGGgBBBb).
const PALETTE_WORDS = [
	0x0000, // 0  black
	0x0FFF, // 1  white
	0x0F00, // 2  red
	0x00F0, // 3  green
	0x000F, // 4  blue
	0x0FF0, // 5  yellow
	0x0F0F, // 6  magenta
	0x00FF, // 7  cyan
	0x0777, // 8  dark grey
	0x0333, // 9  darker grey
	0x0880, // 10 orange-ish
	0x0088, // 11 dark cyan
	0x0888, // 12 mid grey
	0x0BB0, // 13 lime
	0x0B0B, // 14 pink
	0x0BBB, // 15 pale grey
]

// Build pixels: vertical stripes with the given number of palette indices.
// Usage: pixel (x, y) = Math.floor(x / (width / numIndices)) % numIndices, so
// each stripe is exactly width/numIndices pixels wide and the palette wraps
// cleanly across the display. Returns a flat row-major Uint8Array.
function buildPixels(width, height, numIndices) {
	const stripes = numIndices
	const stripeWidth = width / stripes
	const pixels = new Uint8Array(width * height)
	for (let y = 0; y < height; y++) {
		for (let x = 0; x < width; x++) {
			pixels[y * width + x] = Math.floor(x / stripeWidth) % stripes
		}
	}
	return pixels
}

// Encode bitplanes for the given dimensions. Used for PI1/PI2/PI3.
// Layout is row-major: for each row, for each 16-pixel group, for each plane,
// write a big-endian 16-bit word. Each group is `numPlanes` words wide.
function encodeBitplanes(pixels, width, height, numPlanes) {
	const out = Buffer.alloc(32000) // all ST single-image formats fit
	let p = 0
	const groupsPerRow = width / 16
	for (let row = 0; row < height; row++) {
		for (let group = 0; group < groupsPerRow; group++) {
			const bp = new Array(numPlanes).fill(0)
			for (let px = 0; px < 16; px++) {
				const bit = 15 - px
				const ci  = pixels[row * width + group * 16 + px]
				for (let plane = 0; plane < numPlanes; plane++) {
					if ((ci >> plane) & 1) bp[plane] |= (1 << bit)
				}
			}
			for (let plane = 0; plane < numPlanes; plane++) {
				out[p++] = (bp[plane] >> 8) & 0xFF
				out[p++] = bp[plane] & 0xFF
			}
		}
	}
	return out.subarray(0, p)
}

// Degas PackBits compression. Same convention as Amiga PackBits but applied
// to the bitplane body.
function packBits(src) {
	const out = []
	let i = 0
	while (i < src.length) {
		const b = src[i]
		let run = 1
		while (i + run < src.length && src[i + run] === b && run < 128) run++
		if (run >= 4) {
			// PackBits: control n in [-127,-1] repeats the next byte (1-n) times.
			out.push((1 - run + 256) & 0xFF, b)
			i += run
		} else {
			let literals = 0
			while (literals < 128 && i + literals < src.length) {
				const nextB = src[i + literals]
				let nextRun = 1
				while (i + literals + nextRun < src.length && src[i + literals + nextRun] === nextB && nextRun < 128) nextRun++
				if (nextRun >= 4 && literals > 0) break
				if (nextRun >= 4) break
				literals++
			}
			out.push(literals - 1)
			for (let k = 0; k < literals; k++) out.push(src[i + k])
			i += literals
		}
	}
	return Buffer.from(out)
}

function buildPi1() {
	const buf = Buffer.alloc(32034)
	buf.writeUInt16BE(0, 0) // resolution 0 = low res 320×200
	for (let i = 0; i < 16; i++) {
		buf.writeUInt16BE(PALETTE_WORDS[i], 2 + i * 2)
	}
	const pixels = buildPixels(320, 200, 16)
	const bitplanes = encodeBitplanes(pixels, 320, 200, 4)
	bitplanes.copy(buf, 34)
	return buf
}

function buildPi2() {
	const buf = Buffer.alloc(32034)
	buf.writeUInt16BE(1, 0) // resolution 1 = medium res 640×200, 4 colours
	for (let i = 0; i < 16; i++) {
		buf.writeUInt16BE(PALETTE_WORDS[i % 4], 2 + i * 2)
	}
	const pixels = buildPixels(640, 200, 4)
	const bitplanes = encodeBitplanes(pixels, 640, 200, 2)
	bitplanes.copy(buf, 34)
	return buf
}

function buildPi3() {
	const buf = Buffer.alloc(32034)
	buf.writeUInt16BE(2, 0) // resolution 2 = high res 640×400, 2 colours
	for (let i = 0; i < 16; i++) {
		buf.writeUInt16BE(PALETTE_WORDS[i % 2], 2 + i * 2)
	}
	const pixels = buildPixels(640, 400, 2)
	const bitplanes = encodeBitplanes(pixels, 640, 400, 1)
	bitplanes.copy(buf, 34)
	return buf
}

function buildPi1Compressed() {
	const pixels = buildPixels(320, 200, 16)
	const bitplanes = encodeBitplanes(pixels, 320, 200, 4)
	const packed = packBits(bitplanes)
	const buf = Buffer.alloc(2 + 32 + packed.length)
	buf.writeUInt16BE(0x8000, 0)
	for (let i = 0; i < 16; i++) {
		buf.writeUInt16BE(PALETTE_WORDS[i], 2 + i * 2)
	}
	packed.copy(buf, 34)
	return buf
}

function buildNeo() {
	const buf = Buffer.alloc(32128)
	buf.writeUInt16BE(0, 0)
	buf.writeUInt16BE(0, 2)
	for (let i = 0; i < 16; i++) {
		buf.writeUInt16BE(PALETTE_WORDS[i], 4 + i * 2)
	}
	const pixels = buildPixels(320, 200, 16)
	const bitplanes = encodeBitplanes(pixels, 320, 200, 4)
	bitplanes.copy(buf, 128)
	return buf
}

// ── Tiny Stuff encoder ────────────────────────────────────────────────────────

/** Scramble linear screen-memory words into Tiny's 4-set column order. */
function scrambleTinyColumns(screenBytes) {
	const words = new Uint16Array(16000)
	let i = 0
	for (let set = 0; set < 4; set++) {
		for (let column = set; column < 80; column += 4) {
			for (let scanline = 0; scanline < 200; scanline++) {
				const off = (scanline * 80 + column) * 2
				words[i++] = (screenBytes[off] << 8) | screenBytes[off + 1]
			}
		}
	}
	return words
}

/** Tiny RLE: emit separate control-byte and data-word streams. */
function packTiny(words) {
	const control = []
	const data = []

	const pushDataWord = (w) => {
		data.push((w >> 8) & 0xFF, w & 0xFF)
	}

	let i = 0
	while (i < words.length) {
		const w = words[i]
		let run = 1
		while (i + run < words.length && words[i + run] === w && run < 32767) run++

		if (run >= 2) {
			if (run <= 127) {
				control.push(run)
				pushDataWord(w)
			} else {
				control.push(0)
				pushDataWord(run)
				pushDataWord(w)
			}
			i += run
			continue
		}

		let lit = 1
		while (i + lit < words.length && lit < 32767) {
			const next = words[i + lit]
			let nextRun = 1
			while (i + lit + nextRun < words.length && words[i + lit + nextRun] === next && nextRun < 128) nextRun++
			if (nextRun >= 2) break
			lit++
		}

		if (lit <= 127) {
			control.push((256 - lit) & 0xFF) // negative count as unsigned byte
			for (let k = 0; k < lit; k++) pushDataWord(words[i + k])
		} else {
			control.push(1)
			pushDataWord(lit)
			for (let k = 0; k < lit; k++) pushDataWord(words[i + k])
		}
		i += lit
	}

	return { control: Buffer.from(control), data: Buffer.from(data) }
}

function buildTny() {
	const pixels = buildPixels(320, 200, 16)
	const bitplanes = encodeBitplanes(pixels, 320, 200, 4)
	const scrambled = scrambleTinyColumns(bitplanes)
	const { control, data } = packTiny(scrambled)

	const header = Buffer.alloc(1 + 32 + 4)
	header[0] = 0 // low res
	for (let i = 0; i < 16; i++) {
		header.writeUInt16BE(PALETTE_WORDS[i], 1 + i * 2)
	}
	header.writeUInt16BE(control.length, 33)
	header.writeUInt16BE(data.length / 2, 35)
	return Buffer.concat([header, control, data])
}

// ── Spectrum 512 uncompressed ─────────────────────────────────────────────────

function buildSpu() {
	// Same stripe pattern as PI1. Scanline 0 is blanked (Spectrum can't
	// display it). All three mid-scanline palette banks get the same 16
	// colours so FindIndex is a no-op for absolute colour and the decoded
	// image matches the PI1 stripe pattern (except the black top line).
	const pixels = buildPixels(320, 200, 16)
	const bitplanes = Buffer.from(encodeBitplanes(pixels, 320, 200, 4))
	bitplanes.fill(0, 0, 160)

	const palettes = Buffer.alloc(199 * 3 * 16 * 2)
	for (let line = 0; line < 199; line++) {
		for (let bank = 0; bank < 3; bank++) {
			for (let i = 0; i < 16; i++) {
				const off = (line * 48 + bank * 16 + i) * 2
				palettes.writeUInt16BE(PALETTE_WORDS[i], off)
			}
		}
	}

	return Buffer.concat([bitplanes, palettes])
}

// Encode IFF body: per-row, per-plane, per-byte (8 pixels per byte, MSB first).
function encodeIffBody(pixels, width = 320, height = 200, nPlanes = 4) {
	const rowbytes = width / 8
	const out = Buffer.alloc(height * nPlanes * rowbytes)
	let p = 0
	for (let row = 0; row < height; row++) {
		for (let plane = 0; plane < nPlanes; plane++) {
			for (let byte = 0; byte < rowbytes; byte++) {
				let b = 0
				for (let bit = 0; bit < 8; bit++) {
					const col = byte * 8 + bit
					const ci = pixels[row * width + col]
					if ((ci >> plane) & 1) b |= (1 << (7 - bit))
				}
				out[p++] = b
			}
		}
	}
	return out
}

function buildIff() {
	const width = 320, height = 200, nPlanes = 4
	const pixels = buildPixels(320, 200, 16)
	const body = encodeIffBody(pixels, width, height, nPlanes)

	const cmap = Buffer.alloc(16 * 3)
	const to8 = (v4) => Math.round(v4 / 15 * 255)
	for (let i = 0; i < 16; i++) {
		const w = PALETTE_WORDS[i]
		const r4 = ((w >> 8) & 0x7) << 1 | ((w >> 11) & 0x1)
		const g4 = ((w >> 4) & 0x7) << 1 | ((w >>  7) & 0x1)
		const b4 = ((w >> 0) & 0x7) << 1 | ((w >>  3) & 0x1)
		cmap[i * 3]     = to8(r4)
		cmap[i * 3 + 1] = to8(g4)
		cmap[i * 3 + 2] = to8(b4)
	}

	const bmhd = Buffer.alloc(20)
	bmhd.writeUInt16BE(width, 0)
	bmhd.writeUInt16BE(height, 2)
	bmhd.writeUInt16BE(0, 4)
	bmhd.writeUInt16BE(0, 6)
	bmhd[8]  = nPlanes
	bmhd[9]  = 0
	bmhd[10] = 0
	bmhd[11] = 0
	bmhd.writeUInt16BE(0, 12)
	bmhd.writeUInt16BE(width, 16)
	bmhd.writeUInt16BE(height, 18)

	function chunk(id, data) {
		const header = Buffer.alloc(8)
		header.write(id, 0, 'latin1')
		header.writeUInt32BE(data.length, 4)
		const pad = (data.length & 1) ? Buffer.from([0]) : Buffer.alloc(0)
		return Buffer.concat([header, data, pad])
	}

	const form = Buffer.concat([
		chunk('BMHD', bmhd),
		chunk('CMAP', cmap),
		chunk('BODY', body),
	])
	const formHeader = Buffer.alloc(12)
	formHeader.write('FORM', 0, 'latin1')
	formHeader.writeUInt32BE(form.length + 4, 4)
	formHeader.write('ILBM', 8, 'latin1')
	return Buffer.concat([formHeader, form])
}

console.log('Cleaning previous image fixtures…')
rmSync(fixturesDir, { recursive: true, force: true })
mkdirSync(fixturesDir, { recursive: true })

const files = {
	'sample.pi1': buildPi1(),
	'sample.pi2': buildPi2(),
	'sample.pi3': buildPi3(),
	'sample.cp1': buildPi1Compressed(),
	'sample.tny': buildTny(),
	'sample.spu': buildSpu(),
	'sample.neo': buildNeo(),
	'sample.iff': buildIff(),
}

console.log('Wrote:')
for (const [name, buf] of Object.entries(files)) {
	writeFileSync(join(fixturesDir, name), buf)
	console.log(`  ${name}  (${buf.length} bytes)`)
}
