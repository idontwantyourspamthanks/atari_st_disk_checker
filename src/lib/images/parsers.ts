// Atari ST image-format parsers, ported from LemonAndLime's
// `web/src/lib/import-retro.ts` (which I also wrote). Handles the three
// common ST low-resolution formats: Degas Elite (.PI1), NeoChrome (.NEO),
// and DPaint IFF/ILBM. All decode to a common DecodedImage shape so the
// UI can render them the same way.
//
// Colour depth: the STfm had a 512-colour palette (3 bits per channel); the
// STe expanded to 4096 (4 bits per channel). Both use the same 16-bit word
// format in palette tables, with the low bit of each channel used only on
// STe. steWordToHex below handles both cases.

export interface DecodedImage {
	width: number
	height: number
	/**
	 * Flat row-major array of palette indices, 0-based.
	 * Uint16Array is used when a format can exceed 256 unique colours
	 * (Spectrum 512); everything else stays on Uint8Array.
	 */
	pixels: Uint8Array | Uint16Array
	/** Hex colour strings like "#ff8000", indexed by `pixels`. */
	palette: string[]
	/** Format the image was decoded from — useful for the UI. */
	format: 'pi1' | 'pi2' | 'pi3' | 'pi1c' | 'tny' | 'spu' | 'neo' | 'iff'
}

// ── STe colour word → hex ──────────────────────────────────────────────────────
// Word layout: 0000 RRRr GGGg BBBb (12 bits, STe format)
// Upper 3 bits are bits 3-1 of the 4-bit value; the stray bit is bit 0 (LSB).
// On STfm only the upper 3 bits matter (the LSB reads as 0), so STfm images
// render identically — they just don't use the half-step.

function steWordToHex(word: number): string {
	const decode4 = (high3: number, lsb: number) => (high3 << 1) | lsb
	const r4 = decode4((word >> 8) & 0x7, (word >> 11) & 0x1)
	const g4 = decode4((word >> 4) & 0x7, (word >> 7) & 0x1)
	const b4 = decode4((word >> 0) & 0x7, (word >> 3) & 0x1)
	const to8 = (v4: number) => Math.round(v4 / 15 * 255).toString(16).padStart(2, '0')
	return '#' + to8(r4) + to8(g4) + to8(b4)
}

function readStePalette(bytes: Uint8Array, offset: number, count = 16): string[] {
	const palette: string[] = []
	for (let i = 0; i < count; i++) {
		const hi = bytes[offset + i * 2]
		const lo = bytes[offset + i * 2 + 1]
		palette.push(steWordToHex((hi << 8) | lo))
	}
	return palette
}

// ── ST bitplane decoder ───────────────────────────────────────────────────────
// Layout varies by resolution but the interleave pattern is the same:
// `height` rows × `width/16` groups of 16 pixels × `numPlanes` big-endian
// uint16 bitplane words. Each 16-pixel group is described by numPlanes words
// (one per bitplane); the colour index of pixel N within the group is
// assembled from bit (15-N) of each plane.
//
//   Low res   (PI1): 320×200,  4 planes
//   Medium res (PI2): 640×200, 2 planes
//   High res   (PI3): 640×400, 1 plane
//
// All three fit into 32000 bytes of bitplane data (the standard ST one-image
// uncompressed body size).

function decodeStBitplanes(
	bytes: Uint8Array,
	offset: number,
	width: number,
	height: number,
	numPlanes: number,
): Uint8Array {
	const pixels = new Uint8Array(width * height)
	const groupsPerRow = width / 16
	for (let row = 0; row < height; row++) {
		for (let group = 0; group < groupsPerRow; group++) {
			const base = offset + (row * groupsPerRow + group) * numPlanes * 2
			const bp: number[] = []
			for (let p = 0; p < numPlanes; p++) {
				bp.push((bytes[base + p * 2] << 8) | bytes[base + p * 2 + 1])
			}
			for (let px = 0; px < 16; px++) {
				const bit = 15 - px
				let ci = 0
				for (let p = 0; p < numPlanes; p++) {
					ci |= ((bp[p] >> bit) & 1) << p
				}
				pixels[row * width + group * 16 + px] = ci
			}
		}
	}
	return pixels
}

// ── Degas Elite PI1 (low res, uncompressed) ───────────────────────────────────
// 2-byte resolution + 32-byte colour table + 32000-byte bitplane data = 32034 bytes.
// Resolution word: bit 0x8000 = compressed; low byte 0 = low, 1 = medium, 2 = high.
// This function handles the uncompressed low-res case (`0x0000`).

export function parsePi1(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 32034) {
		throw new Error(`PI1 too small (${bytes.length} bytes; need at least 32034)`)
	}
	const palette = readStePalette(bytes, 2)
	const pixels  = decodeStBitplanes(bytes, 34, 320, 200, 4)
	return { width: 320, height: 200, pixels, palette, format: 'pi1' }
}

// ── Degas Elite PI2 (medium res, uncompressed) ───────────────────────────────
// Same container as PI1 but 640×200, 2 bitplanes, 4-colour palette. The
// 32-byte palette block is still present (high bytes only are used).

export function parsePi2(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 32034) {
		throw new Error(`PI2 too small (${bytes.length} bytes; need at least 32034)`)
	}
	const palette = readStePalette(bytes, 2, /*count*/ 4)
	const pixels  = decodeStBitplanes(bytes, 34, 640, 200, 2)
	return { width: 640, height: 200, pixels, palette, format: 'pi2' }
}

// ── Degas Elite PI3 (high res, uncompressed) ─────────────────────────────────
// 640×400, 1 bitplane, 2-colour palette.

export function parsePi3(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 32034) {
		throw new Error(`PI3 too small (${bytes.length} bytes; need at least 32034)`)
	}
	const palette = readStePalette(bytes, 2, /*count*/ 2)
	const pixels  = decodeStBitplanes(bytes, 34, 640, 400, 1)
	return { width: 640, height: 400, pixels, palette, format: 'pi3' }
}

// ── Degas Elite PI1 (compressed) ─────────────────────────────────────────────
// Same header (34 bytes: resolution + palette) but body is PackBits-
// compressed and decodes to 32000 bytes of low-res 4-plane bitplane data.
// Resolution word's high bit (0x8000) signals compression.

export function parsePi1Compressed(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 34) {
		throw new Error(`Compressed PI1 too small (${bytes.length} bytes; need at least 34)`)
	}
	const palette = readStePalette(bytes, 2)
	const body    = bytes.subarray(34)
	const unpacked = unpackBits(body, 32000)
	const pixels  = decodeStBitplanes(unpacked, 0, 320, 200, 4)
	return { width: 320, height: 200, pixels, palette, format: 'pi1c' }
}

// ── NeoChrome NEO ─────────────────────────────────────────────────────────────
// 128-byte header (flags + resolution + colour table at offset 4) + 32000-byte bitplane data.
// Optional 2-byte animation flag + 2-byte slide delay at end (we ignore those).

export function parseNeo(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 32128) {
		throw new Error(`NEO too small (${bytes.length} bytes; need at least 32128)`)
	}
	const palette = readStePalette(bytes, 4)
	const pixels  = decodeStBitplanes(bytes, 128, 320, 200, 4)
	return { width: 320, height: 200, pixels, palette, format: 'neo' }
}

// ── IFF/ILBM ──────────────────────────────────────────────────────────────────
// Standard "FORM...ILBM" container with BMHD, CMAP, BODY chunks. Handles
// both uncompressed (compression=0) and PackBits (compression=1) bodies.
// Atari ST and Amiga share this format; on an ST disk we assume ST.

function unpackBits(src: Uint8Array, unpackedSize: number): Uint8Array {
	const out = new Uint8Array(unpackedSize)
	let si = 0, di = 0
	while (si < src.length && di < unpackedSize) {
		const raw = src[si++]
		const n   = raw > 127 ? raw - 256 : raw   // signed byte
		if (n >= 0) {
			const count = n + 1
			for (let i = 0; i < count && di < unpackedSize; i++) out[di++] = src[si++]
		} else if (n !== -128) {
			const count = 1 - n
			const byte  = src[si++]
			for (let i = 0; i < count && di < unpackedSize; i++) out[di++] = byte
		}
	}
	return out
}

function str4(bytes: Uint8Array, offset: number): string {
	return String.fromCharCode(
		bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
	)
}

function readU32BE(bytes: Uint8Array, offset: number): number {
	return ((bytes[offset]     << 24) |
	        (bytes[offset + 1] << 16) |
	        (bytes[offset + 2] <<  8) |
	        (bytes[offset + 3])) >>> 0
}

function readU16BE(bytes: Uint8Array, offset: number): number {
	return (bytes[offset] << 8) | bytes[offset + 1]
}

export function parseIff(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 12 || str4(bytes, 0) !== 'FORM' || str4(bytes, 8) !== 'ILBM') {
		throw new Error('Not a valid ILBM IFF file (expected FORM...ILBM)')
	}

	let width = 0, height = 0, nPlanes = 4, compression = 0
	const palette: string[] = []
	let bodyOffset = -1, bodySize = 0
	let pos = 12

	while (pos + 8 <= bytes.length) {
		const chunkId   = str4(bytes, pos)
		const chunkSize = readU32BE(bytes, pos + 4)
		const dataStart = pos + 8
		pos = dataStart + chunkSize + (chunkSize & 1)   // IFF chunks are word-aligned

		if (chunkId === 'BMHD') {
			width       = readU16BE(bytes, dataStart)
			height      = readU16BE(bytes, dataStart + 2)
			nPlanes     = bytes[dataStart + 8]
			compression = bytes[dataStart + 10]
		} else if (chunkId === 'CMAP') {
			const entries = Math.floor(chunkSize / 3)
			for (let i = 0; i < entries; i++) {
				const r = bytes[dataStart + i * 3]
				const g = bytes[dataStart + i * 3 + 1]
				const b = bytes[dataStart + i * 3 + 2]
				palette.push('#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join(''))
			}
		} else if (chunkId === 'BODY') {
			bodyOffset = dataStart
			bodySize   = chunkSize
		}
	}

	if (bodyOffset === -1) throw new Error('No BODY chunk found in IFF file')

	const rawRowbytes = Math.ceil(width / 8)
	const rowbytes    = rawRowbytes + (rawRowbytes % 2)   // word-align
	const unpackedLen = height * nPlanes * rowbytes
	const rawBody     = bytes.subarray(bodyOffset, bodyOffset + bodySize)
	const body        = compression === 1 ? unpackBits(rawBody, unpackedLen) : rawBody

	const pixels = new Uint8Array(width * height)
	let bpos = 0
	for (let row = 0; row < height; row++) {
		for (let plane = 0; plane < nPlanes; plane++) {
			for (let byte = 0; byte < rowbytes; byte++) {
				const b = body[bpos++]
				for (let bit = 0; bit < 8; bit++) {
					const col = byte * 8 + bit
					if (col < width && (b & (1 << (7 - bit)))) {
						pixels[row * width + col] |= (1 << plane)
					}
				}
			}
		}
	}

	return { width, height, pixels, palette, format: 'iff' }
}

// ── Tiny Stuff (.TNY / .TN1 / .TN2 / .TN3) ────────────────────────────────────
// Custom RLE (not PackBits). Control bytes and data words live in separate
// streams. Expanded output is 16000 big-endian words in a column-interleaved
// order that must be unscrambled back into normal ST screen memory before
// bitplane decode. See MultimediaWiki "Tiny Stuff" / PIC_FMTS.TXT.

const TNY_WORDS = 16000

function unpackTiny(
	control: Uint8Array,
	data: Uint8Array,
): Uint16Array {
	const out = new Uint16Array(TNY_WORDS)
	let ci = 0, di = 0, oi = 0

	const nextDataWord = (): number => {
		if (di + 1 >= data.length) {
			throw new Error('Tiny: truncated data section')
		}
		const w = (data[di] << 8) | data[di + 1]
		di += 2
		return w
	}

	while (oi < TNY_WORDS) {
		if (ci >= control.length) {
			throw new Error('Tiny: truncated control section')
		}
		const raw = control[ci++]
		const x = raw > 127 ? raw - 256 : raw // signed byte

		if (x < 0) {
			const count = -x
			for (let i = 0; i < count && oi < TNY_WORDS; i++) out[oi++] = nextDataWord()
		} else if (x === 0) {
			const count = nextDataWord()
			const word  = nextDataWord()
			for (let i = 0; i < count && oi < TNY_WORDS; i++) out[oi++] = word
		} else if (x === 1) {
			const count = nextDataWord()
			for (let i = 0; i < count && oi < TNY_WORDS; i++) out[oi++] = nextDataWord()
		} else {
			const word = nextDataWord()
			for (let i = 0; i < x && oi < TNY_WORDS; i++) out[oi++] = word
		}
	}
	return out
}

/** Unscramble Tiny's 4-set vertical-column order into linear screen memory. */
function unscrambleTinyColumns(words: Uint16Array): Uint8Array {
	const screen = new Uint8Array(TNY_WORDS * 2)
	let i = 0
	for (let set = 0; set < 4; set++) {
		for (let column = set; column < 80; column += 4) {
			for (let scanline = 0; scanline < 200; scanline++) {
				const w = words[i++]
				const off = (scanline * 80 + column) * 2
				screen[off]     = (w >> 8) & 0xFF
				screen[off + 1] = w & 0xFF
			}
		}
	}
	return screen
}

export function parseTny(bytes: Uint8Array): DecodedImage {
	if (bytes.length < 37) {
		throw new Error(`TNY too small (${bytes.length} bytes; need at least 37)`)
	}

	let pos = 0
	let resolution = bytes[pos++]
	// Resolutions 3/4/5 carry an optional 4-byte colour-animation block.
	if (resolution > 2) {
		if (bytes.length < 41) {
			throw new Error(`TNY too small for animated header (${bytes.length} bytes)`)
		}
		pos += 4
		resolution -= 3
	}

	const palette = readStePalette(bytes, pos)
	pos += 32

	const nControl = readU16BE(bytes, pos); pos += 2
	const nData    = readU16BE(bytes, pos); pos += 2

	if (pos + nControl + nData * 2 > bytes.length) {
		throw new Error(
			`TNY truncated (need ${nControl} control + ${nData} data words from offset ${pos}; ` +
			`file is ${bytes.length} bytes)`,
		)
	}

	const control = bytes.subarray(pos, pos + nControl)
	const data    = bytes.subarray(pos + nControl, pos + nControl + nData * 2)
	const words   = unpackTiny(control, data)
	const screen  = unscrambleTinyColumns(words)

	let width: number, height: number, planes: number, palCount: number
	switch (resolution) {
		case 0: width = 320; height = 200; planes = 4; palCount = 16; break
		case 1: width = 640; height = 200; planes = 2; palCount = 4;  break
		case 2: width = 640; height = 400; planes = 1; palCount = 2;  break
		default:
			throw new Error(`TNY: unsupported resolution byte ${resolution}`)
	}

	const pixels = decodeStBitplanes(screen, 0, width, height, planes)
	return {
		width, height, pixels,
		palette: palette.slice(0, palCount),
		format: 'tny',
	}
}

// ── Spectrum 512 (.SPU / .SPL) ────────────────────────────────────────────────
// Uncompressed: 160 bytes unused (scanline 0) + 31840 bytes of bitplane data
// for scanlines 1–199 + 19104 bytes of per-scanline palettes (199 lines × 3
// palettes × 16 STe words). Total 51104 bytes.
//
// Three palette banks per scanline are swapped mid-line; FindIndex maps an
// (x, colour-index) pair onto the correct bank entry (0–47).

const SPU_SIZE = 51104
const SPU_BITMAP = 32000 // including the unused first scanline
const SPU_PALETTE_BYTES = 199 * 3 * 16 * 2

/** Spectrum mid-scanline palette bank selector (Steve Belczyk, public domain). */
export function spectrumFindIndex(x: number, c: number): number {
	let x1 = 10 * c
	if (c & 1) x1 -= 5
	else       x1 += 1
	if (x >= x1 && x < x1 + 160) return c + 16
	if (x >= x1 + 160)           return c + 32
	return c
}

export function parseSpu(bytes: Uint8Array): DecodedImage {
	if (bytes.length < SPU_SIZE) {
		throw new Error(`SPU too small (${bytes.length} bytes; need ${SPU_SIZE})`)
	}
	// Layout: SPU_BITMAP bytes of bitplanes + SPU_PALETTE_BYTES of palettes.
	if (bytes.length < SPU_BITMAP + SPU_PALETTE_BYTES) {
		throw new Error(`SPU truncated palette section`)
	}

	// Bitplane data is standard low-res ST layout; scanline 0 is unused/zero.
	const bitplanes = bytes.subarray(0, SPU_BITMAP)
	const rawPixels = decodeStBitplanes(bitplanes, 0, 320, 200, 4)

	const palOffset = SPU_BITMAP
	// Resolve each pixel to an absolute STe colour word, then dedupe into a
	// compact palette. Spectrum can use hundreds of unique colours; indices
	// therefore live in a Uint16Array.
	const colorWords = new Uint16Array(320 * 200)
	const unique = new Map<number, number>() // steWord → palette index
	const paletteWords: number[] = []

	const readPalWord = (line: number, bankEntry: number): number => {
		// Palettes cover scanlines 1–199 only; scanline 0 has no palette —
		// treat it as black.
		if (line === 0) return 0
		const lineIdx = line - 1
		const off = palOffset + (lineIdx * 48 + bankEntry) * 2
		return (bytes[off] << 8) | bytes[off + 1]
	}

	for (let y = 0; y < 200; y++) {
		for (let x = 0; x < 320; x++) {
			const ci = rawPixels[y * 320 + x] & 0xF
			const bank = spectrumFindIndex(x, ci)
			const word = readPalWord(y, bank)
			let idx = unique.get(word)
			if (idx === undefined) {
				idx = paletteWords.length
				unique.set(word, idx)
				paletteWords.push(word)
			}
			colorWords[y * 320 + x] = idx
		}
	}

	const palette = paletteWords.map(steWordToHex)

	return {
		width: 320,
		height: 200,
		pixels: colorWords,
		palette,
		format: 'spu',
	}
}

// ── Dispatch by filename extension ─────────────────────────────────────────────

export type ImageKind = 'pi1' | 'pi2' | 'pi3' | 'pi1c' | 'tny' | 'spu' | 'neo' | 'iff'

export function imageKindFromName(fileName: string): ImageKind | null {
	const lower = fileName.toLowerCase()
	if (lower.endsWith('.pi1')) return 'pi1'
	if (lower.endsWith('.pi2')) return 'pi2'
	if (lower.endsWith('.pi3')) return 'pi3'
	if (lower.endsWith('.tny') || lower.endsWith('.tn1') ||
	    lower.endsWith('.tn2') || lower.endsWith('.tn3')) return 'tny'
	// .SPL is an uncommon alias some archives use for uncompressed Spectrum.
	if (lower.endsWith('.spu') || lower.endsWith('.spl')) return 'spu'
	if (lower.endsWith('.neo') || lower.endsWith('.ne')) return 'neo'
	if (lower.endsWith('.iff') || lower.endsWith('.ilbm')) return 'iff'
	// Compressed PI1 files use the same .pi1 extension — the parseImageKind
	// entry point distinguishes them by checking the resolution word's 0x8000
	// bit at runtime.
	return null
}

export function parseImage(bytes: Uint8Array, fileName: string): DecodedImage {
	const kind = imageKindFromName(fileName)
	if (!kind) throw new Error(`Not a recognised image format: ${fileName}`)

	// .PI1 is ambiguous: it could be uncompressed (the common case) or
	// PackBits-compressed. Disambiguate by checking the high bit of the
	// resolution word.
	if (kind === 'pi1' && bytes.length >= 2) {
		const res = (bytes[0] << 8) | bytes[1]
		if (res & 0x8000) return parsePi1Compressed(bytes)
	}

	return parseImageKind(bytes, kind)
}

export function parseImageKind(bytes: Uint8Array, kind: ImageKind): DecodedImage {
	switch (kind) {
		case 'pi1': return parsePi1(bytes)
		case 'pi2': return parsePi2(bytes)
		case 'pi3': return parsePi3(bytes)
		case 'pi1c': return parsePi1Compressed(bytes)
		case 'tny': return parseTny(bytes)
		case 'spu': return parseSpu(bytes)
		case 'neo': return parseNeo(bytes)
		case 'iff': return parseIff(bytes)
	}
}
