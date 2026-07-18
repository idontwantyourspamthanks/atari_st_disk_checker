import { readU16BE } from './bytes'

/**
 * Magic word at the start of every MSA file. The Hatari sources document this
 * as $0E0F (not the "MS" / 0x4D53 this author had half-remembered).
 */
export const MSA_MAGIC = 0x0E0F

/** Header size in bytes: 5 big-endian words. */
export const MSA_HEADER_SIZE = 10

/** RLE marker byte within a compressed track. */
const MSA_RLE_MARKER = 0xE5

const SECTOR_SIZE = 512

export interface MsaGeometry {
	sectorsPerTrack: number
	sides: number            // actual sides (1 or 2)
	startingTrack: number
	endingTrack: number
}

export interface MsaImage {
	geometry: MsaGeometry
	/** Raw sector data, layout identical to a .st image. */
	raw: Uint8Array
}

/**
 * Decode a `.msa` (Magic Shadow Archiver) disk image into raw sector bytes —
 * the same layout as a `.st` file.
 *
 * Header (10 bytes, big-endian):
 *   Word 0  ID marker (0x0E0F)
 *   Word 1  sectors per track
 *   Word 2  sides stored as 0 or 1 (add 1 for actual count)
 *   Word 3  starting track
 *   Word 4  ending track
 *
 * Tracks follow in side-interleaved order: track 0 side 0, track 0 side 1,
 * track 1 side 0, … Each track is a WORD length prefix followed by either
 * raw sector data (length == 512 × SPT) or RLE-compressed data. RLE: a
 * literal 0xE5 byte signals a run — read value byte + run-length word, emit
 * that many copies of the value. An actual 0xE5 on disk encodes as
 * 0xE5 0xE5 0x00 0x01.
 *
 * Spec source: hatari/src/floppies/msa.c (GPL-2+).
 */
export function decodeMsa(data: Uint8Array): MsaImage {
	if (data.length < MSA_HEADER_SIZE) {
		throw new Error(`MSA: file too short (${data.length} bytes; need at least ${MSA_HEADER_SIZE})`)
	}

	const magic = readU16BE(data, 0)
	if (magic !== MSA_MAGIC) {
		throw new Error(
			`MSA: bad magic 0x${magic.toString(16).padStart(4, '0')} (expected 0x${MSA_MAGIC.toString(16)})`,
		)
	}

	const sectorsPerTrack = readU16BE(data, 2)
	const sidesStored     = readU16BE(data, 4)
	const startingTrack   = readU16BE(data, 6)
	const endingTrack     = readU16BE(data, 8)

	validateMsaHeader(sectorsPerTrack, sidesStored, startingTrack, endingTrack)

	const sides = sidesStored + 1
	const bytesPerTrack = SECTOR_SIZE * sectorsPerTrack
	const trackCount = endingTrack - startingTrack + 1
	const out = new Uint8Array(trackCount * sides * bytesPerTrack)

	let inPtr = MSA_HEADER_SIZE
	let outPtr = 0

	for (let track = startingTrack; track <= endingTrack; track++) {
		for (let side = 0; side < sides; side++) {
			const label = `track ${track} side ${side}`

			if (inPtr + 2 > data.length) {
				throw new Error(`MSA: premature EOF reading ${label} length`)
			}
			const dataLength = readU16BE(data, inPtr)
			inPtr += 2

			if (dataLength === bytesPerTrack) {
				out.set(sliceStrict(data, inPtr, dataLength, label), outPtr)
				inPtr += dataLength
				outPtr += bytesPerTrack
				continue
			}

			inPtr = decodeMsaTrack(
				data, inPtr, dataLength,
				out, outPtr, bytesPerTrack,
				label,
			)
			outPtr += bytesPerTrack
		}
	}

	return {
		geometry: { sectorsPerTrack, sides, startingTrack, endingTrack },
		raw: out,
	}
}

function validateMsaHeader(
	spt: number, sides: number, start: number, end: number,
): void {
	if (spt === 0 || spt > 56) {
		throw new Error(`MSA: implausible sectors-per-track ${spt}`)
	}
	if (sides > 1) {
		throw new Error(`MSA: implausible sides field ${sides} (must be 0 or 1)`)
	}
	if (end > 86) {
		throw new Error(`MSA: implausible ending track ${end}`)
	}
	if (start > end) {
		throw new Error(`MSA: starting track ${start} > ending track ${end}`)
	}
}

/**
 * Decode one RLE-compressed track. Reads compressed bytes from `data` starting
 * at `inPtr`, writes raw bytes to `out` at `outPtr`. Bounded by `dataLength`
 * — if the encoder wrote a shorter stream, we trust that and bound the input
 * accordingly. Returns the new input pointer (after all consumed bytes).
 */
function decodeMsaTrack(
	data: Uint8Array, inPtr: number, dataLength: number,
	out: Uint8Array, outPtr: number, bytesPerTrack: number,
	label: string,
): number {
	const inEnd = inPtr + dataLength
	let written = 0
	let ip = inPtr
	let op = outPtr

	while (written < bytesPerTrack) {
		if (ip >= inEnd) {
			throw new Error(`MSA: premature EOF in RLE stream (${label})`)
		}
		const b = data[ip++]
		if (b !== MSA_RLE_MARKER) {
			out[op++] = b
			written++
			continue
		}

		if (ip + 3 > inEnd) {
			throw new Error(`MSA: premature EOF reading RLE run (${label})`)
		}
		const value = data[ip++]
		const runLength = readU16BE(data, ip)
		ip += 2

		// Cap to track boundary (per Hatari) — corrupt images can overflow.
		const actual = Math.min(runLength, bytesPerTrack - written)
		out.fill(value, op, op + actual)
		op += actual
		written += actual
	}

	return ip
}

/** sliceBytes that throws with a contextual label on out-of-bounds. */
function sliceStrict(data: Uint8Array, offset: number, length: number, label: string): Uint8Array {
	if (offset + length > data.length) {
		throw new Error(`MSA: premature EOF reading uncompressed ${label}`)
	}
	return data.subarray(offset, offset + length)
}
