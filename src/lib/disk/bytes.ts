// Byte-reading helpers for parsing little-endian disk data (FAT12) and
// big-endian headers (MSA). Throws RangeError on out-of-bounds reads so
// upstream code can distinguish "premature EOF" from "bad data".

function assertRange(bytes: Uint8Array, offset: number, needed: number, op: string): void {
	if (offset < 0 || offset + needed > bytes.length) {
		throw new RangeError(
			`${op}: need ${needed} byte(s) at offset ${offset}, have ${bytes.length}`,
		)
	}
}

export function readU8(bytes: Uint8Array, offset: number): number {
	assertRange(bytes, offset, 1, 'readU8')
	return bytes[offset]
}

/** Little-endian 16-bit. Used by FAT12 BPB and directory entries. */
export function readU16LE(bytes: Uint8Array, offset: number): number {
	assertRange(bytes, offset, 2, 'readU16LE')
	return bytes[offset] | (bytes[offset + 1] << 8)
}

/** Little-endian 32-bit. Used for file sizes. `>>> 0` keeps it unsigned. */
export function readU32LE(bytes: Uint8Array, offset: number): number {
	assertRange(bytes, offset, 4, 'readU32LE')
	return (
		(bytes[offset])
		| (bytes[offset + 1] << 8)
		| (bytes[offset + 2] << 16)
		| (bytes[offset + 3] << 24)
	) >>> 0
}

/** Big-endian 16-bit. Used by the MSA header. */
export function readU16BE(bytes: Uint8Array, offset: number): number {
	assertRange(bytes, offset, 2, 'readU16BE')
	return (bytes[offset] << 8) | bytes[offset + 1]
}

/** Bytes [offset, offset+length) as a fresh copy (caller owns the result). */
export function sliceBytes(bytes: Uint8Array, offset: number, length: number): Uint8Array {
	assertRange(bytes, offset, length, 'sliceBytes')
	return bytes.slice(offset, offset + length)
}

/** Latin-1 string of [offset, offset+length) — preserves byte values 1:1. */
export function readLatin1(bytes: Uint8Array, offset: number, length: number): string {
	assertRange(bytes, offset, length, 'readLatin1')
	let out = ''
	for (let i = 0; i < length; i++) {
		out += String.fromCharCode(bytes[offset + i])
	}
	return out
}
