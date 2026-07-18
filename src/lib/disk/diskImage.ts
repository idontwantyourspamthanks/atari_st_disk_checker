import { Fat12Image } from './fat12'
import { decodeMsa, MSA_MAGIC } from './msa'
import { decodeStx, isStx } from './stx'
import { readU16BE } from './bytes'

export type DiskFormat = 'st' | 'msa' | 'stx'

export interface OpenedImage {
	format: DiskFormat
	image: Fat12Image
}

/**
 * Detect the disk-image format of a byte buffer and open it as a FAT12Image.
 *
 * Detection order:
 *   1. STX — magic `RSY\0`
 *   2. MSA — big-endian magic `0x0E0F`
 *   3. anything else → raw `.st` sector dump
 *
 * We don't insist on a PC-style `0x55 0xAA` signature at offset 0x1FE because
 * Atari ST boot sectors are not required to have one — many real ST images
 * omit it.
 */
export function openDiskImage(bytes: Uint8Array): OpenedImage {
	const format = detectFormat(bytes)
	let raw: Uint8Array
	if (format === 'stx') raw = decodeStx(bytes).raw
	else if (format === 'msa') raw = decodeMsa(bytes).raw
	else raw = bytes
	return { format, image: new Fat12Image(raw) }
}

export function detectFormat(bytes: Uint8Array): DiskFormat {
	if (isStx(bytes)) return 'stx'
	if (bytes.length >= 2 && readU16BE(bytes, 0) === MSA_MAGIC) return 'msa'
	return 'st'
}
