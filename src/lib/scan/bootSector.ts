import { readU16BE, readU8, readU16LE } from '../disk/bytes'
import { decodeMsa, MSA_MAGIC } from '../disk/msa'
import { decodeStx, isStx } from '../disk/stx'

export const BOOT_SECTOR_SIZE = 512
export const ST_BOOT_SECTOR_EXE_SUM = 0x1234

/**
 * First byte of common 68000 entry instructions at boot-sector offset 0.
 * TOS JSRs to offset 0 when the checksum is 0x1234, so live boot code
 * (and boot viruses) almost always start with one of these:
 *
 *   0x60–0x6F  Bcc.S / BRA.S — jump over the BPB. BRA (0x60) is normal;
 *              Ghost H deliberately uses BLS (0x6F) to evade scanners that
 *              only looked for BRA. Treat the whole conditional-branch
 *              range as entry code.
 *   0x4E       JMP / JSR / NOP / RTE family (e.g. Joe's 0x4E71 NOP)
 *   0x46       MOVE to SR / USP (classic "move #$2700,sr" boot stubs)
 *   0x48       MOVEM
 *   0x0C       CMPI
 *
 * Deliberately NOT included: 0x00 (ORI / padding). A data disk often has
 * zeros at offset 0; calling that "68000 entry code" was a false signal.
 */
const ENTRY_OPCODE_HIGH_BYTES: ReadonlyArray<number> = [
	0x4E, 0x46, 0x48, 0x0C,
]

/** First byte of the post-BPB region on Atari ST (BPB ends at 0x1D). */
export const BOOT_CODE_REGION_START = 0x1E

/** Last exclusive offset of payload before the checksum tuning word. */
export const BOOT_CODE_REGION_END = 0x1FE

/**
 * Detect whether `input` is an MSA or STX image, decode it if so, and return
 * the raw sector bytes (identical to a `.st` image either way).
 *
 * Exposed publicly so tests (and future tooling) can ask "what does this
 * image look like as raw sectors?" without re-implementing format detection.
 */
export function getImageBytes(input: Uint8Array): Uint8Array {
	if (isStx(input)) return decodeStx(input).raw
	if (input.length >= 2 && readU16BE(input, 0) === MSA_MAGIC) {
		return decodeMsa(input).raw
	}
	return input
}

/** The first 512 bytes of the image — the boot sector TOS reads on insert. */
export function getBootSector(input: Uint8Array): Uint8Array {
	const image = getImageBytes(input)
	if (image.length < BOOT_SECTOR_SIZE) {
		throw new Error(
			`Image too short to contain a boot sector (${image.length} bytes; need ${BOOT_SECTOR_SIZE})`,
		)
	}
	return image.subarray(0, BOOT_SECTOR_SIZE)
}

/**
 * Compute the Atari ST boot-sector checksum: the 16-bit sum of all 256
 * big-endian words in sector 0. TOS considers the sector executable when
 * this equals `ST_BOOT_SECTOR_EXE_SUM` (`0x1234`).
 *
 * Matches Hatari's `Floppy_IsBootSectorExecutable` in `floppy.c`.
 */
export function bootSectorChecksum(boot: Uint8Array): number {
	if (boot.length < BOOT_SECTOR_SIZE) {
		throw new Error(`Boot sector must be 512 bytes (got ${boot.length})`)
	}
	let sum = 0
	for (let i = 0; i < 256; i++) {
		const word = (boot[i * 2] << 8) | boot[i * 2 + 1]
		sum = (sum + word) & 0xFFFF
	}
	return sum
}

/** True when TOS would treat the boot sector as executable. */
export function isBootSectorExecutable(boot: Uint8Array): boolean {
	return bootSectorChecksum(boot) === ST_BOOT_SECTOR_EXE_SUM
}

/**
 * True when the first byte of the boot sector looks like a common 68000
 * entry opcode used by boot loaders and boot-sector viruses.
 */
export function startsWith68000Opcode(boot: Uint8Array): boolean {
	const firstByte = readU8(boot, 0)
	// Short conditional branches / BRA: 0x60–0x6F
	if (firstByte >= 0x60 && firstByte <= 0x6F) return true
	return ENTRY_OPCODE_HIGH_BYTES.includes(firstByte)
}

/**
 * Non-zero bytes in the post-BPB payload region [0x1E, 0x1FE).
 *
 * Atari's BPB ends at 0x1D; viral and custom boot code commonly begins at
 * 0x1E (after a BRA.B $1C). The official TOS loader params live at
 * 0x1E–0x39 with code at 0x3A+, but counting only from the DOS-ish 0x3E
 * under-counted compact viruses that live entirely in 0x1E–0x3D.
 */
export function countNonZeroBytesBeyondBpb(boot: Uint8Array): number {
	let count = 0
	for (let i = BOOT_CODE_REGION_START; i < BOOT_CODE_REGION_END; i++) {
		if (boot[i] !== 0) count++
	}
	return count
}

/**
 * Sane media-descriptor values for the byte at offset 0x15 in a FAT12 boot
 * sector. mtools writes 0xF9 for its 720 KB images; real ST floppies most
 * often use 0xFD (DSDD) or 0xF9 (DSHD). Anything outside this set is not
 * necessarily a virus, but it's a flag worth surfacing.
 */
const KNOWN_MEDIA_DESCRIPTORS = new Set([0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])

/** Read the media descriptor byte (BPB offset 0x15). */
export function mediaDescriptor(boot: Uint8Array): number {
	return readU8(boot, 0x15)
}

/** True if the media descriptor is one of the standard FAT12 values. */
export function hasSaneMediaDescriptor(boot: Uint8Array): boolean {
	return KNOWN_MEDIA_DESCRIPTORS.has(mediaDescriptor(boot))
}

/** True if the BPB's geometry looks plausible (non-zero, reasonable bounds). */
export function hasSaneGeometry(boot: Uint8Array): boolean {
	const bytesPerSector = readU16LE(boot, 0x0B)
	const sectorsPerCluster = readU8(boot, 0x0D)
	const sectorsPerFat = readU16LE(boot, 0x16)
	if (bytesPerSector !== 512) return false
	if (sectorsPerCluster === 0 || sectorsPerCluster > 128) return false
	if (sectorsPerFat === 0 || sectorsPerFat > 64) return false
	return true
}
