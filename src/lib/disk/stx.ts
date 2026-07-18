import { readU8, readU16LE, readU32LE } from './bytes'

/**
 * Pasti / STX disk-image decoder.
 *
 * STX preserves copy-protected Atari ST floppies. For DiskCheck we only need
 * the *logical* sector payload — enough to feed Fat12Image and the boot-sector
 * scanner. Timing, fuzzy-bit masks, and raw track images are parsed just far
 * enough to locate each sector's bytes, then discarded.
 *
 * Spec sources:
 *   - Jean Louis-Guérin, "Pasti File Documentation" v0.5 (info-coach.fr)
 *   - Markus Fritze / P. Putnik reverse-engineering write-ups
 *
 * Endianness: every multi-byte field is little-endian (unusual for Atari
 * formats — STX was designed on the PC side of the imaging toolchain).
 */

/** File magic: ASCII "RSY" + NUL. */
export const STX_MAGIC = 0x00595352 // 'R','S','Y',0 as LE u32 — also check bytes

const SECTOR_SIZE = 512

/** Track-descriptor flags (trackFlags bitfield). */
const TRK_SECT  = 0x01 // sector descriptors present
const TRK_IMAGE = 0x40 // track image present
const TRK_SYNC  = 0x80 // track-image header includes sync offset

/** FDC / custom flags on a sector descriptor. */
const FDC_RNF = 0x10 // record not found — no data block

export interface StxGeometry {
	/** Highest cylinder number seen + 1 (typically 80). */
	tracks: number
	/** 1 or 2. */
	sides: number
	/** Sectors per track inferred from the fullest track (typically 9 or 10). */
	sectorsPerTrack: number
}

export interface StxImage {
	geometry: StxGeometry
	/** Raw sector data, layout identical to a `.st` image (interleaved sides). */
	raw: Uint8Array
}

function isStxMagic(bytes: Uint8Array): boolean {
	return bytes.length >= 4
		&& bytes[0] === 0x52 // 'R'
		&& bytes[1] === 0x53 // 'S'
		&& bytes[2] === 0x59 // 'Y'
		&& bytes[3] === 0x00
}

export function isStx(bytes: Uint8Array): boolean {
	return isStxMagic(bytes)
}

/**
 * Decode a `.stx` (Pasti) disk image into raw sector bytes — the same layout
 * as a `.st` file. Only standard 512-byte sectors are emitted; oversized or
 * missing (RNF) sectors are skipped / zero-filled so the FAT12 layer still
 * sees a contiguous image.
 */
export function decodeStx(data: Uint8Array): StxImage {
	if (data.length < 16) {
		throw new Error(`STX: file too short (${data.length} bytes; need at least 16)`)
	}
	if (!isStxMagic(data)) {
		throw new Error('STX: bad magic (expected "RSY\\0")')
	}

	const version = readU16LE(data, 4)
	if (version !== 3) {
		throw new Error(`STX: unsupported version ${version} (only v3 is documented)`)
	}

	const trackCount = readU8(data, 0x0a)
	if (trackCount === 0) {
		throw new Error('STX: trackCount is 0')
	}

	// Collect sectors keyed by "side:cyl:sector" as we walk the file. We don't
	// know geometry up front — infer it from the address fields we see.
	const sectors = new Map<string, Uint8Array>()
	let maxCyl = -1
	let maxSide = 0
	let maxSec = 0

	let pos = 16
	for (let t = 0; t < trackCount; t++) {
		if (pos + 16 > data.length) {
			throw new Error(`STX: truncated track header at offset ${pos}`)
		}

		const recordSize  = readU32LE(data, pos)
		const fuzzyCount  = readU32LE(data, pos + 4)
		const sectorCount = readU16LE(data, pos + 8)
		const trackFlags  = readU16LE(data, pos + 10)
		// trackLength at +12 unused for logical extraction
		const trackNumber = readU8(data, pos + 14)
		// trackType at +15 unused

		const recordEnd = pos + recordSize
		if (recordEnd > data.length) {
			throw new Error(
				`STX: track ${t} record extends past EOF ` +
				`(${recordSize} bytes from ${pos}, file is ${data.length})`,
			)
		}

		const headerSide = (trackNumber >> 7) & 1
		const headerCyl  = trackNumber & 0x7f
		if (headerCyl > maxCyl) maxCyl = headerCyl
		if (headerSide > maxSide) maxSide = headerSide

		pos += 16

		if ((trackFlags & TRK_SECT) === 0) {
			// Simple / unprotected: sectorCount contiguous 512-byte blocks,
			// numbered 1..n on this side/cylinder.
			for (let s = 1; s <= sectorCount; s++) {
				if (pos + SECTOR_SIZE > recordEnd) {
					throw new Error(`STX: truncated simple sector ${s} on track ${headerCyl} side ${headerSide}`)
				}
				const bytes = data.slice(pos, pos + SECTOR_SIZE)
				pos += SECTOR_SIZE
				sectors.set(key(headerSide, headerCyl, s), bytes)
				if (s > maxSec) maxSec = s
			}
		} else {
			// Sector descriptors present.
			type SecDesc = {
				dataOffset: number
				number: number
				sizeCode: number
				fdcFlags: number
				addrTrack: number
				addrHead: number
			}
			const descs: SecDesc[] = []
			for (let s = 0; s < sectorCount; s++) {
				if (pos + 16 > recordEnd) {
					throw new Error(`STX: truncated sector descriptor ${s} on track ${t}`)
				}
				descs.push({
					dataOffset: readU32LE(data, pos),
					addrTrack:  readU8(data, pos + 8),
					addrHead:   readU8(data, pos + 9),
					number:     readU8(data, pos + 10),
					sizeCode:   readU8(data, pos + 11),
					fdcFlags:   readU8(data, pos + 14),
				})
				pos += 16
			}

			// Optional fuzzy mask — skip (we don't emulate fuzzy bits).
			if (fuzzyCount > 0) {
				if (pos + fuzzyCount > recordEnd) {
					throw new Error(`STX: fuzzy mask overflows track ${t}`)
				}
				pos += fuzzyCount
			}

			const trackDataStart = pos
			let imageSize = 0

			if (trackFlags & TRK_IMAGE) {
				if (trackFlags & TRK_SYNC) {
					if (pos + 4 > recordEnd) throw new Error(`STX: truncated sync header on track ${t}`)
					pos += 2 // FirstSyncOffset — unused for logical extract
					imageSize = readU16LE(data, pos)
					pos += 2
				} else {
					if (pos + 2 > recordEnd) throw new Error(`STX: truncated image header on track ${t}`)
					imageSize = readU16LE(data, pos)
					pos += 2
				}
				if (pos + imageSize > recordEnd) {
					throw new Error(`STX: track image overflows track ${t}`)
				}
				// Sector dataOffset is relative to trackDataStart (which is the
				// start of the image header). Leave pos at end of image so any
				// trailing sector-image payloads that follow stay reachable via
				// absolute offset from trackDataStart.
				pos = trackDataStart + (trackFlags & TRK_SYNC ? 4 : 2) + imageSize
			}

			for (const desc of descs) {
				if (desc.fdcFlags & FDC_RNF) continue // address-only, no data
				const secSize = 128 << desc.sizeCode
				if (secSize !== SECTOR_SIZE) {
					// Non-standard sizes aren't useful for FAT12; skip.
					continue
				}
				const abs = trackDataStart + desc.dataOffset
				if (abs + secSize > recordEnd) {
					throw new Error(
						`STX: sector ${desc.number} data at ${abs} overflows track ${t}`,
					)
				}
				const bytes = data.slice(abs, abs + secSize)

				// Prefer the address-block side/track when present; fall back
				// to the track-header encoding (custom protections sometimes
				// lie in the address field).
				const side = desc.addrHead <= 1 ? desc.addrHead : headerSide
				const cyl  = desc.addrTrack <= 85 ? desc.addrTrack : headerCyl
				sectors.set(key(side, cyl, desc.number), bytes)
				if (cyl > maxCyl) maxCyl = cyl
				if (side > maxSide) maxSide = side
				if (desc.number > maxSec) maxSec = desc.number
			}
		}

		// Always advance to the next record by recordSize (handles padding).
		pos = recordEnd
	}

	if (maxCyl < 0 || maxSec === 0) {
		throw new Error('STX: no readable 512-byte sectors found')
	}

	const tracks = maxCyl + 1
	const sides = maxSide + 1
	const sectorsPerTrack = maxSec
	const raw = new Uint8Array(tracks * sides * sectorsPerTrack * SECTOR_SIZE)

	// Interleaved layout matching .st / MSA: for each cylinder, side 0 then
	// side 1, sectors 1..SPT in order.
	for (let cyl = 0; cyl < tracks; cyl++) {
		for (let side = 0; side < sides; side++) {
			for (let sec = 1; sec <= sectorsPerTrack; sec++) {
				const bytes = sectors.get(key(side, cyl, sec))
				if (!bytes) continue // leave zeros for missing sectors
				const off =
					((cyl * sides + side) * sectorsPerTrack + (sec - 1)) * SECTOR_SIZE
				raw.set(bytes, off)
			}
		}
	}

	return {
		geometry: { tracks, sides, sectorsPerTrack },
		raw,
	}
}

function key(side: number, cyl: number, sector: number): string {
	return `${side}:${cyl}:${sector}`
}
