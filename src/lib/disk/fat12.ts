import { readU8, readU16LE, readU32LE, sliceBytes } from './bytes'

const SECTOR_SIZE = 512

// Directory entry attribute bits (offset 0x0B of a 32-byte entry).
const ATTR_READONLY   = 0x01
const ATTR_HIDDEN     = 0x02
const ATTR_SYSTEM     = 0x04
const ATTR_VOLUME_ID  = 0x08
const ATTR_DIRECTORY  = 0x10
const ATTR_ARCHIVE    = 0x20
const ATTR_LONG_NAME  = 0x0F  // = READONLY|HIDDEN|SYSTEM|VOLUME_ID combo

// FAT12 cluster-chain markers (12-bit values).
const FAT_BAD         = 0xFF7
const FAT_EOC_MIN     = 0xFF8 // end-of-chain: 0xFF8..0xFFF

const DIR_ENTRY_SIZE       = 32
const DIR_FREE             = 0x00 // never-used entry; ends directory scan
const DIR_DELETED          = 0xE5 // deleted entry; skip

/** Disk geometry parsed from the boot sector's BIOS Parameter Block. */
export interface DiskGeometry {
	bytesPerSector:    number
	sectorsPerCluster: number
	reservedSectors:   number
	numFats:           number
	rootEntries:       number
	totalSectors:      number
	sectorsPerFat:     number
	// Derived:
	rootDirStartSector: number  // first sector of the root directory region
	rootDirSectors:     number  // size of root directory region in sectors
	firstDataSector:    number  // first sector of cluster 2
	countOfClusters:    number
}

export interface DirectoryEntry {
	/** Display name with extension, e.g. "README.TXT" or "AUTO" (no dot for dirs). */
	name: string
	attributes:    number
	isReadOnly:    boolean
	isHidden:      boolean
	isSystem:      boolean
	isVolumeLabel: boolean
	isDirectory:   boolean
	isArchive:     boolean
	startingCluster: number
	/** File size in bytes. Always 0 for directories. */
	size: number
	modified: Date | null
}

export interface FileEntry {
	/** Full path from disk root, using "/" separators. Always starts with "/". */
	path: string
	entry: DirectoryEntry
}

/**
 * Read-only walker for a FAT12 disk image (raw sector bytes — what a `.st`
 * file is, and what `decodeMsa` produces from an `.msa` file). Used by the
 * ST TOS / GEMDOS filesystem, which is identical in layout to MS-DOS FAT12.
 *
 * The walker is deliberately tolerant of corrupt images: it tries to read
 * what it can, throws only on structural failures (bad BPB, out-of-bounds),
 * and silently skips individual malformed directory entries. This matters
 * for the virus-scanner use case, where we may want to enumerate files on
 * an image whose boot sector has been overwritten.
 *
 * Implementation fields and methods are kept non-private (with `_`
 * prefixes on the fields) so that Vue's prop-type extraction — which works
 * structurally — does not trip on nominal private-member matching. Treat
 * the underscore-prefixed members and the un-prefixed helpers below as
 * internal API.
 */
export class Fat12Image {
	readonly geometry: DiskGeometry
	readonly _raw: Uint8Array
	readonly _fat: Uint8Array

	constructor(raw: Uint8Array) {
		if (raw.length < SECTOR_SIZE) {
			throw new Error(`FAT12: image too short (${raw.length} bytes; need at least one sector)`)
		}
		this._raw = raw
		this.geometry = parseBootSector(raw)
		this._fat = this.readFat()
	}

	/** Recursively list every file (not directories) under "/". */
	listFiles(): FileEntry[] {
		const out: FileEntry[] = []
		this.walkDirectoryEntries(this.readRootDirectoryEntries(), '/', out)
		return out
	}

	/** Find a file by its full path. Returns null if not found. */
	findFile(path: string): FileEntry | null {
		const normalised = normalisePath(path)
		if (normalised === '/') return null
		return this.listFiles().find(f => f.path === normalised) ?? null
	}

	/** Read a file's contents by following its cluster chain. */
	readFile(entry: DirectoryEntry): Uint8Array {
		if (entry.isDirectory) {
			throw new Error(`FAT12: cannot read a directory as bytes (${entry.name})`)
		}
		if (entry.size === 0) return new Uint8Array(0)

		const out = new Uint8Array(entry.size)
		const clusterBytes = this.geometry.sectorsPerCluster * SECTOR_SIZE
		let cluster = entry.startingCluster
		let written = 0

		while (written < entry.size && this.isValidDataCluster(cluster)) {
			const data = this.readCluster(cluster)
			const chunk = Math.min(clusterBytes, entry.size - written)
			out.set(data.subarray(0, chunk), written)
			written += chunk
			cluster = this.nextCluster(cluster)
		}

		if (written < entry.size) {
			throw new Error(
				`FAT12: cluster chain ended prematurely reading ${entry.name} ` +
				`(${written}/${entry.size} bytes)`,
			)
		}
		return out
	}

	// ── Internal: filesystem structure ──────────────────────────────────────
	// Not prefixed with `_` because they're implementation helpers, not part
	// of the public API. Kept non-private so Vue's prop-type extraction (which
	// works structurally) doesn't trip on nominal private-member matching.

	readFat(): Uint8Array {
		const { reservedSectors, sectorsPerFat } = this.geometry
		const start = reservedSectors * SECTOR_SIZE
		const length = sectorsPerFat * SECTOR_SIZE
		return sliceBytes(this._raw, start, length)
	}

	readCluster(cluster: number): Uint8Array {
		const { firstDataSector, sectorsPerCluster } = this.geometry
		const sector = firstDataSector + (cluster - 2) * sectorsPerCluster
		const offset = sector * SECTOR_SIZE
		return sliceBytes(this._raw, offset, sectorsPerCluster * SECTOR_SIZE)
	}

	nextCluster(cluster: number): number {
		// FAT12 packs two 12-bit entries into three bytes. Entry N lives at
		// byte offset N + N/2 (= floor(N * 3 / 2)). The high nibble of the
		// shared byte belongs to the odd entry.
		const offset = cluster + (cluster >> 1)
		if (offset + 1 >= this._fat.length) {
			return FAT_EOC_MIN // treat out-of-range as end of chain
		}
		const b0 = this._fat[offset]
		const b1 = this._fat[offset + 1]
		const value = (cluster & 1) === 0
			? (b0 | ((b1 & 0x0F) << 8))
			: ((b0 >> 4) | (b1 << 4))
		return value & 0x0FFF
	}

	isValidDataCluster(cluster: number): boolean {
		return cluster >= 2 && cluster < FAT_BAD && cluster < this.geometry.countOfClusters + 2
	}

	// ── Internal: directories ───────────────────────────────────────────────

	/**
	 * Walk a list of directory entries, recursing into subdirectories.
	 * Subdirectory contents are read by following the FAT cluster chain —
	 * never by scanning linearly through the image from the first cluster.
	 * (Menu disks / demos often pack directories across non-contiguous
	 * clusters; linear reads bleed into neighbouring file data and produce
	 * garbage names with multi-gigabyte "sizes".)
	 */
	walkDirectoryEntries(entries: DirectoryEntry[], prefix: string, out: FileEntry[]): void {
		for (const entry of entries) {
			if (entry.isDirectory) {
				if (entry.name === '.' || entry.name === '..') continue
				if (!this.isValidDataCluster(entry.startingCluster)) continue
				const childPrefix = prefix === '/' ? `/${entry.name}` : `${prefix}/${entry.name}`
				const childEntries = this.readClusterDirectoryEntries(entry.startingCluster)
				this.walkDirectoryEntries(childEntries, childPrefix, out)
				continue
			}
			if (entry.isVolumeLabel) continue
			// Skip entries that can't possibly be real files — defence in depth
			// against residual corruption inside an otherwise valid directory.
			if (!this.isPlausibleFileEntry(entry)) continue
			const path = prefix === '/' ? `/${entry.name}` : `${prefix}/${entry.name}`
			out.push({ path, entry })
		}
	}

	/** Root directory: fixed sector range sized by the BPB's rootEntries. */
	readRootDirectoryEntries(): DirectoryEntry[] {
		const { rootDirStartSector, rootDirSectors, rootEntries } = this.geometry
		const start = rootDirStartSector * SECTOR_SIZE
		const length = Math.min(
			rootDirSectors * SECTOR_SIZE,
			rootEntries * DIR_ENTRY_SIZE,
		)
		if (start + length > this._raw.length) {
			return this.parseDirectoryBytes(
				this._raw.subarray(start, this._raw.length),
			)
		}
		return this.parseDirectoryBytes(sliceBytes(this._raw, start, length))
	}

	/**
	 * Subdirectory: concatenate every cluster in the chain, then parse.
	 * Caps the chain length so a corrupt FAT loop can't hang the walker.
	 */
	readClusterDirectoryEntries(startCluster: number): DirectoryEntry[] {
		const clusterBytes = this.geometry.sectorsPerCluster * SECTOR_SIZE
		const maxClusters = Math.max(1, this.geometry.countOfClusters)
		const chunks: Uint8Array[] = []
		let cluster = startCluster
		let seen = 0

		while (this.isValidDataCluster(cluster) && seen < maxClusters) {
			chunks.push(this.readCluster(cluster))
			seen++
			const next = this.nextCluster(cluster)
			if (next >= FAT_EOC_MIN) break
			if (next === cluster) break // defensive: self-loop
			cluster = next
		}

		if (chunks.length === 0) return []
		if (chunks.length === 1) return this.parseDirectoryBytes(chunks[0])

		const buf = new Uint8Array(chunks.length * clusterBytes)
		for (let i = 0; i < chunks.length; i++) {
			buf.set(chunks[i], i * clusterBytes)
		}
		return this.parseDirectoryBytes(buf)
	}

	parseDirectoryBytes(bytes: Uint8Array): DirectoryEntry[] {
		const out: DirectoryEntry[] = []
		const limit = Math.floor(bytes.length / DIR_ENTRY_SIZE)

		for (let i = 0; i < limit; i++) {
			const offset = i * DIR_ENTRY_SIZE
			const firstByte = bytes[offset]
			if (firstByte === DIR_FREE) break       // end of directory
			if (firstByte === DIR_DELETED) continue // deleted, skip

			const attr = bytes[offset + 0x0B]
			if ((attr & ATTR_LONG_NAME) === ATTR_LONG_NAME) continue // LFN slot

			out.push(parseDirectoryEntry(bytes.subarray(offset, offset + DIR_ENTRY_SIZE)))
		}
		return out
	}

	isPlausibleFileEntry(entry: DirectoryEntry): boolean {
		if (entry.size === 0) return true
		if (!this.isValidDataCluster(entry.startingCluster)) return false
		// A single file can't be larger than the data region of the disk.
		const maxBytes =
			this.geometry.countOfClusters *
			this.geometry.sectorsPerCluster *
			SECTOR_SIZE
		return entry.size <= maxBytes
	}
}

// ── Top-level parsing helpers ────────────────────────────────────────────────

function parseBootSector(raw: Uint8Array): DiskGeometry {
	const bytesPerSector    = readU16LE(raw, 0x0B)
	const sectorsPerCluster = readU8(raw, 0x0D)
	const reservedRaw       = readU16LE(raw, 0x0E)
	const numFats           = readU8(raw, 0x10)
	const rootEntries       = readU16LE(raw, 0x11)
	const totalSectors16    = readU16LE(raw, 0x13)
	const sectorsPerFat     = readU16LE(raw, 0x16)

	if (bytesPerSector !== SECTOR_SIZE) {
		throw new Error(`FAT12: unsupported bytes-per-sector ${bytesPerSector} (only 512 supported)`)
	}
	if (sectorsPerCluster === 0) {
		throw new Error('FAT12: invalid sectors-per-cluster 0')
	}

	// Atari ST quirk: many games / demos / cover disks were mastered with
	// a minimal or zero-filled boot sector whose BPB reports reservedSectors
	// as 0 (and sometimes a media descriptor of 0 too). TOS silently assumes
	// the standard layout — boot sector at sector 0, FAT immediately after.
	// We do the same: if the BPB claims 0 reserved sectors, treat it as 1.
	// Without this, the FAT overlaps the boot sector and the walker returns
	// zero files on otherwise perfectly readable disks.
	const reservedSectors = reservedRaw === 0 ? 1 : reservedRaw

	const totalSectors = totalSectors16 > 0
		? totalSectors16
		: readU32LE(raw, 0x20) // fall back to BPB32 field for larger images

	const rootDirSectors = Math.ceil((rootEntries * DIR_ENTRY_SIZE) / SECTOR_SIZE)
	const rootDirStartSector = reservedSectors + numFats * sectorsPerFat
	const firstDataSector = rootDirStartSector + rootDirSectors
	const dataSectors = totalSectors - firstDataSector
	const countOfClusters = Math.floor(dataSectors / sectorsPerCluster)

	return {
		bytesPerSector,
		sectorsPerCluster,
		reservedSectors,
		numFats,
		rootEntries,
		totalSectors,
		sectorsPerFat,
		rootDirStartSector,
		rootDirSectors,
		firstDataSector,
		countOfClusters,
	}
}

function parseDirectoryEntry(entry: Uint8Array): DirectoryEntry {
	const attr = readU8(entry, 0x0B)
	const startingCluster = readU16LE(entry, 0x1A)
	const size = readU32LE(entry, 0x1C)
	const name = parseShortName(entry)
	const modified = parseFatTimestamp(readU16LE(entry, 0x16), readU16LE(entry, 0x18))

	return {
		name,
		attributes: attr,
		isReadOnly:    (attr & ATTR_READONLY) !== 0,
		isHidden:      (attr & ATTR_HIDDEN) !== 0,
		isSystem:      (attr & ATTR_SYSTEM) !== 0,
		isVolumeLabel: (attr & ATTR_VOLUME_ID) !== 0,
		isDirectory:   (attr & ATTR_DIRECTORY) !== 0,
		isArchive:     (attr & ATTR_ARCHIVE) !== 0,
		startingCluster,
		size,
		modified,
	}
}

/**
 * Parse an 8.3 short name from raw bytes. The first 8 bytes are the basename
 * (space padded), the next 3 the extension. Trailing spaces trimmed. The
 * special name "." and ".." come through verbatim. Returns "BASENAME.EXT",
 * or "BASENAME" when there's no extension.
 */
export function parseShortName(entry: Uint8Array): string {
	// 0x05 in the first byte is a hack to mean "name really starts with 0xE5"
	// (the deleted-entry marker). Restore it without mutating the caller's
	// buffer — we read into a local first.
	const firstNameByte = entry[0] === 0x05 ? 0xE5 : entry[0]

	const base = latin1TrimmedWithFirst(entry.subarray(0, 8), firstNameByte)
	const ext  = latin1Trimmed(entry.subarray(8, 11))

	if (ext.length === 0) return base
	if (base === '.' || base === '..') return base
	return `${base}.${ext}`
}

function latin1Trimmed(bytes: Uint8Array): string {
	return latin1TrimmedWithFirst(bytes, bytes[0])
}

function latin1TrimmedWithFirst(bytes: Uint8Array, firstByte: number): string {
	let end = bytes.length
	while (end > 0 && bytes[end - 1] === 0x20) end--
	let out = ''
	for (let i = 0; i < end; i++) {
		out += String.fromCharCode(i === 0 ? firstByte : bytes[i])
	}
	return out
}

/**
 * FAT timestamps are packed 16-bit words: date = YYYYYYMM MMMDDDDD,
 * time = HHHHHMMM MMMSSSSS (seconds ÷ 2). Returns null if either field is 0.
 */
export function parseFatTimestamp(date: number, time: number): Date | null {
	if (date === 0 && time === 0) return null
	const year  = 1980 + ((date >> 9) & 0x7F)
	const month = Math.max(1, (date >> 5) & 0x0F)
	const day   = Math.max(1, date & 0x1F)
	const hours   = (time >> 11) & 0x1F
	const minutes = (time >> 5) & 0x3F
	const seconds = (time & 0x1F) * 2
	return new Date(year, month - 1, day, hours, minutes, seconds)
}

function normalisePath(path: string): string {
	if (!path.startsWith('/')) path = '/' + path
	// Collapse accidental double slashes; ignore trailing slash.
	return path.replace(/\/+/g, '/').replace(/\/$/, '')
}
