import { describe, it, expect } from 'vitest'
import { Fat12Image } from './fat12'

const SECTOR = 512
const ATTR_DIR = 0x10
const ATTR_ARCHIVE = 0x20

/**
 * Build a tiny FAT12 image whose subdirectory spans two *non-contiguous*
 * clusters, with junk "file data" sitting in the cluster between them.
 *
 * This reproduces the D-Bug Menu Disk 026 failure mode: a walker that
 * scans linearly from the subdirectory's first cluster bleeds into the
 * neighbouring junk and invents garbage filenames with multi-GB sizes.
 */
function buildNonContiguousSubdirImage(): Uint8Array {
	// Geometry chosen so BPB math is simple:
	//   1 reserved + 1 FAT (1 sector) + root (1 sector, 16 entries) + data
	//   sectorsPerCluster = 1, so cluster N lives at firstDataSector+(N-2)
	const reserved = 1
	const numFats = 1
	const sectorsPerFat = 1
	const rootEntries = 16
	const rootDirSectors = 1
	const sectorsPerCluster = 1
	const firstDataSector = reserved + numFats * sectorsPerFat + rootDirSectors // 3
	// Need clusters 2..6 at least: dir first, junk, dir second, plus room
	const totalSectors = firstDataSector + 8
	const raw = new Uint8Array(totalSectors * SECTOR)

	// Boot / BPB
	raw[0] = 0xEB; raw[1] = 0x3C; raw[2] = 0x90
	raw[0x0B] = SECTOR & 0xff; raw[0x0C] = (SECTOR >> 8) & 0xff
	raw[0x0D] = sectorsPerCluster
	raw[0x0E] = reserved; raw[0x0F] = 0
	raw[0x10] = numFats
	raw[0x11] = rootEntries; raw[0x12] = 0
	raw[0x13] = totalSectors & 0xff; raw[0x14] = (totalSectors >> 8) & 0xff
	raw[0x15] = 0xF9
	raw[0x16] = sectorsPerFat; raw[0x17] = 0
	raw[0x18] = 9; raw[0x19] = 0
	raw[0x1A] = 2; raw[0x1B] = 0

	// FAT12: media + EOC for first entry pair, then chain 2→4→EOC.
	// Cluster index:  0 (media)  1 (EOC)  2 (→4)  3 (junk EOC)  4 (EOC)
	const fat = raw.subarray(reserved * SECTOR, (reserved + sectorsPerFat) * SECTOR)
	// entries 0+1: F9 FF FF  (media F9, EOC FFF packed)
	fat[0] = 0xF9; fat[1] = 0xFF; fat[2] = 0xFF
	// entries 2+3: cluster2=0x004, cluster3=0xFFF → bytes at offset 2+1=3
	// offset for cluster 2 = 2+1 = 3
	writeFat12(fat, 2, 0x004) // 2 → 4
	writeFat12(fat, 3, 0xFFF) // junk cluster, end
	writeFat12(fat, 4, 0xFFF) // second dir cluster, end
	writeFat12(fat, 5, 0xFFF) // FIRST.TXT payload
	writeFat12(fat, 6, 0xFFF) // SECOND.TXT payload

	// Root directory: one subdirectory "SUB" starting at cluster 2
	const rootOff = (reserved + numFats * sectorsPerFat) * SECTOR
	writeDirEntry(raw, rootOff, 'SUB', '', ATTR_DIR, 2, 0)

	// Cluster 2 (sector firstDataSector+0): first half of SUB
	const c2 = (firstDataSector + 0) * SECTOR
	writeDirEntry(raw, c2, '.', '', ATTR_DIR, 2, 0)
	writeDirEntry(raw, c2 + 32, '..', '', ATTR_DIR, 0, 0)
	writeDirEntry(raw, c2 + 64, 'FIRST', 'TXT', ATTR_ARCHIVE, 5, 11)
	// Fill rest of cluster with non-zero so a linear reader won't see DIR_FREE
	raw.fill(0x5A, c2 + 96, c2 + SECTOR)

	// Cluster 3 (between dir clusters): junk that looks like a dir entry with
	// a huge size if mis-read as a directory.
	const c3 = (firstDataSector + 1) * SECTOR
	raw.fill(0x41, c3, c3 + SECTOR) // 'A's — would parse as a wild name
	raw[c3 + 11] = ATTR_ARCHIVE
	raw[c3 + 0x1C] = 0xFF; raw[c3 + 0x1D] = 0xFF
	raw[c3 + 0x1E] = 0xFF; raw[c3 + 0x1F] = 0x7F // ~2GB size

	// Cluster 4: second half of SUB
	const c4 = (firstDataSector + 2) * SECTOR
	writeDirEntry(raw, c4, 'SECOND', 'TXT', ATTR_ARCHIVE, 6, 12)
	// trailing zeros = end of directory

	// Clusters 5 and 6: tiny file payloads for FIRST.TXT / SECOND.TXT
	const hello = new TextEncoder().encode('hello world')
	raw.set(hello, (firstDataSector + 3) * SECTOR)
	const second = new TextEncoder().encode('second file!')
	raw.set(second, (firstDataSector + 4) * SECTOR)

	return raw
}

function writeFat12(fat: Uint8Array, cluster: number, value: number): void {
	const offset = cluster + (cluster >> 1)
	if ((cluster & 1) === 0) {
		fat[offset] = value & 0xFF
		fat[offset + 1] = (fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F)
	} else {
		fat[offset] = (fat[offset] & 0x0F) | ((value & 0x0F) << 4)
		fat[offset + 1] = (value >> 4) & 0xFF
	}
}

function writeDirEntry(
	raw: Uint8Array,
	offset: number,
	name: string,
	ext: string,
	attr: number,
	cluster: number,
	size: number,
): void {
	raw.fill(0x20, offset, offset + 11)
	for (let i = 0; i < name.length && i < 8; i++) raw[offset + i] = name.charCodeAt(i)
	for (let i = 0; i < ext.length && i < 3; i++) raw[offset + 8 + i] = ext.charCodeAt(i)
	raw[offset + 0x0B] = attr
	raw[offset + 0x1A] = cluster & 0xff
	raw[offset + 0x1B] = (cluster >> 8) & 0xff
	raw[offset + 0x1C] = size & 0xff
	raw[offset + 0x1D] = (size >> 8) & 0xff
	raw[offset + 0x1E] = (size >> 16) & 0xff
	raw[offset + 0x1F] = (size >> 24) & 0xff
}

describe('Fat12Image — non-contiguous subdirectory clusters', () => {
	it('lists only the real files, not the junk between directory clusters', () => {
		const img = new Fat12Image(buildNonContiguousSubdirImage())
		const files = img.listFiles().map(f => f.path).sort()

		expect(files).toEqual(['/SUB/FIRST.TXT', '/SUB/SECOND.TXT'])
	})

	it('can read file contents from both halves of the split directory', () => {
		const img = new Fat12Image(buildNonContiguousSubdirImage())
		const first = img.findFile('/SUB/FIRST.TXT')!
		const second = img.findFile('/SUB/SECOND.TXT')!

		expect(Buffer.from(img.readFile(first.entry)).toString()).toBe('hello world')
		expect(Buffer.from(img.readFile(second.entry)).toString()).toBe('second file!')
	})

	it('does not invent multi-gigabyte garbage entries from the interstitial cluster', () => {
		const img = new Fat12Image(buildNonContiguousSubdirImage())
		const huge = img.listFiles().filter(f => f.entry.size > 1_000_000)
		expect(huge).toEqual([])
	})
})
