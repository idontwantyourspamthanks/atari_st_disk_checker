import { describe, it, expect } from 'vitest'
import { zipSync } from 'fflate'
import { extractDiskImagesFromZip } from './zip'
import { buildExecutableBootSector } from './bootSector.spec'

function makeZip(files: Record<string, Uint8Array>): Uint8Array {
	// fflate wants a plain object of { path: Uint8Array }.
	const tree: Record<string, Uint8Array> = {}
	for (const [name, bytes] of Object.entries(files)) {
		tree[name] = bytes
	}
	const zipped = zipSync(tree)
	return zipped
}

describe('extractDiskImagesFromZip', () => {
	it('returns .st, .msa and .stx entries and skips everything else', () => {
		const boot = buildExecutableBootSector('PENTAGON')
		const zip = makeZip({
			'clean.st':       new Uint8Array(512),
			'virus.msa':      boot,
			'pd.stx':         new Uint8Array([0x52, 0x53, 0x59, 0x00]),
			'README.txt':     new Uint8Array([0x48, 0x49]),
			'screenshot.png': new Uint8Array([0x89, 0x50, 0x4E, 0x47]),
		})

		const result = extractDiskImagesFromZip(zip)

		expect(result.error).toBeUndefined()
		expect(result.entries.map(e => e.name)).toEqual(['clean.st', 'pd.stx', 'virus.msa'])
		expect(result.skipped).toEqual(['README.txt', 'screenshot.png'])
	})

	it('sorts entries alphabetically by name', () => {
		const zip = makeZip({
			'zeta.st':   new Uint8Array(512),
			'alpha.st':  new Uint8Array(512),
			'mid.st':    new Uint8Array(512),
		})
		const names = extractDiskImagesFromZip(zip).entries.map(e => e.name)
		expect(names).toEqual(['alpha.st', 'mid.st', 'zeta.st'])
	})

	it('handles nested directory paths inside the archive', () => {
		const zip = makeZip({
			'disks/clean.st': new Uint8Array(512),
			'disks/sub/v.st': new Uint8Array(512),
		})
		const names = extractDiskImagesFromZip(zip).entries.map(e => e.name)
		expect(names).toEqual(['disks/clean.st', 'disks/sub/v.st'])
	})

	it('ignores macOS metadata files and directory markers', () => {
		const zip = makeZip({
			'foo.st':                new Uint8Array(512),
			'__MACOSX/foo.st':       new Uint8Array(64),
			'__MACOSX/._foo.st':     new Uint8Array(64),
			'disks/':                new Uint8Array(0),
		})
		const result = extractDiskImagesFromZip(zip)
		expect(result.entries.map(e => e.name)).toEqual(['foo.st'])
		// The metadata and directory marker should land in `skipped`.
		expect(result.skipped.length).toBeGreaterThan(0)
	})

	it('returns an error rather than throwing when the input is not a ZIP', () => {
		const result = extractDiskImagesFromZip(new Uint8Array([0x00, 0x01, 0x02]))
		expect(result.entries).toEqual([])
		expect(result.error).toBeDefined()
	})

	it('returns empty entries (no error) for a valid ZIP with no disk images', () => {
		const zip = makeZip({ 'notes.txt': new Uint8Array([0x41]) })
		const result = extractDiskImagesFromZip(zip)
		expect(result.entries).toEqual([])
		expect(result.skipped).toEqual(['notes.txt'])
		expect(result.error).toBeUndefined()
	})
})
