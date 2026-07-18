import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { openDiskImage } from './diskImage'
import { decodeMsa } from './msa'
import { readU16LE } from './bytes'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '__fixtures__')

/**
 * Regression test for the Adarod v2.0 cover disk, a real-world Atari ST
 * MSA whose BPB reports `reservedSectors = 0` and a media descriptor of 0.
 *
 * TOS silently treats the disk as having the standard FAT12 layout (one
 * reserved sector for the boot sector). Without that fallback our walker
 * placed FAT1 at sector 0 — colliding with the boot sector — and the
 * root directory became unreadable, so listFiles() returned 0 entries
 * and the Text Renderer showed an empty file list.
 *
 * This fixture is checked in at __fixtures__/adarod.msa.
 */
describe('Adarod v2.0.msa — regression: BPB with reservedSectors=0', () => {
	function load() {
		const buf = readFileSync(join(fixturesDir, 'adarod.msa'))
		return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
	}

	it('the BPB really does claim reservedSectors=0 (we have not "fixed" the fixture)', () => {
		const decoded = decodeMsa(load())
		expect(readU16LE(decoded.raw, 0x0E)).toBe(0)
	})

	it('decodes without error and reports a single-sided 80-track disk', () => {
		const decoded = decodeMsa(load())
		expect(decoded.geometry).toEqual({
			sectorsPerTrack: 9,
			sides: 1,
			startingTrack: 0,
			endingTrack: 79,
		})
		expect(decoded.raw.length).toBe(80 * 9 * 512)
	})

	it('lists files in the disk image (was returning 0 before the fix)', () => {
		const opened = openDiskImage(load())
		const files = opened.image.listFiles()
		expect(files.length).toBeGreaterThan(0)

		// The first root-directory entry is the "ADAROD" volume / directory
		// name (we saw this in the manual hex dump when diagnosing the bug).
		const allPaths = files.map(f => f.path)
		expect(allPaths.some(p => p.toUpperCase().includes('ADAROD'))).toBe(true)
	})

	it('can read at least one file end-to-end without throwing', () => {
		const opened = openDiskImage(load())
		const first = opened.image.listFiles()[0]
		const bytes = opened.image.readFile(first.entry)
		expect(bytes.length).toBe(first.entry.size)
	})
})
