#!/usr/bin/env node
// Wrap sample.st in a minimal unprotected Pasti/STX container so the STX
// decoder can be round-tripped against the known mtools fixture.
//
// Output: src/lib/disk/__fixtures__/sample.stx
//
// Format used: simple tracks (trackFlags bit 0 clear) — contiguous 512-byte
// sector blocks numbered 1..9. This is the "unprotected" STX layout described
// in DrCoolZic's Pasti File Documentation §2.2.1.

import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'src', 'lib', 'disk', '__fixtures__')
const stPath = join(fixturesDir, 'sample.st')
const stxPath = join(fixturesDir, 'sample.stx')

const SECTOR_SIZE = 512
const SPT = 9
const SIDES = 2
const TRACKS = 80

const st = readFileSync(stPath)
const expected = TRACKS * SIDES * SPT * SECTOR_SIZE
if (st.length !== expected) {
	throw new Error(`sample.st is ${st.length} bytes; expected ${expected} (80×2×9×512)`)
}

const parts = []

// File descriptor (16 bytes, little-endian).
const header = Buffer.alloc(16)
header[0] = 0x52; header[1] = 0x53; header[2] = 0x59; header[3] = 0x00 // "RSY\0"
header.writeUInt16LE(3, 4)     // version
header.writeUInt16LE(0x01, 6)  // tool = Atari imaging tool
header.writeUInt16LE(0, 8)     // reserved
header[0x0a] = TRACKS * SIDES  // trackCount
header[0x0b] = 0               // revision
header.writeUInt32LE(0, 0x0c)  // reserved
parts.push(header)

// Tracks in interleaved order (cyl 0 side 0, cyl 0 side 1, …).
for (let cyl = 0; cyl < TRACKS; cyl++) {
	for (let side = 0; side < SIDES; side++) {
		const recordSize = 16 + SPT * SECTOR_SIZE
		const th = Buffer.alloc(16)
		th.writeUInt32LE(recordSize, 0)
		th.writeUInt32LE(0, 4)            // fuzzyCount
		th.writeUInt16LE(SPT, 8)          // sectorCount
		th.writeUInt16LE(0, 10)           // trackFlags = simple
		th.writeUInt16LE(6250, 12)        // trackLength (nominal)
		th[14] = (side << 7) | cyl        // trackNumber
		th[15] = 0                        // trackType

		const stOff = ((cyl * SIDES + side) * SPT) * SECTOR_SIZE
		const sectors = st.subarray(stOff, stOff + SPT * SECTOR_SIZE)
		parts.push(th, sectors)
	}
}

const out = Buffer.concat(parts)
writeFileSync(stxPath, out)
console.log(`Wrote ${stxPath} (${out.length} bytes, ${TRACKS * SIDES} tracks)`)
