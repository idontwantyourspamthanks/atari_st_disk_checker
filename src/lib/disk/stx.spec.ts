import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { decodeStx, isStx } from './stx'
import { readU16LE, readU32LE } from './bytes'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '__fixtures__')

function load(name: string): Uint8Array {
	const buf = readFileSync(join(fixturesDir, name))
	return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

describe('isStx', () => {
	it('recognises the sample.stx magic', () => {
		expect(isStx(load('sample.stx'))).toBe(true)
	})

	it('rejects a raw .st image', () => {
		expect(isStx(load('sample.st'))).toBe(false)
	})
})

describe('decodeStx — round-trip against sample.st', () => {
	it('produces byte-identical sector data to the source .st', () => {
		const stx = decodeStx(load('sample.stx'))
		const st  = load('sample.st')

		expect(stx.geometry).toEqual({ tracks: 80, sides: 2, sectorsPerTrack: 9 })
		expect(stx.raw.length).toBe(st.length)
		expect(stx.raw).toEqual(st)
	})

	it('rejects truncated / non-STX input', () => {
		expect(() => decodeStx(new Uint8Array(8))).toThrow(/too short/i)
		expect(() => decodeStx(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])))
			.toThrow(/magic/i)
	})
})

describe('decodeStx — sector-descriptor tracks', () => {
	it('extracts sectors addressed by descriptors (no track image)', () => {
		// Hand-build a 1-track, 1-side, 2-sector STX using TRK_SECT.
		const sector1 = new Uint8Array(512).fill(0x11)
		const sector2 = new Uint8Array(512).fill(0x22)
		sector1[0] = 0x60 // pretend boot marker so we can spot it

		const parts: number[] = []
		const pushU16 = (n: number) => { parts.push(n & 0xff, (n >> 8) & 0xff) }
		const pushU32 = (n: number) => {
			parts.push(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff)
		}
		const pushBytes = (b: Uint8Array) => { for (const x of b) parts.push(x) }

		// File header
		parts.push(0x52, 0x53, 0x59, 0x00)
		pushU16(3)      // version
		pushU16(1)      // tool
		pushU16(0)      // reserved
		parts.push(1)   // trackCount
		parts.push(0)   // revision
		pushU32(0)

		// Track record: header + 2 sector descs + 2×512 data
		const recordSize = 16 + 2 * 16 + 2 * 512
		pushU32(recordSize)
		pushU32(0)      // fuzzy
		pushU16(2)      // sectors
		pushU16(0x01)   // TRK_SECT
		pushU16(6250)
		parts.push(0)   // track 0 side 0
		parts.push(0)

		// Sector desc 1: offset 0, sector number 1, size code 2 (512)
		pushU32(0)
		pushU16(0); pushU16(0)
		parts.push(0, 0, 1, 2) // track, head, number, size
		pushU16(0)            // crc
		parts.push(0, 0)      // fdcFlags, reserved

		// Sector desc 2: offset 512, sector number 2
		pushU32(512)
		pushU16(0); pushU16(0)
		parts.push(0, 0, 2, 2)
		pushU16(0)
		parts.push(0, 0)

		pushBytes(sector1)
		pushBytes(sector2)

		const buf = new Uint8Array(parts)
		// Sanity: recordSize field matches.
		expect(readU32LE(buf, 16)).toBe(recordSize)
		expect(readU16LE(buf, 16 + 10)).toBe(0x01)

		const decoded = decodeStx(buf)
		expect(decoded.geometry).toEqual({ tracks: 1, sides: 1, sectorsPerTrack: 2 })
		expect(decoded.raw.subarray(0, 512)).toEqual(sector1)
		expect(decoded.raw.subarray(512, 1024)).toEqual(sector2)
	})
})
