// Minimal .st -> .msa encoder, used by gen-fixtures.mjs to produce a paired
// fixture so the MSA decoder test can verify against a real compressed image.
// Compression policy is naive: emit any run of >= 4 identical bytes as an RLE
// run; otherwise emit literals. An 0xE5 byte is always emitted as a run of 1.
//
// This is the inverse of src/lib/disk/msa.ts. The decoder is the production
// code path; this encoder exists only to make test fixtures, so it lives under
// scripts/ rather than src/.

import { readFileSync, writeFileSync } from 'node:fs'

const MSA_MAGIC = 0x0E0F
const SECTOR_SIZE = 512
const RLE_MARKER = 0xE5
const MIN_RUN = 4

const stPath = process.argv[2]
const msaPath = process.argv[3]
if (!stPath || !msaPath) {
	console.error('Usage: msa-encode.mjs <input.st> <output.msa>')
	process.exit(1)
}

const st = readFileSync(stPath)

// Hatari's boot-sector offsets (little-endian):
const sectorsPerTrack = st.readUInt16LE(0x18)
const sidesStored     = st.readUInt16LE(0x1A) // 0 or 1; we store sides-1
const totalSectors    = st.readUInt16LE(0x13) || st.readUInt32LE(0x20)

const sides = Math.max(1, sidesStored)
if (sides > 2) throw new Error(`Unexpected sides value ${sides}`)
const tracksPerSide = Math.floor(totalSectors / sectorsPerTrack / sides)

const bytesPerTrack = SECTOR_SIZE * sectorsPerTrack
const out = []

function pushU16BE(v) {
	out.push((v >> 8) & 0xFF, v & 0xFF)
}

pushU16BE(MSA_MAGIC)
pushU16BE(sectorsPerTrack)
pushU16BE(sides - 1)
pushU16BE(0)              // starting track
pushU16BE(tracksPerSide - 1) // ending track

for (let track = 0; track < tracksPerSide; track++) {
	for (let side = 0; side < sides; side++) {
		const offset = (track * sides + side) * bytesPerTrack
		const trackData = st.subarray(offset, offset + bytesPerTrack)
		const encoded = encodeTrack(trackData)
		if (encoded.length < bytesPerTrack) {
			pushU16BE(encoded.length)
			for (const b of encoded) out.push(b)
		} else {
			pushU16BE(bytesPerTrack)
			for (const b of trackData) out.push(b)
		}
	}
}

writeFileSync(msaPath, Buffer.from(out))
console.log(`Encoded ${stPath} -> ${msaPath} (${out.length} bytes; .st was ${st.length})`)

function encodeTrack(track) {
	const out = []
	let i = 0
	while (i < track.length) {
		const b = track[i]
		let run = 1
		while (i + run < track.length && track[i + run] === b) run++

		if (run >= MIN_RUN || b === RLE_MARKER) {
			out.push(RLE_MARKER, b, (run >> 8) & 0xFF, run & 0xFF)
			i += run
		} else {
			out.push(b)
			i++
		}
	}
	return out
}
