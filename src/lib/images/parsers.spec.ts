import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
	parsePi1,
	parsePi2,
	parsePi3,
	parsePi1Compressed,
	parseTny,
	parseSpu,
	spectrumFindIndex,
	parseNeo,
	parseIff,
	parseImage,
	imageKindFromName,
	type DecodedImage,
} from './parsers'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '__fixtures__')

function load(name: string): Uint8Array {
	const buf = readFileSync(join(fixturesDir, name))
	return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

// The fixture's known pattern: vertical colour stripes, width/numIndices wide.
// Pixel (x, y) has palette index floor(x / stripeWidth) % numIndices.
function expectedPixel(x: number, width: number, numIndices: number): number {
	const stripeWidth = width / numIndices
	return Math.floor(x / stripeWidth) % numIndices
}

function expectStripes(img: DecodedImage, numIndices: number) {
	expect(img.pixels.length).toBe(img.width * img.height)
	expect(img.palette.length).toBeGreaterThanOrEqual(numIndices)

	// Sample a handful of coordinates across the stripe pattern.
	for (const [x, y] of [[0, 0], [1, 100], [Math.floor(img.width / 2) - 1, 50], [img.width - 1, img.height - 1]]) {
		expect(img.pixels[y * img.width + x]).toBe(expectedPixel(x, img.width, numIndices))
	}
}

describe('imageKindFromName', () => {
	it('maps .pi1 to pi1', () => {
		expect(imageKindFromName('PAINT.PI1')).toBe('pi1')
	})
	it('maps .pi2 to pi2', () => {
		expect(imageKindFromName('med.pi2')).toBe('pi2')
	})
	it('maps .pi3 to pi3', () => {
		expect(imageKindFromName('hires.pi3')).toBe('pi3')
	})
	it('maps .tny / .tn1 / .tn2 / .tn3 to tny', () => {
		expect(imageKindFromName('pic.TNY')).toBe('tny')
		expect(imageKindFromName('pic.tn1')).toBe('tny')
		expect(imageKindFromName('pic.tn2')).toBe('tny')
		expect(imageKindFromName('pic.tn3')).toBe('tny')
	})
	it('maps .spu and .spl to spu', () => {
		expect(imageKindFromName('scene.SPU')).toBe('spu')
		expect(imageKindFromName('scene.spl')).toBe('spu')
	})
	it('maps .neo (and .ne) to neo', () => {
		expect(imageKindFromName('scene.neo')).toBe('neo')
		expect(imageKindFromName('scene.ne')).toBe('neo')
	})
	it('maps .iff and .ilbm to iff', () => {
		expect(imageKindFromName('picture.IFF')).toBe('iff')
		expect(imageKindFromName('picture.ilbm')).toBe('iff')
	})
	it('returns null for unknown extensions', () => {
		expect(imageKindFromName('readme.txt')).toBeNull()
		expect(imageKindFromName('game.prg')).toBeNull()
	})
})

describe('parsePi1', () => {
	it('decodes the fixture as 320x200 16-colour with the stripe pattern', () => {
		const img = parsePi1(load('sample.pi1'))
		expect(img.width).toBe(320)
		expect(img.height).toBe(200)
		expectStripes(img, 16)
	})

	it('rejects files too small to be a valid PI1', () => {
		expect(() => parsePi1(new Uint8Array(100))).toThrow(/too small/i)
	})

	it('exposes the format tag on the result', () => {
		expect(parsePi1(load('sample.pi1')).format).toBe('pi1')
	})
})

describe('parsePi2 (medium res)', () => {
	it('decodes the fixture as 640x200 with 4 palette indices', () => {
		const img = parsePi2(load('sample.pi2'))
		expect(img.width).toBe(640)
		expect(img.height).toBe(200)
		expect(img.palette.length).toBe(4)
		expectStripes(img, 4)
	})

	it('rejects files too small', () => {
		expect(() => parsePi2(new Uint8Array(100))).toThrow(/too small/i)
	})
})

describe('parsePi3 (high res)', () => {
	it('decodes the fixture as 640x400 with 2 palette indices', () => {
		const img = parsePi3(load('sample.pi3'))
		expect(img.width).toBe(640)
		expect(img.height).toBe(400)
		expect(img.palette.length).toBe(2)
		expectStripes(img, 2)
	})

	it('rejects files too small', () => {
		expect(() => parsePi3(new Uint8Array(100))).toThrow(/too small/i)
	})
})

describe('parsePi1Compressed', () => {
	it('decodes the compressed fixture to the same image as the uncompressed PI1', () => {
		// Fixture is stored as sample.cp1 for clarity, but real compressed
		// Degas files keep the .PI1 extension — dispatch uses that + the
		// 0x8000 resolution flag.
		const compressed = parseImage(load('sample.cp1'), 'sample.pi1')
		const uncompressed = parsePi1(load('sample.pi1'))

		expect(compressed.format).toBe('pi1c')
		expect(compressed.width).toBe(320)
		expect(compressed.height).toBe(200)
		// Pixel data must match the uncompressed version bit-for-bit.
		expect(compressed.pixels.length).toBe(uncompressed.pixels.length)
		for (let i = 0; i < compressed.pixels.length; i++) {
			expect(compressed.pixels[i]).toBe(uncompressed.pixels[i])
		}
	})

	it('rejects files too small to even contain a header', () => {
		expect(() => parsePi1Compressed(new Uint8Array(8))).toThrow(/too small/i)
	})
})

describe('parseImage auto-detects compressed PI1 by the 0x8000 flag', () => {
	it('dispatches to parsePi1Compressed for a file with the high bit set', () => {
		// The sample.cp1 fixture has the high bit set in its resolution word.
		const img = parseImage(load('sample.cp1'), 'compressed.PI1')
		expect(img.format).toBe('pi1c')
	})
})

describe('parseTny', () => {
	it('decodes the fixture as 320x200 with the stripe pattern', () => {
		const img = parseTny(load('sample.tny'))
		expect(img.width).toBe(320)
		expect(img.height).toBe(200)
		expect(img.format).toBe('tny')
		expectStripes(img, 16)
	})

	it('rejects files too small to be a valid TNY', () => {
		expect(() => parseTny(new Uint8Array(10))).toThrow(/too small/i)
	})
})

describe('spectrumFindIndex', () => {
	it('keeps even colour indices in bank 0 near the left edge', () => {
		expect(spectrumFindIndex(0, 0)).toBe(0)
		expect(spectrumFindIndex(0, 2)).toBe(2)
	})

	it('shifts into bank 1 / bank 2 further across the scanline', () => {
		// For c=0: x1 = 1; bank1 for x in [1, 160), bank2 for x >= 161
		expect(spectrumFindIndex(50, 0)).toBe(16)
		expect(spectrumFindIndex(200, 0)).toBe(32)
	})
})

describe('parseSpu', () => {
	it('decodes the fixture as 320x200 with the stripe pattern (below scanline 0)', () => {
		const img = parseSpu(load('sample.spu'))
		const reference = parsePi1(load('sample.pi1'))
		expect(img.width).toBe(320)
		expect(img.height).toBe(200)
		expect(img.format).toBe('spu')
		expect(img.pixels.length).toBe(320 * 200)
		expect(img.palette.length).toBeGreaterThanOrEqual(16)

		// Spectrum remaps into a deduped absolute-colour palette, so compare
		// resolved hex colours against the PI1 reference (same underlying
		// stripe pattern and ST palette). Scanline 0 is unused/black.
		for (const [x, y] of [[0, 1], [1, 100], [159, 50], [319, 199]]) {
			const got = img.palette[img.pixels[y * img.width + x]]
			const want = reference.palette[reference.pixels[y * reference.width + x]]
			expect(got).toBe(want)
		}
		expect(img.palette[img.pixels[0]]).toBe('#000000')
	})

	it('rejects files too small to be a valid SPU', () => {
		expect(() => parseSpu(new Uint8Array(100))).toThrow(/too small/i)
	})
})

describe('parseNeo', () => {
	it('decodes the fixture as 320x200 with the stripe pattern', () => {
		const img = parseNeo(load('sample.neo'))
		expect(img.width).toBe(320)
		expect(img.height).toBe(200)
		expectStripes(img, 16)
	})

	it('rejects files too small to be a valid NEO', () => {
		expect(() => parseNeo(new Uint8Array(100))).toThrow(/too small/i)
	})
})

describe('parseIff', () => {
	it('decodes the fixture as 320x200 with the stripe pattern', () => {
		const img = parseIff(load('sample.iff'))
		expect(img.width).toBe(320)
		expect(img.height).toBe(200)
		expectStripes(img, 16)
	})

	it('rejects files that do not start with FORM…ILBM', () => {
		expect(() => parseIff(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]))).toThrow(/ILBM/)
	})
})

describe('parseImage dispatch', () => {
	it('parses a .pi1 by filename (uncompressed)', () => {
		const img = parseImage(load('sample.pi1'), 'test.PI1')
		expect(img.format).toBe('pi1')
	})

	it('parses a .pi2 by filename', () => {
		const img = parseImage(load('sample.pi2'), 'test.PI2')
		expect(img.format).toBe('pi2')
	})

	it('parses a .pi3 by filename', () => {
		const img = parseImage(load('sample.pi3'), 'test.PI3')
		expect(img.format).toBe('pi3')
	})

	it('parses a .tny by filename', () => {
		const img = parseImage(load('sample.tny'), 'test.TNY')
		expect(img.format).toBe('tny')
	})

	it('parses a .spu by filename', () => {
		const img = parseImage(load('sample.spu'), 'test.SPU')
		expect(img.format).toBe('spu')
	})

	it('parses a .neo by filename', () => {
		const img = parseImage(load('sample.neo'), 'test.NEO')
		expect(img.format).toBe('neo')
	})

	it('parses a .iff by filename', () => {
		const img = parseImage(load('sample.iff'), 'test.iff')
		expect(img.format).toBe('iff')
	})

	it('throws for unrecognised extensions', () => {
		expect(() => parseImage(new Uint8Array(0), 'readme.txt')).toThrow(/not a recognised/i)
	})
})
