import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { buildExecutableBootSector } from '../lib/scan/bootSector.spec'
import HexView from '../components/HexView.vue'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'lib', 'disk', '__fixtures__')

function loadSt(): Uint8Array {
	const buf = readFileSync(join(fixturesDir, 'sample.st'))
	return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

describe('HexView', () => {
	it('mounts and shows a status line', () => {
		const wrapper = mount(HexView, { props: { image: loadSt() } })
		expect(wrapper.find('.hex__status').exists()).toBe(true)
		// mtools-generated clean disk is not executable.
		expect(wrapper.find('.hex__status').text()).toContain('not executable')
	})

	it('shows "executable" for an executable boot sector', () => {
		const boot = buildExecutableBootSector('HI')
		// The component calls getImageBytes / getBootSector internally, which
		// passes a .st through unchanged. We hand it just the 512-byte
		// boot sector; the helpers will accept that as-is (no MSA magic).
		const wrapper = mount(HexView, { props: { image: boot } })
		expect(wrapper.find('.hex__status').text()).toContain('executable')
	})

	it('renders 32 rows of 16 bytes each', () => {
		const wrapper = mount(HexView, { props: { image: loadSt() } })
		const rows = wrapper.findAll('.hex__row')
		expect(rows).toHaveLength(32)
	})

	it('shows the offset for each row in hex with at least 8 hex digits', () => {
		const wrapper = mount(HexView, { props: { image: loadSt() } })
		const offsets = wrapper.findAll('.hex__offset').map(el => el.text())
		expect(offsets[0]).toBe('00000000')
		expect(offsets[1]).toBe('00000010')
		expect(offsets[31]).toBe('000001F0')
	})

	it('replaces non-printable bytes with "·" in the ASCII column', () => {
		// An all-zero boot sector should have a row of dots in the ASCII column,
		// not the NUL character.
		const zero = new Uint8Array(512)
		const wrapper = mount(HexView, { props: { image: zero } })
		const firstAscii = wrapper.findAll('.hex__ascii')[0].text()
		expect(firstAscii).toBe('·'.repeat(16))
	})

	it('highlights rows that contain an offset in highlightOffsets', () => {
		const wrapper = mount(HexView, {
			props: { image: loadSt(), highlightOffsets: [0x10, 0x12] },
		})
		// Row 2 (offset 0x10) should be highlighted because it contains 0x10 and 0x12.
		const rows = wrapper.findAll('.hex__row')
		expect(rows[0].classes()).not.toContain('hex__row--highlight')
		expect(rows[1].classes()).toContain('hex__row--highlight')
	})
})