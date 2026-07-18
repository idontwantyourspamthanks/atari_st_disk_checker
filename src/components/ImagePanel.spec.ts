import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import ImagePanel from '../components/ImagePanel.vue'

const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'lib', 'images', '__fixtures__')

function loadPi1(): Uint8Array {
	const buf = readFileSync(join(fixturesDir, 'sample.pi1'))
	return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

describe('ImagePanel', () => {
	it('mounts and shows format metadata', () => {
		const wrapper = mount(ImagePanel, {
			props: { name: 'test.pi1', bytes: loadPi1(), origin: 'raw' },
		})

		// jsdom does not implement canvas 2d rendering, but the component
		// should still mount and show the textual metadata.
		expect(wrapper.find('.gem-window__title').text()).toContain('test.pi1')
		expect(wrapper.find('.meta').text()).toContain('PI1')
		expect(wrapper.find('.meta').text()).toContain('320×200')
		expect(wrapper.find('.meta').text()).toContain('16 colours')
	})

	it('shows the zoom controls with the default selected', () => {
		const wrapper = mount(ImagePanel, {
			props: { name: 'test.pi1', bytes: loadPi1(), origin: 'raw' },
		})
		const buttons = wrapper.findAll('.zoom-btn')
		expect(buttons).toHaveLength(4)
		expect(buttons.map(b => b.text())).toEqual(['1×', '2×', '4×', '8×'])
		// Default zoom is 4× (320x200 is tiny at 1×).
		const active = buttons.filter(b => b.classes().includes('zoom-btn--active'))
		expect(active).toHaveLength(1)
		expect(active[0].text()).toBe('4×')
	})

	it('renders the palette swatches', () => {
		const wrapper = mount(ImagePanel, {
			props: { name: 'test.pi1', bytes: loadPi1(), origin: 'raw' },
		})
		const swatches = wrapper.findAll('.palette__swatch')
		expect(swatches).toHaveLength(16)
	})

	it('shows the "back to list" button only for disk-origin files', () => {
		const fromDisk = mount(ImagePanel, {
			props: { name: 'test.pi1', bytes: loadPi1(), origin: 'disk' },
		})
		expect(fromDisk.findAll('button').some(b => b.text().includes('List'))).toBe(true)

		const fromRaw = mount(ImagePanel, {
			props: { name: 'test.pi1', bytes: loadPi1(), origin: 'raw' },
		})
		expect(fromRaw.findAll('button').some(b => b.text().includes('List'))).toBe(false)
	})

	it('shows an error message when the bytes cannot be parsed', () => {
		const wrapper = mount(ImagePanel, {
			props: { name: 'bogus.pi1', bytes: new Uint8Array(64), origin: 'raw' },
		})
		expect(wrapper.find('.error').exists()).toBe(true)
		expect(wrapper.find('.error').text()).toMatch(/too small/i)
	})
})
