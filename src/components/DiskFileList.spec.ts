import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import DiskFileList from '../components/DiskFileList.vue'
import { Fat12Image } from '../lib/disk/fat12'

const here = dirname(fileURLToPath(import.meta.url))
const fixturePath = join(here, '..', 'lib', 'disk', '__fixtures__', 'sample.st')

function loadFixtureImage(): Fat12Image {
	const buf = readFileSync(fixturePath)
	const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
	return new Fat12Image(bytes)
}

describe('DiskFileList', () => {
	it('lists every file from the disk image, sorted by path', () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		const paths = wrapper.findAll('.disk-list__path').map(el => el.text())
		expect(paths).toEqual(['/HELLO.TXT', '/READ.ME', '/SUB/INSIDE.TXT'])
	})

	it('renders a row per file with size and date columns', () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		const rows = wrapper.findAll('.disk-list__row')
		expect(rows).toHaveLength(3)

		// Each row should have a path, a size, and a date cell.
		for (const row of rows) {
			expect(row.find('.disk-list__path').exists()).toBe(true)
			expect(row.find('.disk-list__size').exists()).toBe(true)
			expect(row.find('.disk-list__date').exists()).toBe(true)
		}
	})

	it('emits "select" with the matching FileEntry when a row is clicked', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		// Click the HELLO.TXT row.
		const helloRow = wrapper.find('[data-testid="file-/HELLO.TXT"]')
		expect(helloRow.exists()).toBe(true)
		await helloRow.trigger('click')

		const selectEvent = wrapper.emitted('select')
		expect(selectEvent).toBeDefined()
		expect(selectEvent).toHaveLength(1)

		const emittedEntry = selectEvent![0][0] as { path: string; entry: { size: number } }
		expect(emittedEntry.path).toBe('/HELLO.TXT')
		// "Hello, Atari ST!\r\n" is 18 bytes — matches what gen-fixtures writes.
		expect(emittedEntry.entry.size).toBe(18)
	})

	it('shows the empty-state message when the image has no files', () => {
		// Hand-rolled minimal "image" substitute: an object that quacks like
		// Fat12Image as far as DiskFileList is concerned (only listFiles()
		// is read by the component).
		const emptyImage = { listFiles: () => [] } as unknown as Fat12Image
		const wrapper = mount(DiskFileList, { props: { image: emptyImage } })

		expect(wrapper.find('.disk-list__empty').exists()).toBe(true)
		expect(wrapper.text()).toContain('No files')
		expect(wrapper.findAll('.disk-list__row')).toHaveLength(0)
	})
})

describe('DiskFileList — keyboard navigation', () => {
	function newKeyboardEvent(key: string): KeyboardEvent {
		return new KeyboardEvent('keydown', { key, bubbles: true })
	}

	it('ArrowDown moves selection down by one', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image }, attachTo: document.body })

		// First row starts selected (data-idx="0" has the --selected class).
		expect(wrapper.find('[data-idx="0"]').classes()).toContain('disk-list__row--selected')

		window.dispatchEvent(newKeyboardEvent('ArrowDown'))
		await wrapper.vm.$nextTick()
		expect(wrapper.find('[data-idx="0"]').classes()).not.toContain('disk-list__row--selected')
		expect(wrapper.find('[data-idx="1"]').classes()).toContain('disk-list__row--selected')

		wrapper.unmount()
	})

	it('ArrowUp does not go above 0', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		window.dispatchEvent(newKeyboardEvent('ArrowUp'))
		await wrapper.vm.$nextTick()
		expect(wrapper.find('[data-idx="0"]').classes()).toContain('disk-list__row--selected')

		wrapper.unmount()
	})

	it('End jumps to the last file', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })
		const lastIdx = image.listFiles().length - 1

		window.dispatchEvent(newKeyboardEvent('End'))
		await wrapper.vm.$nextTick()
		expect(wrapper.find(`[data-idx="${lastIdx}"]`).classes()).toContain('disk-list__row--selected')

		wrapper.unmount()
	})

	it('Enter emits select with the currently-highlighted file', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		// Move to READ.ME (index 1) and press Enter.
		window.dispatchEvent(newKeyboardEvent('ArrowDown'))
		await wrapper.vm.$nextTick()
		window.dispatchEvent(newKeyboardEvent('Enter'))
		await wrapper.vm.$nextTick()

		const emitted = wrapper.emitted('select')
		expect(emitted).toHaveLength(1)
		expect((emitted![0][0] as { path: string }).path).toBe('/READ.ME')

		wrapper.unmount()
	})

	it('Escape emits close', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		window.dispatchEvent(newKeyboardEvent('Escape'))
		await wrapper.vm.$nextTick()

		expect(wrapper.emitted('close')).toHaveLength(1)

		wrapper.unmount()
	})

	it('ignores keys when focus is inside an input', async () => {
		const image = loadFixtureImage()
		const wrapper = mount(DiskFileList, { props: { image } })

		// Simulate an input being focused: build a keyboard event whose
		// target is an input element.
		const input = document.createElement('input')
		document.body.appendChild(input)
		input.focus()
		const event = new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true })
		Object.defineProperty(event, 'target', { value: input })
		window.dispatchEvent(event)
		await wrapper.vm.$nextTick()

		// Selection should not have moved.
		expect(wrapper.find('[data-idx="0"]').classes()).toContain('disk-list__row--selected')

		wrapper.unmount()
		document.body.removeChild(input)
	})
})
