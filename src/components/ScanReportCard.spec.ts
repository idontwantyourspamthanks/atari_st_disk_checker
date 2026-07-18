import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ScanReportCard from '../components/ScanReportCard.vue'
import type { ScanReport } from '../lib/scan/scanner'

function baseReport(overrides: Partial<ScanReport> = {}): ScanReport {
	return {
		fileName: 'test.st',
		format: 'st',
		status: 'clean',
		imageBytes: 720 * 1024,
		bootSectorChecksum: 0xABCD,
		bootSectorExecutable: false,
		findings: [],
		...overrides,
	}
}

describe('ScanReportCard', () => {
	it('renders the file name and status', () => {
		const wrapper = mount(ScanReportCard, { props: { report: baseReport() } })
		expect(wrapper.find('.scan-card__name').text()).toBe('test.st')
		expect(wrapper.find('.scan-card__status').text()).toBe('CLEAN')
	})

	it('applies the clean status class', () => {
		const wrapper = mount(ScanReportCard, { props: { report: baseReport() } })
		expect(wrapper.find('.scan-card--clean').exists()).toBe(true)
	})

	it('applies the protected status class and shows PROT findings', () => {
		const report = baseReport({
			status: 'protected',
			findings: [{
				kind: 'protector',
				name: 'Sagrotan',
				detail: 'Known boot protector.',
				severity: 'info',
			}],
		})
		const wrapper = mount(ScanReportCard, { props: { report } })
		expect(wrapper.find('.scan-card--protected').exists()).toBe(true)
		expect(wrapper.text()).toContain('PROT')
		expect(wrapper.text()).toContain('Sagrotan')
	})

	it('applies the infected status class and shows findings when there are signatures', () => {
		const report = baseReport({
			status: 'infected',
			findings: [{
				kind: 'signature',
				name: 'Pentagon',
				detail: 'Matched signature string "PENTAGON" at offset 0x80.',
				severity: 'high',
			}],
		})
		const wrapper = mount(ScanReportCard, { props: { report } })

		expect(wrapper.find('.scan-card--infected').exists()).toBe(true)
		expect(wrapper.find('.finding--signature').exists()).toBe(true)
		expect(wrapper.find('.finding__name').text()).toBe('Pentagon')
		expect(wrapper.find('.finding__kind').text()).toBe('VIRUS')
	})

	it('shows the "no findings" message for a clean image', () => {
		const wrapper = mount(ScanReportCard, { props: { report: baseReport() } })
		expect(wrapper.find('.scan-card__nofindings').exists()).toBe(true)
	})

	it('shows the error message in place of findings when status is "error"', () => {
		const report = baseReport({
			status: 'error',
			error: 'Image too short to contain a boot sector',
		})
		const wrapper = mount(ScanReportCard, { props: { report } })
		expect(wrapper.find('.scan-card__error').exists()).toBe(true)
		expect(wrapper.text()).toContain('Image too short')
		expect(wrapper.find('.scan-card__findings').exists()).toBe(false)
	})

	it('formats the boot sector checksum as 0xNNNN', () => {
		const wrapper = mount(ScanReportCard, { props: { report: baseReport({ bootSectorChecksum: 0x1234 }) } })
		expect(wrapper.find('.scan-card__meta').text()).toContain('0x1234')
	})
})
