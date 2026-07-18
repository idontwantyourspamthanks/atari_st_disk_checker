import { describe, it, expect } from 'vitest'
import {
	reportsToJson,
	reportsToCsv,
	csvEscape,
} from './export'
import type { ScanReport } from './scanner'

function baseReport(over: Partial<ScanReport> = {}): ScanReport {
	return {
		fileName: 'demo.st',
		format: 'st',
		status: 'clean',
		imageBytes: 720 * 1024,
		bootSectorChecksum: 0xABCD,
		bootSectorExecutable: false,
		findings: [],
		...over,
	}
}

describe('reportsToJson', () => {
	it('produces valid JSON that round-trips back to ScanReport[]', () => {
		const reports = [
			baseReport(),
			baseReport({
				fileName: 'virus.st',
				status: 'infected',
				bootSectorExecutable: true,
				findings: [{
					kind: 'signature',
					name: 'Pentagon',
					detail: 'Payload display.',
					severity: 'high',
				}],
			}),
		]

		const json = reportsToJson(reports)
		const parsed = JSON.parse(json)
		expect(parsed).toHaveLength(2)
		expect(parsed[0].fileName).toBe('demo.st')
		expect(parsed[1].fileName).toBe('virus.st')
		expect(parsed[1].status).toBe('infected')
		expect(parsed[1].findings[0].name).toBe('Pentagon')
	})

	it('handles an empty array', () => {
		expect(reportsToJson([])).toBe('[]')
	})
})

describe('csvEscape', () => {
	it('does not quote a plain string', () => {
		expect(csvEscape('hello')).toBe('hello')
	})
	it('quotes a string containing a comma', () => {
		expect(csvEscape('a,b')).toBe('"a,b"')
	})
	it('doubles embedded quotes', () => {
		expect(csvEscape('say "hi"')).toBe('"say ""hi"""')
	})
	it('quotes newlines', () => {
		expect(csvEscape('line1\nline2')).toBe('"line1\nline2"')
	})
})

describe('reportsToCsv', () => {
	it('returns a header row followed by one row per report', () => {
		const reports = [
			baseReport(),
			baseReport({ fileName: 'other.st' }),
		]
		const csv = reportsToCsv(reports)
		const lines = csv.split('\r\n').filter(l => l.length > 0)
		expect(lines).toHaveLength(3)
		expect(lines[0]).toMatch(/^fileName,format,status/)
	})

	it('uses 0xNNNN format for the bootsector checksum column', () => {
		const csv = reportsToCsv([baseReport({ bootSectorChecksum: 0x1234 })])
		expect(csv).toContain('0x1234')
	})

	it('"yes"/"no" for the executability flag', () => {
		const csv = reportsToCsv([
			baseReport({ bootSectorExecutable: true }),
			baseReport({ fileName: 'other.st', bootSectorExecutable: false }),
		])
		expect(csv).toContain(',yes,')
		expect(csv).toContain(',no,')
	})

	it('surfaces the highest-severity finding as the "top" columns', () => {
		const reports = [baseReport({
			status: 'infected',
			findings: [
				{ kind: 'heuristic', name: 'low thing', detail: 'boring', severity: 'low' },
				{ kind: 'signature', name: 'Pentagon', detail: 'armed',   severity: 'high' },
				{ kind: 'heuristic', name: 'odd md',   detail: 'medium',  severity: 'medium' },
			],
		})]

		const csv = reportsToCsv(reports)
		const dataRow = csv.split('\r\n').filter(l => l.length > 0)[1]
		// The high-severity signature must come through as topFindingName.
		expect(dataRow).toContain('Pentagon')
		expect(dataRow).toContain('high')
	})

	it('exports empty cells when there are no findings', () => {
		const csv = reportsToCsv([baseReport()])
		const fields = csv.split('\r\n').filter(l => l.length > 0)[1].split(',')
		// findingCount column is index 6.
		expect(fields[6]).toBe('0')
		// topSeverity (index 7) is an empty cell.
		expect(fields[7]).toBe('')
	})

	it('escapes a filename containing a comma', () => {
		const reports = [baseReport({ fileName: 'foo,bar.st' })]
		const csv = reportsToCsv(reports)
		const line = csv.split('\r\n').filter(l => l.length > 0)[1]
		expect(line).toContain('"foo,bar.st"')
	})
})