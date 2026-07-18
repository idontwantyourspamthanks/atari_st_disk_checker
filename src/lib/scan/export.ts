import type { ScanReport } from './scanner'

/**
 * Serialise scan results as a pretty-printed JSON string. Preserves every
 * field on `ScanReport` so the export is faithful — including boot sector
 * checksum, finding details, and any scan errors.
 */
export function reportsToJson(reports: readonly ScanReport[]): string {
	return JSON.stringify(reports, null, 2)
}

/**
 * Serialise scan results as CSV. One row per file scanned, with a flat
 * shape that's friendly for spreadsheet apps (LibreOffice Calc, Google
 * Sheets, Excel).
 *
 * Columns: fileName, format, status, imageBytes, bootSectorChecksum,
 * bootSectorExecutable, findingCount, topSeverity, topFindingName,
 * topFindingDetail, error.
 *
 * "Top" = the most-concerning finding (highest severity first, then
 * signature before heuristic on ties).
 */
export function reportsToCsv(reports: readonly ScanReport[]): string {
	const SEVERITY_ORDER: Record<string, number> = {
		high: 0, medium: 1, low: 2, info: 3,
	}
	const toFindingRank = (f: ScanReport['findings'][number]) =>
		SEVERITY_ORDER[f.severity] ?? 99

	const rows = reports.map((r) => {
		const sorted = [...r.findings].sort((a, b) => toFindingRank(a) - toFindingRank(b))
		const top = sorted[0]
		return {
			fileName:               r.fileName,
			format:                  r.format,
			status:                  r.status,
			imageBytes:              r.imageBytes,
			bootSectorChecksum:     '0x' + r.bootSectorChecksum.toString(16).toUpperCase().padStart(4, '0'),
			bootSectorExecutable:   r.bootSectorExecutable ? 'yes' : 'no',
			findingCount:           r.findings.length,
			topSeverity:            top?.severity ?? '',
			topFindingName:         top?.name ?? '',
			topFindingDetail:       top?.detail ?? '',
			error:                  r.error ?? '',
		}
	})

	const headers = [
		'fileName', 'format', 'status', 'imageBytes',
		'bootSectorChecksum', 'bootSectorExecutable',
		'findingCount', 'topSeverity', 'topFindingName', 'topFindingDetail', 'error',
	]

	const lines = [headers.join(',')]
	for (const r of rows) {
		lines.push(headers.map(h => csvEscape(String(r[h as keyof typeof r]))).join(','))
	}
	return lines.join('\r\n') + '\r\n'
}

/**
 * CSV-escape a single cell. Per RFC 4180: quote the field if it contains
 * any of comma, double-quote, newline, or carriage return. Embedded
 * double-quotes are doubled.
 */
export function csvEscape(value: string): string {
	if (/[",\r\n]/.test(value)) {
		return '"' + value.replace(/"/g, '""') + '"'
	}
	return value
}

/**
 * Trigger a download of `text` as a file with the given filename. Uses
 * the same Blob + URL.createObjectURL pattern as ImagePanel's PNG export.
 */
export function downloadTextFile(text: string, filename: string, mimeType: string): void {
	const blob = new Blob([text], { type: mimeType })
	const url = URL.createObjectURL(blob)
	const a = document.createElement('a')
	a.href = url
	a.download = filename
	a.click()
	URL.revokeObjectURL(url)
}