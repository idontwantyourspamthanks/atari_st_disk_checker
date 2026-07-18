import { unzipSync } from 'fflate'

export interface ZipEntry {
	/** Path inside the archive, e.g. "games/foo.st". */
	name: string
	bytes: Uint8Array
}

export interface ZipExtractionResult {
	entries: ZipEntry[]
	/** Non-disk-image files that were ignored (for transparency in the UI). */
	skipped: string[]
	/** Present if the archive itself couldn't be parsed. */
	error?: string
}

/**
 * Extract every `.st` / `.msa` / `.stx` entry from a ZIP archive. Other files
 * (READMEs, scans, etc.) are listed in `skipped` so the UI can show
 * "ignored 3 unrelated files" rather than silently dropping them.
 *
 * Uses fflate's synchronous `unzipSync` — fine for the zip sizes we
 * expect (a few hundred floppy images). If we ever need to handle truly
 * huge archives, swap to the async `unzip` and yield entries.
 */
export function extractDiskImagesFromZip(zipBytes: Uint8Array): ZipExtractionResult {
	let unzipped: Record<string, Uint8Array>
	try {
		unzipped = unzipSync(zipBytes)
	} catch (e) {
		return {
			entries: [],
			skipped: [],
			error: e instanceof Error ? e.message : String(e),
		}
	}

	const entries: ZipEntry[] = []
	const skipped: string[] = []

	for (const [name, bytes] of Object.entries(unzipped)) {
		// Skip macOS metadata files and directory entries.
		if (name.startsWith('__MACOSX/') || name.endsWith('/')) {
			skipped.push(name)
			continue
		}
		if (looksLikeDiskImage(name)) {
			entries.push({ name, bytes })
		} else {
			skipped.push(name)
		}
	}

	entries.sort((a, b) => a.name.localeCompare(b.name))
	skipped.sort()

	return { entries, skipped }
}

function looksLikeDiskImage(name: string): boolean {
	const lower = name.toLowerCase()
	return lower.endsWith('.st') || lower.endsWith('.msa') || lower.endsWith('.stx')
}
