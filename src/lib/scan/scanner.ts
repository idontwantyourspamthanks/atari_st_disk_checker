import {
	getBootSector,
	getImageBytes,
	bootSectorChecksum,
	isBootSectorExecutable,
	startsWith68000Opcode,
	countNonZeroBytesBeyondBpb,
} from './bootSector'
import {
	runHeuristics,
	PROTECTOR_EXPECTED_HEURISTIC_IDS,
	type HeuristicFinding,
} from './heuristics'
import { runBootSandbox, type SandboxResult } from './sandbox/bootSandbox'
import { matchSignatures, type SignatureMatch } from './signatures'
import { matchProtectors } from './protectors'
import type { ProtectorMatch } from './protectors'
import { isStx } from '../disk/stx'
import { MSA_MAGIC } from '../disk/msa'
import { readU16BE } from '../disk/bytes'

export type DiskFormat = 'st' | 'msa' | 'stx' | 'unknown'

export type ScanStatus = 'clean' | 'protected' | 'suspicious' | 'infected' | 'error'

/**
 * How much confidence we have that a signature match represents an actual
 * infection, as opposed to a disk that was merely vaccinated against the
 * named virus. Immunization used the same identifiable bytes at the same
 * offsets — so a signature match on a non-executable boot sector is most
 * likely a clean immunized disk rather than an infected one.
 */
export type InfectionStatus =
	| 'infected'           // Signature matches AND boot is executable with actual 68000 code
	| 'probably-infected'  // Signature matches AND boot is executable but code is suspicious/ambiguous
	| 'immunized'          // Signature matches but boot is NOT executable — likely a vaccinated clean disk
	| 'unclear'            // Anything else

export type ScanFinding = {
	kind: 'signature' | 'protector' | 'heuristic' | 'sandbox'
	/** Display name — virus/protector name, or heuristic headline. */
	name: string
	detail: string
	severity: 'info' | 'low' | 'medium' | 'high'
	/**
	 * Offsets within the boot sector that this finding concerns. The hex
	 * viewer highlights these rows so the user can see exactly what tripped
	 * the detector. Empty for findings that don't pinpoint a byte.
	 */
	highlightOffsets?: number[]
	/**
	 * Per-signature infection status. Only set on signature findings.
	 * Lets the UI distinguish "infected with X" from "immunized against X".
	 */
	infectionStatus?: InfectionStatus
}

export interface ScanReport {
	fileName: string
	format: DiskFormat
	status: ScanStatus
	/** Total image bytes scanned (raw, post-MSA-decode if applicable). */
	imageBytes: number
	/** Boot sector checksum TOS uses to decide executability. */
	bootSectorChecksum: number
	/** Whether TOS would execute the boot sector (checksum == 0x1234). */
	bootSectorExecutable: boolean
	/** The raw 512-byte boot sector — used by the hex viewer. Present whenever scanning succeeded. */
	bootSector?: Uint8Array
	findings: ScanFinding[]
	/** Present only when scanning threw before producing findings. */
	error?: string
}

/**
 * Scan a single disk image (raw bytes — `.st`, `.msa`, or `.stx`). Returns a report
 * combining virus signatures, protector signatures, and heuristic findings.
 *
 * Status assignment:
 *   - 'infected'    — at least one live virus signature matched
 *   - 'protected'   — known boot protector / antivirus bootblock, no live virus
 *   - 'suspicious'  — no named match, but ≥1 high/medium heuristic
 *   - 'clean'       — nothing concerning
 *   - 'error'       — boot sector couldn't be parsed at all
 */
export function scanImage(input: Uint8Array, fileName: string): ScanReport {
	const format = detectFormat(input)

	let boot: Uint8Array
	let imageBytes: number
	try {
		boot = getBootSector(input)
		imageBytes = (format === 'msa' || format === 'stx')
			? getImageBytes(input).length
			: input.length
	} catch (e) {
		return {
			fileName,
			format,
			status: 'error',
			imageBytes: input.length,
			bootSectorChecksum: 0,
			bootSectorExecutable: false,
			findings: [],
			error: e instanceof Error ? e.message : String(e),
		}
	}

	const checksum = bootSectorChecksum(boot)
	const executable = isBootSectorExecutable(boot)

	const signatureMatches = matchSignatures(boot)
	const protectorMatches = matchProtectors(boot)
	let heuristicFindings = runHeuristics(boot)
	let sandboxFindings = sandboxToFindings(runBootSandbox(boot))

	const infectionStatus = computeInfectionStatus(executable, boot)
	const liveVirus = signatureMatches.length > 0 && infectionStatus !== 'immunized'

	// A named protector explains an executable boot sector — demote the
	// generic boot-code heuristics so the card isn't double-alarmed.
	if (protectorMatches.length > 0 && !liveVirus) {
		heuristicFindings = demoteBootCodeHeuristics(heuristicFindings)
		sandboxFindings = demoteSandboxFindings(sandboxFindings)
	}

	const findings: ScanFinding[] = [
		...signatureMatches.map(m => toSignatureFinding(m, boot.length, infectionStatus)),
		...protectorMatches.map(m => toProtectorFinding(m, boot.length)),
		...heuristicFindings.map(h => toHeuristicFinding(h)),
		...sandboxFindings,
	]

	synthesise(findings, signatureMatches, heuristicFindings, boot, protectorMatches)

	const status = computeStatus(
		signatureMatches,
		protectorMatches,
		heuristicFindings,
		sandboxFindings,
		boot,
		executable,
	)

	return {
		fileName,
		format,
		status,
		imageBytes,
		bootSectorChecksum: checksum,
		bootSectorExecutable: executable,
		bootSector: boot.slice(),
		findings,
	}
}

function detectFormat(input: Uint8Array): DiskFormat {
	if (isStx(input)) return 'stx'
	if (input.length >= 2 && readU16BE(input, 0) === MSA_MAGIC) return 'msa'
	if (input.length >= 512) return 'st'
	return 'unknown'
}

function toSignatureFinding(match: SignatureMatch, bootLength: number, infectionStatus: InfectionStatus): ScanFinding {
	const sig = match.signature
	const parts: string[] = []

	const highlightOffsets: number[] = []
	if (match.matched.kind === 'bytes' || match.matched.kind === 'bytes-scan') {
		for (let i = 0; i < match.matched.bytes.length; i++) {
			if (match.offset + i < bootLength) {
				highlightOffsets.push(match.offset + i)
			}
		}
	} else if (match.matched.kind === 'ascii' && match.offset >= 0) {
		for (let i = 0; i < match.matched.text.length; i++) {
			if (match.offset + i < bootLength) {
				highlightOffsets.push(match.offset + i)
			}
		}
	}

	const matchDesc =
		match.matched.kind === 'ascii'
			? `string "${match.matched.text}"`
			: match.matched.kind === 'bytes-scan'
				? `byte sequence at offset 0x${match.offset.toString(16)}`
				: `byte pattern at offset 0x${match.matched.offset.toString(16)}`
	parts.push(`Matched ${matchDesc}.`)
	parts.push(`Assessment: ${infectionLabel(infectionStatus)}.`)
	if (infectionStatus === 'immunized') {
		parts.push(
			`Boot sector is not executable, so this is most likely a clean disk` +
			` vaccinated against ${sig.name} rather than a live infection.`,
		)
	}
	if (sig.payload) parts.push(`Payload: ${sig.payload}`)
	const meta = [
		sig.year && `${sig.year}`,
		sig.origin,
		sig.uvk && `UVK #${sig.uvk}`,
	].filter(Boolean).join(' · ')
	if (meta) parts.push(meta)
	parts.push(`Confidence: ${sig.confidence}.`)
	if (sig.notes) parts.push(sig.notes)

	return {
		kind: 'signature',
		name: sig.name,
		detail: parts.join(' '),
		severity: infectionStatus === 'immunized' ? 'low' : 'high',
		highlightOffsets,
		infectionStatus,
	}
}

function toProtectorFinding(match: ProtectorMatch, bootLength: number): ScanFinding {
	const p = match.protector
	const highlightOffsets: number[] = []
	for (let i = 0; i < match.matched.length; i++) {
		if (match.offset + i < bootLength) highlightOffsets.push(match.offset + i)
	}
	const parts = [
		`Matched string "${match.matched}".`,
		`Known boot protector / antivirus bootblock (${p.family}).`,
		`Executable boot code here is expected — this is not a virus signature.`,
	]
	if (p.notes) parts.push(p.notes)

	return {
		kind: 'protector',
		name: p.name,
		detail: parts.join(' '),
		severity: 'info',
		highlightOffsets,
	}
}

function infectionLabel(status: InfectionStatus): string {
	switch (status) {
		case 'infected':           return 'live infection'
		case 'probably-infected':  return 'probable infection'
		case 'immunized':          return 'immunized (likely clean)'
		case 'unclear':            return 'ambiguous'
	}
}

/**
 * Decide whether a signature match on this disk is an actual infection or
 * an immunization, based on whether the boot sector actually executes
 * code at boot. The principle: a virus must make the boot sector
 * executable (checksum = 0x1234) for TOS to run it. A clean disk
 * vaccinated against a virus carries the virus's identifying bytes
 * WITHOUT making the sector executable.
 */
function computeInfectionStatus(executable: boolean, boot: Uint8Array): InfectionStatus {
	if (!executable) {
		return 'immunized'
	}
	const hasOpcode = startsWith68000Opcode(boot)
	const codeBytes = countNonZeroBytesBeyondBpb(boot)
	// Substantial post-BPB payload is enough for "live infection" even when
	// the entry byte is disguised (Finland starts with $00000000 so TOS still
	// executes, but our opcode list correctly rejects a leading zero).
	if (codeBytes > 16 && (hasOpcode || codeBytes > 64)) {
		return 'infected'
	}
	if (hasOpcode || codeBytes > 4) {
		return 'probably-infected'
	}
	return 'unclear'
}

function demoteBootCodeHeuristics(heuristics: HeuristicFinding[]): HeuristicFinding[] {
	return heuristics.map(h => {
		if (!PROTECTOR_EXPECTED_HEURISTIC_IDS.has(h.id)) return h
		return {
			...h,
			severity: 'info',
			detail:
				h.detail +
				' Consistent with a known boot protector — see protector finding above.',
		}
	})
}

function demoteSandboxFindings(findings: ScanFinding[]): ScanFinding[] {
	return findings.map(f => ({
		...f,
		severity: 'info' as const,
		detail:
			f.detail +
			' Consistent with a known boot protector — see protector finding above.',
	}))
}

/** Turn sandbox side-effects into scan findings. */
export function sandboxToFindings(result: SandboxResult): ScanFinding[] {
	if (!result.ran) return []

	const out: ScanFinding[] = []

	if (result.resetProofMagic || result.resetProofVector) {
		const parts: string[] = []
		if (result.resetProofMagic) {
			parts.push('wrote π ($31415926) to resvalid ($426)')
		}
		if (result.resetProofVector) {
			const rv = result.writes.find(w => w.addr === 0x042a)
			parts.push(
				rv
					? `wrote resvector ($42A) = $${rv.value.toString(16)}`
					: 'wrote resvector ($42A)',
			)
		}
		out.push({
			kind: 'sandbox',
			name: 'Sandbox: reset-proof install',
			detail:
				`While executing the boot sector, the sandbox observed: ${parts.join('; ')}. ` +
				`That is how code stays resident across a warm reset. ` +
				`Ran ${result.instructions} instructions (${result.haltReason}).`,
			severity: 'high',
		})
	}

	if (result.hooks.length > 0) {
		out.push({
			kind: 'sandbox',
			name: 'Sandbox: system vector hook',
			detail:
				`Boot code wrote to ${result.hooks.join(', ')} during sandbox execution ` +
				`(${result.instructions} instructions, ${result.haltReason}). ` +
				`Typical of memory-resident boot viruses (and some protectors / loaders).`,
			severity: 'high',
		})
	}

	if (result.memorySignatures.length > 0) {
		const names = [...new Set(result.memorySignatures.map(h => h.name))]
		const relocated = result.memorySignatures.filter(h => h.windowBase !== 0x4000)
		out.push({
			kind: 'sandbox',
			name: 'Sandbox: signature in RAM',
			detail:
				`After execution, signature material for ${names.join(', ')} was found in ` +
				`sandbox RAM` +
				(relocated.length > 0
					? ` including outside the boot buffer (e.g. $${relocated[0]!.windowBase.toString(16)}) — likely a relocated or decrypted copy.`
					: ` (in-place transform of the boot sector).`) +
				` Ran ${result.instructions} instructions (${result.haltReason}).`,
			severity: 'high',
		})
	}

	return out
}

// Exported for direct unit testing of the family-attribution path.
export const FAMILY_PATTERNS: ReadonlyArray<{ name: string; offset: number; bytes: number[] }> = [
	// Empty on purpose — shared BRA offsets also appear on protectors.
]

/**
 * Post-process findings to draw correlations between heuristics,
 * virus signatures, and protectors. Mutates `findings` in place.
 */
export function synthesise(
	findings: ScanFinding[],
	signatureMatches: SignatureMatch[],
	heuristics: HeuristicFinding[],
	boot: Uint8Array,
	protectorMatches: ProtectorMatch[] = [],
): void {
	if (
		signatureMatches.length === 0 &&
		heuristics.length === 0 &&
		protectorMatches.length === 0
	) return

	const hasBootCodeHeuristic = heuristics.some(h =>
		h.id === 'boot-code-present' || h.id === 'executable-boot-sector',
	)

	const protectorNames = protectorMatches.map(m => m.protector.name)
	const liveSigs = findings.filter(
		f => f.kind === 'signature' && f.infectionStatus !== 'immunized',
	)

	// Virus + protector on the same disk: often a reinfection of a formerly
	// protected bootblock (or a mislabeled archive). Call it out.
	if (liveSigs.length > 0 && protectorNames.length > 0) {
		const note =
			` Also matches known boot protector (${protectorNames.join(', ')})` +
			` — disk may have been reinfected after protection, or the protector` +
			` embeds detection strings.`
		for (const f of liveSigs) f.detail += note
	}

	if (signatureMatches.length > 0 && hasBootCodeHeuristic) {
		for (const f of findings) {
			if (f.kind !== 'signature') continue
			if (f.infectionStatus === 'immunized') continue
			f.detail += ' Confirmed by the executable-boot-sector heuristic.'
		}
		return
	}

	if (signatureMatches.length === 0 && hasBootCodeHeuristic) {
		const families: string[] = []
		for (const fp of FAMILY_PATTERNS) {
			let matches = true
			for (let i = 0; i < fp.bytes.length; i++) {
				if (boot[fp.offset + i] !== fp.bytes[i]) { matches = false; break }
			}
			if (matches) families.push(fp.name)
		}

		const bootCodeFinding = findings.find(f =>
			f.kind === 'heuristic' && (
				f.name === 'Executable boot sector with 68000 entry code' ||
				f.name === 'Executable boot sector' ||
				f.name === 'Executable boot sector with substantial code'
			),
		)
		if (bootCodeFinding && families.length > 0) {
			bootCodeFinding.detail += ` Possible family: ${families.join('; ')}.`
		}
	}
}

function toHeuristicFinding(h: HeuristicFinding): ScanFinding {
	return {
		kind: 'heuristic',
		name: h.headline,
		detail: h.detail,
		severity: h.severity,
		highlightOffsets: h.highlightOffsets,
	}
}

function computeStatus(
	signatures: SignatureMatch[],
	protectors: ProtectorMatch[],
	heuristics: HeuristicFinding[],
	sandboxFindings: ScanFinding[],
	boot: Uint8Array,
	executable: boolean,
): ScanStatus {
	if (signatures.length > 0) {
		const infectionStatus = computeInfectionStatus(executable, boot)
		if (infectionStatus !== 'immunized') {
			return 'infected'
		}
	}
	if (protectors.length > 0) {
		return 'protected'
	}
	const hasHigh =
		heuristics.some(h => h.severity === 'high') ||
		sandboxFindings.some(f => f.severity === 'high')
	const hasMedium =
		heuristics.some(h => h.severity === 'medium') ||
		sandboxFindings.some(f => f.severity === 'medium')
	if (hasHigh || hasMedium) return 'suspicious'
	return 'clean'
}
