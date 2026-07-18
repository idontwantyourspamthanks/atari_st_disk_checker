import {
	isBootSectorExecutable,
	startsWith68000Opcode,
	countNonZeroBytesBeyondBpb,
	hasSaneGeometry,
	hasSaneMediaDescriptor,
	mediaDescriptor,
} from './bootSector'

export type Severity = 'info' | 'low' | 'medium' | 'high'

export interface HeuristicFinding {
	/** Stable identifier — used as React key / dedup token. */
	id: string
	/** Short human-readable headline, e.g. "Executable boot sector". */
	headline: string
	/** Long-form explanation shown when expanded. */
	detail: string
	severity: Severity
}

/** π magic longword written to resvalid ($426) by Ghost and several reset-proof viruses. */
const RESVALID_MAGIC = [0x31, 0x41, 0x59, 0x26] as const

/**
 * Run every heuristic against a boot sector. Heuristics are deliberately
 * the primary detector: they catch unknown boot-sector viruses (and any
 * variant) by behaviour rather than by signature. The signature DB only
 * names a virus after the heuristics have flagged it.
 *
 * Returns findings in order of decreasing severity. Empty array = "no
 * notable features".
 */
export function runHeuristics(boot: Uint8Array): HeuristicFinding[] {
	const findings: HeuristicFinding[] = []

	const executable = isBootSectorExecutable(boot)
	const opcodeAtStart = startsWith68000Opcode(boot)
	const nonZeroBeyondBpb = countNonZeroBytesBeyondBpb(boot)
	const saneGeometry = hasSaneGeometry(boot)
	const saneMedia = hasSaneMediaDescriptor(boot)

	// Executable + (recognised entry opcode OR a real post-BPB payload) is
	// the strongest behavioural signal. TOS would jump to offset 0 on boot.
	// A vanilla data disk never looks like this.
	//
	// Code density matters on its own: variants like Ghost H replace BRA
	// with BLS (still recognised) or disguise the entry byte entirely
	// (Wolf's $EB34). Requiring a known opcode alone would downgrade those
	// to medium and miss the point — if it boots and has a body, flag it.
	const CODE_DENSITY_HIGH = 16
	if (executable && (opcodeAtStart || nonZeroBeyondBpb >= CODE_DENSITY_HIGH)) {
		const entry = opcodeAtStart
			? 'begins with a 68000 entry opcode'
			: `has ${nonZeroBeyondBpb} non-zero bytes beyond the BPB despite an unrecognised entry byte (0x${boot[0]!.toString(16).padStart(2, '0')})`
		findings.push({
			id: 'boot-code-present',
			headline: opcodeAtStart
				? 'Executable boot sector with 68000 entry code'
				: 'Executable boot sector with substantial code',
			detail:
				`The boot sector's checksum validates to 0x1234 (TOS would execute it) ` +
				`and it ${entry}. There are ${nonZeroBeyondBpb} non-zero bytes of code/data ` +
				`beyond the BPB. A data disk should not look like this; a bootable TOS ` +
				`disk might, so cross-reference with the disk's intended use.`,
			severity: 'high',
		})
	} else if (executable) {
		// Checksum validates but little/no payload and no recognised entry —
		// unusual; worth surfacing without treating it as a full infection.
		findings.push({
			id: 'executable-boot-sector',
			headline: 'Executable boot sector',
			detail:
				`The boot sector's 256-word checksum equals 0x1234, so TOS would treat ` +
				`this disk as bootable and jump to offset 0, but there is little code ` +
				`beyond the BPB (${nonZeroBeyondBpb} non-zero bytes). If this is supposed ` +
				`to be a data disk, an executable boot sector is still suspicious.`,
			severity: 'medium',
		})
	}

	const resvalidOffset = findBytes(boot, RESVALID_MAGIC)
	if (resvalidOffset !== -1) {
		// Bare π appears in Anti-Ghost bootblocks as a CMP immediate (they
		// look for Ghost). Only treat it as high severity when Ghost's own
		// MOVE.L #$31415926,D0 write is also present.
		const ghostWrite = findBytes(boot, [0x20, 0x3C, 0x31, 0x41, 0x59, 0x26])
		findings.push({
			id: 'resvalid-magic',
			headline: 'Reset-proof magic longword ($31415926)',
			detail:
				`Found π ($31415926) at offset 0x${resvalidOffset.toString(16)} — used by ` +
				`Ghost and several reset-proof boot viruses for resvalid, but also embedded ` +
				`in Anti-Ghost / protector bootblocks that scan for it` +
				(ghostWrite !== -1
					? `. This sector also contains Ghost's MOVE.L #π,D0 write — strong live-Ghost signal.`
					: `. Without Ghost's MOVE.L #π,D0 this is usually a detector, not an infection.`),
			severity: ghostWrite !== -1 && executable ? 'high' : 'medium',
		})
	}

	if (!saneGeometry) {
		findings.push({
			id: 'odd-geometry',
			headline: 'BPB geometry looks unusual',
			detail:
				`Bytes-per-sector, sectors-per-cluster, or sectors-per-FAT has a value ` +
				`outside the plausible range for a real floppy. This can be a malformed ` +
				`image, an all-zero boot sector on a freshly-erased disk, or a virus ` +
				`deliberately corrupting the BPB to confuse scanners.`,
			severity: 'low',
		})
	}

	if (!saneMedia) {
		findings.push({
			id: 'odd-media-descriptor',
			headline: `Unusual media descriptor (0x${mediaDescriptor(boot).toString(16).padStart(2, '0')})`,
			detail:
				`The media descriptor byte at BPB offset 0x15 is not one of the standard ` +
				`FAT12 values (0xF0–0xFF). Real ST floppies are usually 0xFD (DSDD) or ` +
				`0xF9 (DSHD). A weird value here is sometimes a deliberate fingerprint.`,
			severity: 'low',
		})
	}

	return findings.sort(bySeverity)
}

function findBytes(haystack: Uint8Array, needle: readonly number[]): number {
	outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
		for (let j = 0; j < needle.length; j++) {
			if (haystack[i + j] !== needle[j]) continue outer
		}
		return i
	}
	return -1
}

function bySeverity(a: HeuristicFinding, b: HeuristicFinding): number {
	const order: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 }
	return order[a.severity] - order[b.severity]
}
