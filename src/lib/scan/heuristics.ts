import {
	isBootSectorExecutable,
	startsWith68000Opcode,
	countNonZeroBytesBeyondBpb,
	hasSaneGeometry,
	hasSaneMediaDescriptor,
	mediaDescriptor,
	BOOT_CODE_REGION_START,
	BOOT_CODE_REGION_END,
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
	/**
	 * Offsets within the boot sector that this finding concerns. The hex
	 * viewer highlights these when present. Optional — some findings are
	 * whole-sector properties.
	 */
	highlightOffsets?: number[]
}

/** Heuristic IDs that known boot protectors also trigger — demoted when a protector matches. */
export const PROTECTOR_EXPECTED_HEURISTIC_IDS: ReadonlySet<string> = new Set([
	'boot-code-present',
	'executable-boot-sector',
	'resvalid-magic',
	'resvalid-write',
	'resvector-write',
	'trap-vector-install',
	'hdv-vector-install',
	'high-entropy-boot',
])

/** π magic longword written to resvalid ($426) by Ghost and several reset-proof viruses. */
const RESVALID_MAGIC = [0x31, 0x41, 0x59, 0x26] as const

/** System vector addresses commonly hooked by resident / reset-proof boot code. */
const TRAP_VECTORS = [
	{ addr: 0x0084, name: 'Trap #1 (GEMDOS)' },
	{ addr: 0x00b4, name: 'Trap #13 (BIOS)' },
	{ addr: 0x00b8, name: 'Trap #14 (XBIOS)' },
] as const

const HDV_VECTORS = [
	{ addr: 0x0472, name: 'hdv_bpb' },
	{ addr: 0x0476, name: 'hdv_rw' },
	{ addr: 0x047a, name: 'hdv_boot' },
	{ addr: 0x047e, name: 'hdv_mediach' },
] as const

const RESVALID_ADDR = 0x0426
const RESVECTOR_ADDR = 0x042a

/** Min non-zero post-BPB bytes before high-entropy is worth reporting. */
const ENTROPY_MIN_NONZERO = 128
/** Shannon entropy (bits/byte) over the code region — encrypted/packed-looking. */
const ENTROPY_THRESHOLD = 7.0

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
			highlightOffsets: [0],
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
			highlightOffsets: [0],
		})
	}

	const resvalidOffset = findBytes(boot, RESVALID_MAGIC)
	if (resvalidOffset !== -1) {
		// Bare π appears in Anti-Ghost bootblocks as a CMP immediate (they
		// look for Ghost). Only treat it as high severity when Ghost's own
		// MOVE.L #$31415926,D0 write is also present.
		const ghostWrite = findBytes(boot, [0x20, 0x3c, 0x31, 0x41, 0x59, 0x26])
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
			highlightOffsets: [resvalidOffset, resvalidOffset + 1, resvalidOffset + 2, resvalidOffset + 3],
		})
	}

	// Residency / reset-proof install patterns — only meaningful if TOS would run
	// the sector. Protectors hook the same vectors; the scanner demotes these
	// when a known protector matches.
	if (executable) {
		const resvalidWrites = findMoveLStoresTo(boot, RESVALID_ADDR)
		if (resvalidWrites.length > 0) {
			findings.push({
				id: 'resvalid-write',
				headline: 'Writes to resvalid ($426)',
				detail:
					`Found a MOVE.L store to resvalid at offset 0x${resvalidWrites[0]!.toString(16)}. ` +
					`Reset-proof boot viruses set this (usually to π / $31415926) so their ` +
					`handler survives a warm reset. Hard-disk drivers and some protectors ` +
					`do the same — correlate with other findings.`,
				severity: 'high',
				highlightOffsets: expandOpcodeHits(resvalidWrites, 4),
			})
		}

		const resvectorWrites = findMoveLStoresTo(boot, RESVECTOR_ADDR)
		if (resvectorWrites.length > 0) {
			findings.push({
				id: 'resvector-write',
				headline: 'Writes to resvector ($42A)',
				detail:
					`Found a MOVE.L store to resvector at offset 0x${resvectorWrites[0]!.toString(16)}. ` +
					`Together with a valid resvalid, this is how code stays in memory across ` +
					`a warm reset. Classic reset-proof boot viruses install their handler here.`,
				severity: 'high',
				highlightOffsets: expandOpcodeHits(resvectorWrites, 4),
			})
		}

		const trapHits = findVectorInstalls(boot, TRAP_VECTORS)
		if (trapHits.length > 0) {
			const names = unique(trapHits.map(h => h.name)).join(', ')
			findings.push({
				id: 'trap-vector-install',
				headline: 'Installs trap handler',
				detail:
					`Found MOVE.L store(s) to ${names}. Boot viruses typically hook GEMDOS/BIOS/XBIOS ` +
					`traps so they stay resident after boot and can infect disks on later access. ` +
					`Antivirus bootblocks hook traps too — not proof of infection on its own.`,
				severity: 'high',
				highlightOffsets: expandOpcodeHits(trapHits.map(h => h.offset), 4),
			})
		}

		const hdvHits = findVectorInstalls(boot, HDV_VECTORS)
		if (hdvHits.length > 0) {
			const names = unique(hdvHits.map(h => h.name)).join(', ')
			findings.push({
				id: 'hdv-vector-install',
				headline: 'Installs disk (hdv_*) handler',
				detail:
					`Found MOVE.L store(s) to ${names}. These TOS disk vectors are a common ` +
					`residency hook for boot viruses (infect-on-access). Legitimate boot ` +
					`loaders and protectors also use them.`,
				severity: 'high',
				highlightOffsets: expandOpcodeHits(hdvHits.map(h => h.offset), 4),
			})
		}

		if (nonZeroBeyondBpb >= ENTROPY_MIN_NONZERO) {
			const entropy = shannonEntropy(boot, BOOT_CODE_REGION_START, BOOT_CODE_REGION_END)
			if (entropy >= ENTROPY_THRESHOLD) {
				findings.push({
					id: 'high-entropy-boot',
					headline: 'High-entropy executable boot payload',
					detail:
						`The post-BPB region looks densely packed/random (Shannon entropy ` +
						`${entropy.toFixed(2)} bits/byte over ${nonZeroBeyondBpb} non-zero bytes). ` +
						`That can mean an encrypted or polymorphic boot virus — or commercial ` +
						`game copy-protection that decrypts a loader at boot. Manual inspection ` +
						`or a known-protector match is needed to tell which.`,
					severity: 'medium',
					highlightOffsets: [BOOT_CODE_REGION_START],
				})
			}
		}
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
			highlightOffsets: [0x15],
		})
	}

	return findings.sort(bySeverity)
}

/**
 * Shannon entropy in bits/byte for boot[start..end). Exported for unit tests.
 */
export function shannonEntropy(boot: Uint8Array, start: number, end: number): number {
	const len = end - start
	if (len <= 0) return 0
	const freq = new Array<number>(256).fill(0)
	for (let i = start; i < end; i++) freq[boot[i]!]++
	let h = 0
	for (const c of freq) {
		if (c === 0) continue
		const p = c / len
		h -= p * Math.log2(p)
	}
	return h
}

/**
 * Find MOVE.L stores targeting an absolute address (Abs.W or Abs.L form).
 * Covers the common 68000 encodings ST boot viruses use to install handlers.
 * Exported for unit tests.
 */
export function findMoveLStoresTo(boot: Uint8Array, addr: number): number[] {
	const hits: number[] = []
	const ah = (addr >> 8) & 0xff
	const al = addr & 0xff
	const limit = Math.min(boot.length, 0x1fe)

	for (let i = 0; i + 4 <= limit; i++) {
		const b0 = boot[i]!
		const b1 = boot[i + 1]!

		// MOVE.L Dn/An, Abs.W (21C0–21CF)
		if (b0 === 0x21 && b1 >= 0xc0 && b1 <= 0xcf) {
			if (boot[i + 2] === ah && boot[i + 3] === al) hits.push(i)
			continue
		}
		// MOVE.L (An) / (An)+ / -(An), Abs.W (21D0–21E7)
		if (b0 === 0x21 && b1 >= 0xd0 && b1 <= 0xe7) {
			if (boot[i + 2] === ah && boot[i + 3] === al) hits.push(i)
			continue
		}
		// MOVE.L #imm, Abs.W (21FC imm.L abs.W)
		if (b0 === 0x21 && b1 === 0xfc && i + 8 <= limit) {
			if (boot[i + 6] === ah && boot[i + 7] === al) hits.push(i)
			continue
		}
		// MOVE.L Dn/An, Abs.L (23C0–23CF + addr.L)
		if (b0 === 0x23 && b1 >= 0xc0 && b1 <= 0xcf && i + 6 <= limit) {
			if (
				boot[i + 2] === 0x00 &&
				boot[i + 3] === 0x00 &&
				boot[i + 4] === ah &&
				boot[i + 5] === al
			) {
				hits.push(i)
			}
			continue
		}
		// MOVE.L #imm, Abs.L (23FC imm.L abs.L)
		if (b0 === 0x23 && b1 === 0xfc && i + 10 <= limit) {
			if (
				boot[i + 6] === 0x00 &&
				boot[i + 7] === 0x00 &&
				boot[i + 8] === ah &&
				boot[i + 9] === al
			) {
				hits.push(i)
			}
		}
	}
	return hits
}

function findVectorInstalls(
	boot: Uint8Array,
	vectors: ReadonlyArray<{ addr: number; name: string }>,
): Array<{ offset: number; name: string }> {
	const hits: Array<{ offset: number; name: string }> = []
	for (const v of vectors) {
		for (const offset of findMoveLStoresTo(boot, v.addr)) {
			hits.push({ offset, name: v.name })
		}
	}
	return hits
}

function expandOpcodeHits(offsets: number[], byteLen: number): number[] {
	const out: number[] = []
	for (const o of offsets) {
		for (let i = 0; i < byteLen; i++) out.push(o + i)
	}
	return out
}

function unique(values: string[]): string[] {
	return [...new Set(values)]
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
