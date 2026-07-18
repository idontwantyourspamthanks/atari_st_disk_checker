/**
 * Atari ST boot-sector virus signature database.
 *
 * Sources (both excellent, cross-referenced where possible):
 *
 *   - Ultimate Virus Killer 2000 (UVK), Richard Karsmakers et al.
 *     https://www.exxosforum.co.uk/atari/mirror/UVK2000/viruses.htm
 *     The canonical reference. Each virus has a UVK catalogue number,
 *     included here as `uvk` for traceability.
 *
 *   - Retro-virology: Atari ST Museum of Malware
 *     https://www.retrovirology.ca/viruses_gallery.html
 *
 * DETECTION MODEL
 *
 * Each signature carries one or more `patterns`. The matcher fires a match
 * if ANY pattern in the list matches. Prefer distinctive payload strings
 * and magic constants over UVK "immunization" bytes: those markers are
 * often just a short BRA over the BPB (e.g. `0x60 0x1C`) shared by many
 * viruses *and* by unrelated boot loaders. Using them as positive IDs
 * produces false INFECTED hits (Ghost famously starts with that BRA and
 * also happens to contain Gotcha's `$1E.L $263C0000` immunization word —
 * ordinary `MOVE.L #0,D3` right after the BPB).
 *
 * When UVK only documents a too-broad immunization pattern, leave
 * `patterns` empty (heuristic-only), same approach as Mad A.
 *
 * CONFIDENCE LEVELS
 *
 *   verified    — pattern comes straight from UVK immunization data, with
 *                  corroboration. Trust the match.
 *   probable    — distinctive payload string reported by UVK / retrovirology,
 *                  but not the virus's primary identifier.
 *   speculative — pattern inferred from secondary sources; treat as hint.
 */

export type BytePattern = {
	kind: 'bytes'
	/** Offset within the 512-byte boot sector. */
	offset: number
	/** Raw byte sequence to match at the offset. */
	bytes: number[]
}

export type AsciiPattern = {
	kind: 'ascii'
	/** Substring to find anywhere in the boot sector (case-insensitive). */
	text: string
}

export type BytesScanPattern = {
	kind: 'bytes-scan'
	/** Raw byte sequence to find anywhere in the boot sector. */
	bytes: number[]
}

export type Pattern = BytePattern | AsciiPattern | BytesScanPattern

export type Confidence = 'verified' | 'probable' | 'speculative'

export interface Signature {
	/** Canonical name, including variant letter (e.g. "Signum A"). */
	name: string
	/** Family for grouping variants in the UI (e.g. "Signum", "Ghost"). */
	family: string
	/** UVK catalogue number, when known. */
	uvk?: number
	/** Year first reported. */
	year?: number
	/** Country of origin if documented. */
	origin?: string
	/** One-line payload description. */
	payload?: string
	/** Detection patterns — see `match`. */
	patterns: Pattern[]
	/**
	 * How to combine `patterns`:
	 *   'any' (default) — first matching pattern wins
	 *   'all' — every pattern must match (use for short immunization
	 *           bytes that only become distinctive with a second check)
	 */
	match?: 'any' | 'all'
	confidence: Confidence
	/** Attribution and notes for the curious. */
	notes?: string
}

const w = (...bytes: number[]) => bytes

export const SIGNATURES: readonly Signature[] = Object.freeze([
	// ── Signum / BPL family — the most widely-spread ST virus ever ──────────
	{
		name: 'Signum A', family: 'Signum', uvk: 1, year: 1987,
		origin: 'Netherlands',
		payload: 'Dormant — payload never observed in the wild',
		// UVK immunization is only 0.W $6038 — BRA.B $38 over the BPB, also
		// used by Sagrotan, FCopy Pro, UVK, and countless "virus free"
		// bootblocks. Require the live Signum body entry at $3A as well.
		patterns: [
			{ kind: 'bytes', offset: 0, bytes: w(0x60, 0x38) },
			{ kind: 'bytes', offset: 0x3A, bytes: w(0x41, 0xFA, 0xFF, 0xC4) },
		],
		match: 'all',
		confidence: 'verified',
		notes:
			'AKA Emil 1A, Key Virus, BPL. Estimated 1.5M+ copies worldwide — by far ' +
			'the most successful ST boot virus. Same family as DJA.',
	},
	{
		name: 'Signum D', family: 'Signum', uvk: 66, year: 1992,
		payload: 'Optimised Signum variant, same behaviour',
		patterns: [{ kind: 'bytes', offset: 2, bytes: w(0x07, 0xC4) }],
		confidence: 'verified',
		notes: 'UVK could not immunize against this one — different branch offset.',
	},
	{
		name: 'DJA', family: 'Signum', uvk: 45, year: 1990,
		origin: 'Scandinavia',
		payload: 'Locks system, prints infection message in a Scandinavian language',
		patterns: [
			// Dropped shared BRA.B $38 — identify by payload text only.
			{ kind: 'ascii', text: 'DJA viruset' },
		],
		confidence: 'verified',
		notes: 'Offshoot of Signum; shares Signum\'s BRA.B $38 but that alone is not distinctive.',
	},

	// ── Ghost family — British, mouse-inverting, very widely spread ────────
	{
		name: 'Ghost A', family: 'Ghost', uvk: 12, year: 1988,
		origin: 'England',
		payload: 'Inverts mouse Y-axis after 10 copies',
		patterns: [
			// MOVE.L #$31415926,D0 — Ghost's own write of π to prepare
			// resvalid. Anti-Ghost bootblocks embed bare $31415926 for
			// CMP/CMPI and often the ASCII word "GHOST" in messages — neither
			// alone is a live infection. (UVK: not immunizable.)
			{ kind: 'bytes-scan', bytes: w(0x20, 0x3C, 0x31, 0x41, 0x59, 0x26) },
		],
		confidence: 'verified',
		notes:
			'AKA Mouse Virus, Inversion Virus. Reset-proof, widespread across NW Europe. ' +
			'Starts with BRA.B $1C over the BPB — do not confuse with Lazy Lion immunization.',
	},
	{
		name: 'Finland', family: 'Finland', uvk: 55, year: 1990,
		origin: 'Scandinavia',
		payload: 'Reverses desktop green/white colours after every 12th copy',
		patterns: [
			// Deliberately starts with a zero longword so BRA-at-0 scanners
			// (and early UVK) miss it, then BRA.B $18 at offset 4.
			{ kind: 'bytes', offset: 0, bytes: w(0x00, 0x00, 0x00, 0x00, 0x60, 0x18) },
			// Author credit embedded in the boot sector.
			{ kind: 'ascii', text: 'Coding: Toubab' },
		],
		// Leading zeros alone could theoretically collide; require both the
		// disguise entry AND the Toubab credit (Pure Energy reuses the credit
		// string but starts with a normal BRA.B $1C).
		match: 'all',
		confidence: 'verified',
		notes:
			'By Toubab, 30 Aug 1990. Reset-proof. UVK #55 noted the leading ' +
			'$00000000 made it invisible to scanners that only checked offset 0 for a branch.',
	},

	// ── Mad family — also very common, screen+sound payload ────────────────
	{
		name: 'Mad A', family: 'Mad', uvk: 2, year: 1988,
		payload: 'Screen effects + sound chip bleeps after 5 copies',
		patterns: [], // UVK immunization is just "0.B $60" — a single BRA opcode
		// byte shared with countless legitimate boot sectors. Too broad to
		// use as a signature. Detect via heuristics instead.
		confidence: 'speculative',
		notes: 'AKA Emil 2A. No distinctive signature — heuristic-only detection.',
	},

	// ── Maulwurf / Caterpillar ─────────────────────────────────────────────
	{
		name: 'Maulwurf I B (English TOS)', family: 'Maulwurf', uvk: 8, year: 1988,
		origin: 'Germany',
		payload: 'Prints "Maulwurf I - SSG (Subversive Software Group)" and locks up',
		patterns: [
			{ kind: 'ascii', text: 'Maulwurf' },
			{ kind: 'ascii', text: 'SSG' },
		],
		confidence: 'probable',
		notes: 'By the Subversive Software Group. AKA Caterpillar in English.',
	},

	// ── ACA — destructive, Swedish ─────────────────────────────────────────
	{
		name: 'ACA', family: 'ACA', uvk: 4, year: 1988,
		origin: 'Sweden',
		payload: 'Wipes track 0 (BPB, bootsector, FAT) after 10 copies — data lost',
		patterns: [
			// UVK offers two immunization alternatives: 0.B $60 (too broad —
			// shared with every legitimate BRA-based boot sector) or 4.W $4143
			// (the literal letters "AC" at offset 4). We use only the latter.
			{ kind: 'bytes', offset: 4, bytes: w(0x41, 0x43) }, // "AC"
		],
		confidence: 'verified',
		notes: 'By the Anti Copyright Association, Sweden. Reset-proof and destructive.',
	},

	// ── Norwegian wave — all by "The Lazy Lion", Dec 1989 ──────────────────
	{
		name: 'Chopin', family: 'Lazy Lion', uvk: 31, year: 1989,
		origin: 'Norway',
		payload: 'Endless Chopin funeral march + "FUCK! YOU\'VE GOT A VIRUS!"',
		patterns: [{ kind: 'ascii', text: "FUCK! YOU'VE GOT A VIRUS" }],
		confidence: 'verified',
	},
	{
		name: 'Cookie Monster A', family: 'Lazy Lion', uvk: 32, year: 1989,
		origin: 'Norway',
		payload: 'Demands you type "COOKIE" before continuing',
		patterns: [{ kind: 'ascii', text: 'I WANT A COOKIE' }],
		confidence: 'verified',
	},
	{
		name: 'Puke A', family: 'Lazy Lion', uvk: 34, year: 1989,
		origin: 'Norway',
		payload: 'Deletes first file from current floppy',
		// UVK immunization is only 0.W $601C — BRA.B $1C over the BPB, also
		// used by Ghost and many legitimate boot loaders. Too broad for ID.
		patterns: [],
		confidence: 'speculative',
		notes: 'Heuristic-only: UVK marker shared with Upside Down / Anti-ACA / Ghost.',
	},
	{
		name: 'Puke B', family: 'Lazy Lion', uvk: 35, year: 1989,
		origin: 'Norway',
		payload: 'Writes screen memory to track 1 — corrupts disk',
		// UVK immunization 19E.L $70756B65 ("puke") is planted on UVK/AVK
		// "new method" immunization bootblocks that are themselves executable.
		// No distinctive live-infection string beyond that marker — heuristic-only.
		patterns: [],
		confidence: 'speculative',
		notes: 'Heuristic-only: UVK marker "puke" at $19E is shared with immunization farms.',
	},
	{
		name: 'Upside Down', family: 'Lazy Lion', uvk: 36, year: 1989,
		origin: 'Norway',
		payload: 'Screen turns upside down after 4 copies',
		patterns: [], // same too-broad 0.W $601C as Puke A
		confidence: 'speculative',
		notes: 'Heuristic-only: UVK marker is BRA.B $1C, not unique to this virus.',
	},
	{
		name: 'Anti-ACA', family: 'Lazy Lion', uvk: 30, year: 1989,
		origin: 'Norway',
		payload: 'Prints greeting to ACA then crashes',
		patterns: [
			// Dropped 0.W $601C — see Puke A. Identify by payload text only.
			{ kind: 'ascii', text: 'GREETINGS TO ACA' },
		],
		confidence: 'verified',
	},

	// ── German / central European viruses ──────────────────────────────────
	{
		name: 'C\'T', family: 'CT', uvk: 7, year: 1988,
		origin: 'Germany',
		payload: 'Deletes FAT of floppy AND hard disk if date stamp is 1987',
		patterns: [{ kind: 'ascii', text: 'Diskvirus' }],
		confidence: 'verified',
		notes: 'Published in Computer & Technik magazine. Carries "ARRRGGGHHH" message.',
	},
	{
		name: 'Kobold 2 A', family: 'Kobold', uvk: 16, year: 1989,
		origin: 'Germany',
		payload: 'Distorts mouse UP/LEFT; prints "KOBOLD#2 AKTIV!"',
		patterns: [{ kind: 'ascii', text: 'KOBOLD#2 AKTIV' }],
		confidence: 'verified',
	},
	{
		name: 'Kobold 2 B', family: 'Kobold', uvk: 86, year: 1991,
		origin: 'Balkan',
		payload: 'Prints "I LOVE JADRANKA" at install',
		patterns: [{ kind: 'ascii', text: 'I LOVE JADRANKA' }],
		confidence: 'verified',
	},
	{
		name: 'Gauweiler', family: 'Gauweiler', uvk: 24, year: 1989,
		origin: 'Germany',
		payload: 'Writes "AIDS?" and zeroes track 1',
		patterns: [{ kind: 'ascii', text: 'AIDS?' }],
		confidence: 'verified',
	},
	{
		name: 'Reset', family: 'Reset', uvk: 48, year: 1988,
		payload: 'Prints "Ihr Rechner hat Aids" and freezes after 3 hours',
		patterns: [{ kind: 'ascii', text: 'Ihr Rechner hat Aids' }],
		confidence: 'verified',
	},
	{
		name: 'Beilstein', family: 'Beilstein', uvk: 71, year: 1993,
		origin: 'Germany',
		payload: '12+ payloads including disk wipe, RAM clear, password lock ("Apokalypse")',
		patterns: [{ kind: 'ascii', text: 'Apokalypse' }],
		confidence: 'probable',
		notes: 'Nastiest known ST boot virus. ~650k polymorphic variants possible.',
	},

	// ── British / English-language viruses ────────────────────────────────
	{
		name: 'Evil (Old Nick)', family: 'Evil', uvk: 25, year: 1989,
		origin: 'England',
		payload: 'Inverts screen colours after 100 copies',
		patterns: [
			// UVK: 0.L $60380666
			{ kind: 'bytes', offset: 0, bytes: w(0x60, 0x38, 0x06, 0x66) },
			{ kind: 'ascii', text: 'A Gift from Old Nick' },
		],
		confidence: 'verified',
	},
	{
		name: 'Goblin', family: 'Goblin', uvk: 19, year: 1989,
		origin: 'England',
		payload: '"The Green Goblins Strike Again" after 128 copies',
		patterns: [
			// Dropped UVK 1A2.L $27182818 (e) — planted on AVK immunization
			// bootblocks. Identify by payload text only.
			{ kind: 'ascii', text: 'Green Goblins' },
		],
		confidence: 'verified',
	},
	{
		name: 'P.M.S. (Pirate Trap)', family: 'PMS', uvk: 26, year: 1989,
		payload: '"*** The Pirate Trap ***" every 50 copies',
		patterns: [
			// Dropped UVK 1B4.L $2A2A2A20 — "*** " is planted by AVK and
			// appears in unrelated boot art (Sagrotan asterisks).
			{ kind: 'ascii', text: 'Pirate Trap' },
		],
		confidence: 'verified',
		notes: 'Possibly written by a software vendor to deter in-shop copying.',
	},
	{
		name: 'Pashley', family: 'Pashley', uvk: 82, year: 1993,
		origin: 'England',
		payload: 'Red screen flash on boot',
		patterns: [{ kind: 'ascii', text: 'VIRUS KILLED BY S.C.PASHLEY' }],
		confidence: 'verified',
	},
	{
		name: 'Grim Reaper', family: 'Grim Reaper', uvk: 42, year: 1990,
		payload: 'Screen garbage, then writes screen memory to first 20 sectors',
		patterns: [
			{ kind: 'ascii', text: 'The Jumper strikes again' },
			{ kind: 'ascii', text: 'grim reaper' },
		],
		confidence: 'verified',
	},

	// ── Italian / Slovenian / French ───────────────────────────────────────
	{
		name: 'Megaguru & Argo 2', family: 'Megaguru', uvk: 53, year: 1991,
		origin: 'Italy',
		payload: 'Boots with a software-swapping hacker advert',
		patterns: [{ kind: 'ascii', text: 'MEGAGURU & ARGO 2' }],
		confidence: 'verified',
	},
	{
		name: 'Flying Chimp (Waldo)', family: 'Flying Chimp', uvk: 47, year: 1990,
		origin: 'USA',
		payload: '"Zapped by Waldo the Flying Chimp!"',
		patterns: [{ kind: 'ascii', text: 'Waldo the Flying Chimp' }],
		confidence: 'verified',
	},
	{
		name: 'Lucky Lady 1.02', family: 'Lucky Lady', uvk: 77, year: 1994,
		origin: 'Slovenia',
		payload: '"Lucky Lady rules forever!" locks the system',
		patterns: [{ kind: 'ascii', text: 'Lucky Lady rules' }],
		confidence: 'verified',
	},
	{
		name: 'Lucky Lady 4.12', family: 'Lucky Lady', uvk: 78, year: 1994,
		origin: 'Slovenia',
		payload: 'Targets UVK specifically — erases the antivirus, corrupts clusters',
		patterns: [{ kind: 'ascii', text: 'Lucky Lady forbids' }],
		confidence: 'verified',
	},
	{
		name: 'Anaconda A', family: 'Anaconda', uvk: 79, year: 1994,
		origin: 'France',
		payload: 'Attempts to print "MAUI viens de vous niquer"',
		patterns: [{ kind: 'ascii', text: 'MAUI' }],
		confidence: 'speculative',
		notes: 'Believed written by the Replicants cracking group.',
	},
	{
		name: 'Anaconda B (Ako Pads)', family: 'Anaconda', uvk: 81, year: 1994,
		payload: 'Prints "AKO-PADS" and corrupts disks it copies to',
		patterns: [{ kind: 'ascii', text: 'AKO-PADS' }],
		confidence: 'verified',
	},

	// ── Dutch anti-viruses-gone-wrong ──────────────────────────────────────
	{
		name: 'Zorro A', family: 'Zorro', uvk: 67, year: 1992,
		origin: 'Netherlands',
		payload: 'System lock-up; polymorphic (each copy differs)',
		patterns: [], // No usable signature — fakes MS-DOS boot sector
		confidence: 'speculative',
		notes: 'Polymorphic; mimics MS-DOS bootsector to evade virus killers.',
	},
	{
		name: 'Macumba 3.3', family: 'Macumba', uvk: 69, year: 1993,
		origin: 'Netherlands',
		payload: 'Total system freeze after 42 copies',
		patterns: [],
		confidence: 'speculative',
	},
	{
		name: 'Macumba 5.2', family: 'Macumba', uvk: 88, year: 1994,
		origin: 'Netherlands',
		payload: 'Probably a crash, exact trigger unknown',
		patterns: [
			// UVK: 0.L $EB909047
			{ kind: 'bytes', offset: 0, bytes: w(0xEB, 0x90, 0x90, 0x47) },
		],
		confidence: 'verified',
	},
	{
		name: 'Zoch', family: 'Zoch', uvk: 68, year: 1992,
		payload: '"The Night Force Virus Breaker by Zoch" — written as anti-virus but destroys other bootsectors',
		patterns: [
			// UVK: 0.L $5A4F4348 ("ZOCH")
			{ kind: 'bytes', offset: 0, bytes: w(0x5A, 0x4F, 0x43, 0x48) },
			{ kind: 'ascii', text: 'Night Force Virus Breaker' },
		],
		confidence: 'verified',
	},
	{
		name: 'Pharaoh (Curse)', family: 'Pharaoh', uvk: 94, year: 1996,
		origin: 'Netherlands',
		payload: 'High-frequency sound + noise after 5 copies',
		patterns: [],
		confidence: 'speculative',
		notes: 'MS-DOS-mimicking, Falcon-compatible. ~5×10^23 polymorphic variants.',
	},

	// ── Lone distinctive ones ──────────────────────────────────────────────
	{
		name: 'OLI', family: 'OLI', uvk: 14, year: 1988,
		payload: '"OLI-VIRUS installed." then slows the system',
		patterns: [{ kind: 'ascii', text: 'OLI-VIRUS' }],
		confidence: 'verified',
	},
	{
		name: 'Wolf', family: 'Wolf', uvk: 61, year: 1991,
		payload: 'Halves reported RAM after 8 generations',
		patterns: [
			// Dropped 0.W $EB34 — identical to an MS-DOS short JMP and shows
			// up on IBM/PC-formatted "other" disks as a false immunization hit.
			{ kind: 'ascii', text: 'Kein Virus im bootsector' },
		],
		confidence: 'verified',
		notes: 'Disguises itself as a Sagrotan antivirus boot sector.',
	},
	{
		name: 'Joe (Cannibal)', family: 'Joe', uvk: 58, year: 1991,
		payload: 'Crashes when it encounters itself',
		patterns: [
			// UVK: 0.W $4E71 — a 68000 NOP
			{ kind: 'bytes', offset: 0, bytes: w(0x4E, 0x71) },
		],
		confidence: 'verified',
	},
	{
		name: 'Gotcha Xeno', family: 'Gotcha', uvk: 83, year: 1994,
		payload: 'Writes "GOTCHA!" garbage to random tracks',
		patterns: [
			// UVK immunization $1E.L $263C0000 is MOVE.L #0,D3 — ordinary 68000
			// that Ghost (and other BRA.B $1C boots) also place right after the
			// BPB. Identify by the payload string only.
			{ kind: 'ascii', text: 'GOTCHA' },
		],
		confidence: 'verified',
	},
	{
		name: 'Vaccin-Gillus', family: 'Vaccin-Gillus', uvk: 89, year: 1994,
		payload: 'Wobbly colour bars + "VACCIN-GILLUS"',
		patterns: [{ kind: 'ascii', text: 'VACCIN-GILLUS' }],
		confidence: 'verified',
	},
	{
		name: 'G-DATA', family: 'G-DATA', uvk: 38, year: 1990,
		payload: 'Dormant — based on Exception',
		patterns: [
			{ kind: 'ascii', text: 'ANTI-VIREN KIT 3' },
			{ kind: 'ascii', text: 'KEIN VIRUS IM BOOTSECTOR' },
		],
		confidence: 'verified',
		notes: 'Impersonates a G-Data antivirus immunization message.',
	},
	{
		name: 'Ashton Nirvana', family: 'Ashton', uvk: 64, year: 1992,
		payload: 'Writes "ASHTON" into random sectors on every disk access',
		patterns: [{ kind: 'ascii', text: 'ASHTON' }],
		confidence: 'verified',
		notes: 'Can corrupt hard disks too — particularly nasty.',
	},
	{
		name: 'Darkness (Nightmare of Brooklyn #2)', family: 'Darkness', uvk: 73, year: 1993,
		origin: 'Poland',
		payload: 'Track garbage every 8 copies, screen blackening, intricate encoding',
		patterns: [{ kind: 'ascii', text: 'Nightmare of Brooklyn' }],
		confidence: 'verified',
	},
])

// ── Matcher ─────────────────────────────────────────────────────────────────

export interface SignatureMatch {
	signature: Signature
	/** First offset where a pattern matched, for display. -1 if it was an ASCII search hit. */
	offset: number
	/** The specific pattern that matched. */
	matched: Pattern
}

/**
 * Match a boot sector against the database. Returns every match (a sector
 * can match multiple viruses when patterns overlap — common with the
 * `0x60` family of BRA.B-based boot sectors).
 */
export function matchSignatures(boot: Uint8Array): SignatureMatch[] {
	const matches: SignatureMatch[] = []

	for (const sig of SIGNATURES) {
		if (sig.patterns.length === 0) continue

		if (sig.match === 'all') {
			const offsets: number[] = []
			let ok = true
			for (const pattern of sig.patterns) {
				const offset = matchPattern(boot, pattern)
				if (offset === -1) { ok = false; break }
				offsets.push(offset)
			}
			if (ok) {
				matches.push({
					signature: sig,
					offset: offsets[0]!,
					matched: sig.patterns[0]!,
				})
			}
			continue
		}

		for (const pattern of sig.patterns) {
			const offset = matchPattern(boot, pattern)
			if (offset !== -1) {
				matches.push({ signature: sig, offset, matched: pattern })
				break // one match per signature is enough
			}
		}
	}

	return matches
}

function matchPattern(boot: Uint8Array, pattern: Pattern): number {
	if (pattern.kind === 'ascii') {
		return findAsciiCaseInsensitive(boot, pattern.text)
	}
	if (pattern.kind === 'bytes-scan') {
		return findBytes(boot, pattern.bytes)
	}
	return bytesEqualAt(boot, pattern.bytes, pattern.offset) ? pattern.offset : -1
}

function findBytes(haystack: Uint8Array, needle: number[]): number {
	if (needle.length === 0 || needle.length > haystack.length) return -1
	outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
		for (let j = 0; j < needle.length; j++) {
			if (haystack[i + j] !== needle[j]) continue outer
		}
		return i
	}
	return -1
}

function findAsciiCaseInsensitive(haystack: Uint8Array, needle: string): number {
	const lower = new Uint8Array(needle.length)
	const upper = new Uint8Array(needle.length)
	for (let i = 0; i < needle.length; i++) {
		const c = needle.charCodeAt(i)
		lower[i] = (c >= 0x41 && c <= 0x5A) ? c + 0x20 : c
		upper[i] = (c >= 0x61 && c <= 0x7A) ? c - 0x20 : c
	}
	for (let i = 0; i + needle.length <= haystack.length; i++) {
		let ok = true
		for (let j = 0; j < needle.length; j++) {
			const b = haystack[i + j]
			if (b !== lower[j] && b !== upper[j]) { ok = false; break }
		}
		if (ok) return i
	}
	return -1
}

function bytesEqualAt(haystack: Uint8Array, needle: number[], offset: number): boolean {
	if (offset + needle.length > haystack.length) return false
	for (let j = 0; j < needle.length; j++) {
		if (haystack[offset + j] !== needle[j]) return false
	}
	return true
}
