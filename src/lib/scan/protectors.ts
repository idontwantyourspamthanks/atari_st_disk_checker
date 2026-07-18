/**
 * Known Atari ST boot protectors / antivirus bootblocks / "virus free"
 * loaders. Distinct from virus signatures: these are intentional executable
 * boot sectors that announce themselves in ASCII.
 *
 * Sources: the diskimages/ corpus (PD antivirus / crew bootblocks) plus
 * well-known commercial tools (Sagrotan, UVK/AVK, FastCopy guardian).
 *
 * Matching is string-first - almost every protector brands itself. Generic
 * tokens like "VIRUS FREE" are included so unnamed variants still get
 * classified as protected rather than suspicious-unknown.
 */

export interface ProtectorSignature {
	/** Display name, e.g. "Sagrotan 4.x". */
	name: string
	/** Family for grouping variants. */
	family: string
	/** Substrings to find anywhere in the boot sector (case-insensitive). Any hit counts. */
	patterns: string[]
	/** Short description shown in the finding detail. */
	notes?: string
}

export const PROTECTORS: readonly ProtectorSignature[] = Object.freeze([
	// -- Commercial / widely distributed antivirus --------------------------
	{
		name: 'Sagrotan',
		family: 'Sagrotan',
		patterns: ['SAGROTAN', 'Kein Virus im Bootsektor', 'Bootprogramm'],
		notes: "Henrik Alt's German antivirus boot protector.",
	},
	{
		name: 'UVK / AVK immunization',
		family: 'UVK',
		patterns: ['IMMUNIZED WITH AVK', 'IMMUNIZED WITH UVK', 'NO VIRUS!!'],
		notes: 'Ultimate Virus Killer / Atari Virus Killer immunization bootblock.',
	},
	{
		name: 'FastCopy Pro guardian',
		family: 'FastCopy',
		patterns: [
			'NOT INFECTED BY ANY VIRUS',
			'personal boot sector',
			'FASTCOPY PRO',
			'FASTCOPY IV',
		],
		notes: 'ICP Verlag FastCopy guardian boot sector (Martin Backschat).',
	},
	{
		name: 'Antidote (Kai Holst)',
		family: 'Antidote',
		patterns: ['Bootsector protected by Antidote', 'protected by Antidote'],
	},

	// -- Anti-Ghost specialists ---------------------------------------------
	{
		name: 'TDT Altair Anti-Ghost',
		family: 'Altair',
		patterns: ['ALTAIR ANTI VIRUS', 'TDT ANTI GHOST', 'ANTI GHOST'],
		notes: 'Detects Ghost via resvalid pi; not an infection.',
	},

	// -- Crew / PD "virus free" bootblocks ----------------------------------
	{
		name: 'Medway Boys Protector',
		family: 'Medway Boys',
		patterns: [
			'Medway Boys Protector',
			'The Medway Boys',
		],
	},
	{
		name: 'Adrenalin UK virus-free',
		family: 'Adrenalin',
		patterns: [
			'ADRENALIN U.K. VIRUS FREE',
			'ADRENALIN U.K.',
		],
	},
	{
		name: 'Floppyshop Anti-Virus',
		family: 'Floppyshop',
		patterns: ['Floppyshop Anti-Virus', 'GUARANTEED Virus Free'],
	},
	{
		name: 'BBC Boot-block',
		family: 'BBC',
		patterns: ['BBC Boot-block', 'BBC Bootblock'],
	},
	{
		name: 'DNT Crew boot-sector',
		family: 'DNT Crew',
		patterns: ['DNT CREW BOOT-SECTOR', 'DNT CREW BOOT'],
	},
	{
		name: 'Dream Weavers virus-free',
		family: 'Dream Weavers',
		patterns: ['Dream Weavers', 'A Dream Weavers'],
	},
	{
		name: 'Pompey Pirates virus-free',
		family: 'Pompey Pirates',
		patterns: ['POMPEY', '=> VIRUS FREE'],
	},
	{
		name: 'P.O.V. virus-free boot',
		family: 'POV',
		patterns: ['P.O.V. BOOT', 'Persistence of Vision'],
	},
	{
		name: 'Disk Master virus-free',
		family: 'Disk Master',
		patterns: ['Disk Master - Virus Free', 'Disk Master'],
	},
	{
		name: 'LAPD virus-free',
		family: 'LAPD',
		patterns: ['L.A.P.D.'],
	},
	{
		name: 'Tronic PDL Anti-Virus',
		family: 'Tronic',
		patterns: [
			'TRONIC P.D.L.',
			'NTI-VIRUS v',
			'TI-VIRUS v',
			'GHOST VIRUS IS IN YOUR MEMORY',
			'There is no virus in memory',
		],
	},
	{
		name: 'Wizzcat virus-free',
		family: 'Wizzcat',
		patterns: ['Thou art FREE of viruses', '4MB fix by Wizzcat'],
	},
	{
		name: "Mad'Vision virus-free",
		family: 'Mad Vision',
		patterns: ["MAD'VISION", 'HATE VIRUSES'],
	},
	{
		name: 'NOW 5 virus-free',
		family: 'NOW 5',
		patterns: ['NOW 5  100% VIRUS FREE', 'NOW 5 NOW 5', 'NOW 5  LOADING'],
	},
	{
		name: 'Stormlord bootblock',
		family: 'Stormlord',
		patterns: ['STORMLORD', 'RIPPING OFF THIS BOOTSECTOR'],
	},
	{
		name: 'Kobold Virenschutz',
		family: 'Kobold',
		patterns: ['KOBOLD-Virenschutz', '*** KOBOLD'],
	},
	{
		name: 'Power PD Anti-Virus',
		family: 'Power',
		patterns: ['POWER P.D. ANTI-VIRUS', 'POWER DISK MAG'],
	},
	{
		name: 'Floppy Copy Crew VFB',
		family: 'FCC',
		patterns: ['FLOPPY COPY CREW'],
	},
	{
		name: 'The Detonators virus-free',
		family: 'Detonators',
		patterns: ['THE DETONATORS'],
	},
	{
		name: 'Silver Bullet Force',
		family: 'Silver Bullet',
		patterns: ['SILVER BULLET FORCE'],
	},
	{
		name: 'British Alliance bootblock',
		family: 'British Alliance',
		patterns: ['THE BRITISH ALLIANCE'],
	},
	{
		name: 'Pure Energy virus-free',
		family: 'Pure Energy',
		patterns: ['Pure Energy', 'Your Virus Free'],
	},
	{
		name: 'GND 100% virus-free',
		family: 'GND',
		patterns: ['This disk is 100%'],
	},
	{
		name: 'TSB Virus Killer',
		family: 'TSB',
		patterns: ['TSB2.4', 'TSB from ESC'],
	},
	{
		name: 'Falcon Boot',
		family: 'Falcon',
		patterns: ['FALCON BOOT'],
		notes: 'STE/Falcon utility boot menu - not antivirus, but a known bootblock.',
	},
	{
		name: 'Folders PDL Bootblock',
		family: 'Folders PDL',
		patterns: ['Folders PDL Bootblock'],
	},
	{
		name: 'Shapeshifters / Budgie UK',
		family: 'Shapeshifters',
		patterns: ['SHAPESHIFTERS', 'BUDGIE UK'],
	},
	{
		name: 'Black Rainbow / Fantomas',
		family: 'Black Rainbow',
		patterns: ['CODED BY -FANTOMAS-', 'FANTOMAS'],
	},
	{
		name: '3GB Anti-Virus',
		family: '3GB',
		patterns: ['This Anti-Virus', 'Remove this Anti-Virus'],
	},
	{
		name: 'Fuzion virus killer',
		family: 'Fuzion',
		patterns: ['THE FUZION', '- VIRUS KILLER -'],
	},
	{
		name: 'Dirty Tricks Brigade V-Detect',
		family: 'DTB',
		patterns: ['V-DETECT', 'Dirty Tricks'],
	},

	// -- Generic catch-all (keep last so specific names also match) ---------
	{
		name: 'Virus-free / antivirus bootblock',
		family: 'Generic',
		patterns: [
			'VIRUS FREE',
			'Virus Free',
			'ANTI-VIRUS',
			'ANTI VIRUS',
			'Antivirus',
			'boot protector',
			'BOOTPROTECTOR',
		],
		notes:
			'Generic branding shared by many PD crew bootblocks. Prefer a more ' +
			'specific protector match above when both fire.',
	},
])

export interface ProtectorMatch {
	protector: ProtectorSignature
	/** Offset of the first matching substring. */
	offset: number
	/** The substring that matched. */
	matched: string
}

/**
 * Match a boot sector against known protector / antivirus bootblocks.
 * Returns every match (specific + generic often both fire).
 */
export function matchProtectors(boot: Uint8Array): ProtectorMatch[] {
	const matches: ProtectorMatch[] = []
	for (const prot of PROTECTORS) {
		for (const text of prot.patterns) {
			const offset = findAsciiCaseInsensitive(boot, text)
			if (offset !== -1) {
				matches.push({ protector: prot, offset, matched: text })
				break
			}
		}
	}
	return matches
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
