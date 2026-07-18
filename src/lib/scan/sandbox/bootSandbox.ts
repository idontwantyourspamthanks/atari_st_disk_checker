import { M68k, M68kError } from './m68k'
import { BOOT_SECTOR_SIZE, isBootSectorExecutable } from '../bootSector'
import { matchSignatures, type SignatureMatch } from '../signatures'

/** Addresses we watch for residency / reset-proof installs. */
export const WATCHED_VECTORS = [
	{ addr: 0x0084, name: 'Trap #1 (GEMDOS)' },
	{ addr: 0x00b4, name: 'Trap #13 (BIOS)' },
	{ addr: 0x00b8, name: 'Trap #14 (XBIOS)' },
	{ addr: 0x0426, name: 'resvalid' },
	{ addr: 0x042a, name: 'resvector' },
	{ addr: 0x0472, name: 'hdv_bpb' },
	{ addr: 0x0476, name: 'hdv_rw' },
	{ addr: 0x047a, name: 'hdv_boot' },
	{ addr: 0x047e, name: 'hdv_mediach' },
] as const

export interface SandboxWrite {
	addr: number
	name: string
	value: number
	/** Instruction count when the write happened. */
	atInstruction: number
}

export interface MemorySignatureHit {
	name: string
	/** Absolute address in sandbox RAM where the pattern matched. */
	address: number
	/** Window base used for the 512-byte signature scan. */
	windowBase: number
}

export interface SandboxResult {
	/** Did we attempt to run (executable boot)? */
	ran: boolean
	instructions: number
	haltReason: 'return' | 'limit' | 'loop' | 'unsupported' | 'error' | 'not-executable'
	/** Vector / system-var writes observed. */
	writes: SandboxWrite[]
	/** True if resvalid was set to π ($31415926). */
	resetProofMagic: boolean
	/** True if resvector was written. */
	resetProofVector: boolean
	/** Names of trap/hdv vectors that were written. */
	hooks: string[]
	/**
	 * Virus signatures found in RAM after the run (relocated / decrypted
	 * copies), excluding a pure match on the original boot load window
	 * alone when nothing was relocated.
	 */
	memorySignatures: MemorySignatureHit[]
	error?: string
	/** Final PC (debug). */
	finalPc?: number
}

const RESVALID_PI = 0x31415926
const DEFAULT_LIMIT = 50_000
const MEM_SIZE = 0x10_0000 // 1 MiB
/**
 * Load address for the boot sector. Must NOT be $0 — the exception vector
 * table and TOS system variables live in low RAM, and zeroing trap stubs
 * would overwrite the boot image (Goblin keeps live code/data around $80).
 * $4000 is a plausible floppy-buffer style address above _membot.
 */
export const BOOT_LOAD_ADDR = 0x00004000
const RETURN_SENTINEL = 0x00e00000 // fake "back in TOS" address
const STACK_TOP = 0x00080000
/** Same PC hit this many times → treat as a spin (VBL wait, etc.). */
const LOOP_HIT_THRESHOLD = 512
const DIRTY_PAGE_SHIFT = 8 // 256-byte pages

/**
 * Run a boot sector in a tiny ST-like sandbox and report residency-related
 * side effects (vector installs, reset-proofing).
 *
 * Spike / experimental — not a full TOS emulation.
 */
export function runBootSandbox(
	boot: Uint8Array,
	opts: { instructionLimit?: number } = {},
): SandboxResult {
	const limit = opts.instructionLimit ?? DEFAULT_LIMIT

	if (boot.length < BOOT_SECTOR_SIZE) {
		return emptyResult('error', `Boot sector too short (${boot.length})`)
	}

	if (!isBootSectorExecutable(boot)) {
		return emptyResult('not-executable')
	}

	const mem = new Uint8Array(MEM_SIZE)

	// Cold-boot-ish system variables (trap vectors unused — we intercept TRAPs).
	write32raw(mem, 0x0420, 0x752019f3) // memvalid
	write32raw(mem, 0x042e, MEM_SIZE) // phystop
	write32raw(mem, 0x0432, 0x00000800) // _membot
	write32raw(mem, 0x0436, MEM_SIZE) // _memtop
	write32raw(mem, 0x04c6, 0x00010000) // pun_ptr-ish buffer

	mem.set(boot.subarray(0, BOOT_SECTOR_SIZE), BOOT_LOAD_ADDR)

	const writes: SandboxWrite[] = []
	const seen = new Set<string>()
	const dirtyPages = new Set<number>()
	let instructions = 0
	const pcHits = new Map<number, number>()

	const cpu = new M68k(mem, (addr, size, value) => {
		dirtyPages.add(addr >>> DIRTY_PAGE_SHIFT)
		if (size === 4) dirtyPages.add((addr + 2) >>> DIRTY_PAGE_SHIFT)
		if (size !== 4 && size !== 2) return
		for (const v of WATCHED_VECTORS) {
			if (addr === v.addr) {
				const key = `${v.addr}:${value >>> 0}`
				if (seen.has(key)) continue
				seen.add(key)
				writes.push({
					addr: v.addr,
					name: v.name,
					value: value >>> 0,
					atInstruction: instructions,
				})
			}
		}
	})

	cpu.trapHandler = (trapNo, c) => handleTrap(trapNo, c, mem)

	cpu.pc = BOOT_LOAD_ADDR
	cpu.sp = STACK_TOP
	cpu.sp = (cpu.sp - 4) >>> 0
	write32raw(mem, cpu.sp, RETURN_SENTINEL)
	cpu.a[7] = cpu.sp

	try {
		while (instructions < limit) {
			if (cpu.pc === RETURN_SENTINEL) {
				return finish('return')
			}
			// Strayed into vector/system-variable space (e.g. JMP to memvalid) —
			// stop; any residency writes already recorded still count.
			if (cpu.pc < BOOT_LOAD_ADDR && cpu.pc >= 0x100) {
				return finish('return')
			}

			const hits = (pcHits.get(cpu.pc) ?? 0) + 1
			pcHits.set(cpu.pc, hits)
			if (hits >= LOOP_HIT_THRESHOLD) {
				return finish('loop')
			}

			cpu.step()
			instructions++
			if (cpu.pc === RETURN_SENTINEL) {
				return finish('return')
			}
		}
		return finish('limit')
	} catch (e) {
		const msg = e instanceof M68kError ? e.message : e instanceof Error ? e.message : String(e)
		return {
			ran: true,
			instructions,
			haltReason: e instanceof M68kError ? 'unsupported' : 'error',
			writes,
			resetProofMagic: hasPi(writes),
			resetProofVector: writes.some(w => w.addr === 0x042a),
			hooks: hookNames(writes),
			memorySignatures: scanDirtyMemory(mem, dirtyPages, boot),
			error: msg,
			finalPc: cpu.pc,
		}
	}

	function finish(haltReason: SandboxResult['haltReason']): SandboxResult {
		return {
			ran: true,
			instructions,
			haltReason,
			writes,
			resetProofMagic: hasPi(writes),
			resetProofVector: writes.some(w => w.addr === 0x042a),
			hooks: hookNames(writes),
			memorySignatures: scanDirtyMemory(mem, dirtyPages, boot),
			finalPc: cpu.pc,
		}
	}
}

function emptyResult(
	haltReason: SandboxResult['haltReason'],
	error?: string,
): SandboxResult {
	return {
		ran: false,
		instructions: 0,
		haltReason,
		writes: [],
		resetProofMagic: false,
		resetProofVector: false,
		hooks: [],
		memorySignatures: [],
		error,
	}
}

function hasPi(writes: SandboxWrite[]): boolean {
	return writes.some(w => w.addr === 0x0426 && w.value === RESVALID_PI)
}

function hookNames(writes: SandboxWrite[]): string[] {
	const names = new Set<string>()
	for (const w of writes) {
		if (w.addr === 0x0426 || w.addr === 0x042a) continue
		names.add(w.name)
	}
	return [...names]
}

/**
 * BIOS / XBIOS / GEMDOS stubs. Enough for install paths that re-read the
 * boot sector or probe disk presence. Returns success (D0=0) by default.
 */
function handleTrap(trapNo: number, cpu: M68k, mem: Uint8Array): void {
	if (trapNo === 13) {
		// BIOS — function in D0.W
		const fn = cpu.d[0]! & 0xffff
		if (fn === 4) {
			// Rwabs(rwflag, buf, count, recno, dev)
			const rwflag = cpu.read16(cpu.sp)
			const buf = cpu.read32(cpu.sp + 2)
			const count = cpu.read16(cpu.sp + 6)
			const recno = cpu.read16(cpu.sp + 8)
			if ((rwflag & 1) === 0 && recno === 0 && count > 0) {
				copyBootTo(mem, buf)
			}
		}
		cpu.d[0] = 0
		return
	}
	if (trapNo === 14) {
		// XBIOS — function word at 0(sp)
		const fn = cpu.read16(cpu.sp)
		if (fn === 8 || fn === 9) {
			// Floprd / Flopwr: buf at 2(sp), sector at 12(sp), track at 14(sp)
			const buf = cpu.read32(cpu.sp + 2)
			const sector = cpu.read16(cpu.sp + 12)
			const track = cpu.read16(cpu.sp + 14)
			if (fn === 8 && track === 0 && sector === 1) {
				copyBootTo(mem, buf)
			}
		}
		cpu.d[0] = 0
		return
	}
	// GEMDOS (#1) and anything else — succeed
	cpu.d[0] = 0
}

function copyBootTo(mem: Uint8Array, buf: number): void {
	buf >>>= 0
	if (buf + BOOT_SECTOR_SIZE > mem.length) return
	mem.set(mem.subarray(BOOT_LOAD_ADDR, BOOT_LOAD_ADDR + BOOT_SECTOR_SIZE).slice(), buf)
}

/**
 * Signature-scan 512-byte windows over dirty pages and a few high-RAM
 * candidates (typical virus residence just below phystop).
 */
export function scanDirtyMemory(
	mem: Uint8Array,
	dirtyPages: Set<number>,
	originalBoot: Uint8Array,
): MemorySignatureHit[] {
	const bases = new Set<number>()
	bases.add(BOOT_LOAD_ADDR)
	for (const page of dirtyPages) {
		const addr = page << DIRTY_PAGE_SHIFT
		// Align down to 256; also try 512-aligned
		bases.add(addr & ~0xff)
		bases.add(addr & ~0x1ff)
	}
	// Classic "hide under phystop" band
	for (let a = MEM_SIZE - 0x8000; a < MEM_SIZE - 0x200; a += 0x200) {
		bases.add(a)
	}

	const originalNames = new Set(
		matchSignatures(originalBoot.subarray(0, BOOT_SECTOR_SIZE)).map(m => m.signature.name),
	)

	const hits: MemorySignatureHit[] = []
	const seen = new Set<string>()

	for (const base of bases) {
		if (base < 0 || base + BOOT_SECTOR_SIZE > mem.length) continue
		const window = mem.subarray(base, base + BOOT_SECTOR_SIZE)
		// Skip all-zero windows
		let nonzero = false
		for (let i = 0; i < window.length; i++) {
			if (window[i] !== 0) {
				nonzero = true
				break
			}
		}
		if (!nonzero) continue

		const matches: SignatureMatch[] = matchSignatures(window)
		for (const m of matches) {
			// Always report hits outside the original boot load window.
			// Inside it, only report if we also saw a relocated copy elsewhere
			// (handled by collecting all then filtering).
			const key = `${m.signature.name}@${base}`
			if (seen.has(key)) continue
			seen.add(key)
			hits.push({
				name: m.signature.name,
				address: base + m.offset,
				windowBase: base,
			})
		}
	}

	// Prefer relocated evidence: drop boot-window-only hits that aren't
	// corroborated elsewhere, unless the boot window itself is the only place
	// (still useful after in-place decrypt — keep if pattern differs from
	// static... we can't know easily, so keep boot-window hits always but
	// tag them; scanner can de-dupe against static sigs).
	const relocated = hits.filter(h => h.windowBase !== BOOT_LOAD_ADDR)
	if (relocated.length > 0) {
		// Return relocated + any boot hits for names also seen relocated
		const relocatedNames = new Set(relocated.map(h => h.name))
		return hits.filter(
			h => h.windowBase !== BOOT_LOAD_ADDR || relocatedNames.has(h.name),
		)
	}

	// No relocation — keep boot-window hits only when static scan wouldn't
	// already see them (e.g. in-place decrypt). Compare name set loosely:
	return hits.filter(h => h.windowBase === BOOT_LOAD_ADDR && !originalNames.has(h.name))
}

function write32raw(mem: Uint8Array, addr: number, value: number): void {
	mem[addr] = (value >>> 24) & 0xff
	mem[addr + 1] = (value >>> 16) & 0xff
	mem[addr + 2] = (value >>> 8) & 0xff
	mem[addr + 3] = value & 0xff
}
