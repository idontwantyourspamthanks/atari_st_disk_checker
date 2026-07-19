import { M68k, M68kError } from './m68k'
import { BOOT_SECTOR_SIZE, isBootSectorExecutable } from '../bootSector'
import { matchSignatures, type SignatureMatch } from '../signatures'

/** Addresses we watch for residency / reset-proof installs. */
export const WATCHED_VECTORS = [
	{ addr: 0x0084, name: 'Trap #1 (GEMDOS)' },
	{ addr: 0x00b4, name: 'Trap #13 (BIOS)' },
	{ addr: 0x00b8, name: 'Trap #14 (XBIOS)' },
	{ addr: 0x0400, name: 'etv_timer' },
	{ addr: 0x0404, name: 'etv_critic' },
	{ addr: 0x0408, name: 'etv_term' },
	{ addr: 0x0426, name: 'resvalid' },
	{ addr: 0x042a, name: 'resvector' },
	{ addr: 0x0432, name: '_membot' },
	{ addr: 0x0436, name: '_memtop' },
	{ addr: 0x0472, name: 'hdv_bpb' },
	{ addr: 0x0476, name: 'hdv_rw' },
	{ addr: 0x047a, name: 'hdv_boot' },
	{ addr: 0x047e, name: 'hdv_mediach' },
] as const

/** RAM-limit system variables — written to carve out a hiding place, not to hook a vector. */
export const RAM_LIMIT_ADDRS: ReadonlySet<number> = new Set([0x0432, 0x0436])

export interface SandboxWrite {
	addr: number
	name: string
	value: number
	/** Instruction count when the write happened. */
	atInstruction: number
}

/**
 * A trapped attempt to WRITE the boot sector back to the floppy — the
 * defining self-propagation behaviour of a boot-sector virus.
 */
export interface BootWriteAttempt {
	/** Which OS call was used ('BIOS Rwabs' or 'XBIOS Flopwr'). */
	via: string
	/** Buffer the sector would be written from. */
	buf: number
	/** Sector count requested. */
	count: number
	/** Instruction count when the call happened. */
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
	haltReason: 'return' | 'limit' | 'loop' | 'stray' | 'unsupported' | 'error' | 'not-executable'
	/** Vector / system-var writes observed. */
	writes: SandboxWrite[]
	/** Boot-sector write attempts observed via BIOS/XBIOS traps. */
	bootWrites: BootWriteAttempt[]
	/** True if resvalid was set to π ($31415926). */
	resetProofMagic: boolean
	/** True if resvector was written. */
	resetProofVector: boolean
	/** Names of trap/hdv/etv vectors that were written (excludes resvalid/resvector/RAM limits). */
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

/** Reused across runs to avoid 1 MiB alloc + GC per executable boot. */
let scratchMem: Uint8Array | null = null

function acquireScratchMem(): Uint8Array {
	if (!scratchMem || scratchMem.length !== MEM_SIZE) {
		scratchMem = new Uint8Array(MEM_SIZE)
	} else {
		scratchMem.fill(0)
	}
	return scratchMem
}

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

	const mem = acquireScratchMem()

	// Cold-boot-ish system variables (trap vectors unused — we intercept TRAPs).
	write32raw(mem, 0x0420, 0x752019f3) // memvalid
	write32raw(mem, 0x042e, MEM_SIZE) // phystop
	write32raw(mem, 0x0432, 0x00000800) // _membot
	write32raw(mem, 0x0436, MEM_SIZE) // _memtop
	write32raw(mem, 0x04c6, 0x00010000) // pun_ptr-ish buffer

	mem.set(boot.subarray(0, BOOT_SECTOR_SIZE), BOOT_LOAD_ADDR)

	const writes: SandboxWrite[] = []
	const bootWrites: BootWriteAttempt[] = []
	const seen = new Set<string>()
	const dirtyPages = new Set<number>()
	let instructions = 0
	let lastPc = -1
	let consecutiveHits = 0
	/** Second PC in a tight 2-insn cycle (decrypt/poll). */
	let prevPc = -1
	let cycle2Hits = 0
	let lastProgressWrites = 0
	let progressWriteCount = 0

	const cpu = new M68k(mem, (addr, size, _value) => {
		dirtyPages.add(addr >>> DIRTY_PAGE_SHIFT)
		if (size === 4) dirtyPages.add((addr + 2) >>> DIRTY_PAGE_SHIFT)
		// Decrypt loops write into the boot image — count as progress so we
		// don't mistake a XOR/DBF body for a VBL spin.
		if (addr >= BOOT_LOAD_ADDR && addr < BOOT_LOAD_ADDR + BOOT_SECTOR_SIZE) {
			progressWriteCount++
		}
		if (size !== 4 && size !== 2 && size !== 1) return
		const writeEnd = addr + size
		for (const v of WATCHED_VECTORS) {
			const vecEnd = v.addr + 4
			// Any overlapping write into the watched longword — read live RAM
			// so MOVE.L at $424 covering resvalid ($426) still counts.
			if (addr < vecEnd && writeEnd > v.addr) {
				const live = read32raw(mem, v.addr)
				const key = `${v.addr}:${live}`
				if (seen.has(key)) continue
				seen.add(key)
				writes.push({
					addr: v.addr,
					name: v.name,
					value: live,
					atInstruction: instructions,
				})
			}
		}
	})

	cpu.trapHandler = (trapNo, c) =>
		handleTrap(trapNo, c, { mem, dirtyPages, bootWrites, atInstruction: () => instructions })

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
			// Strayed below the boot load window into vector/system-variable
			// space — stop; any residency writes already recorded still count.
			if (cpu.pc < BOOT_LOAD_ADDR) {
				return finish('stray')
			}

			const progressed = progressWriteCount > lastProgressWrites
			if (progressed) lastProgressWrites = progressWriteCount

			// Consecutive same-PC spin (VBL/key poll). Ignore while the boot
			// image is still being rewritten (decrypt-in-place).
			if (cpu.pc === lastPc) consecutiveHits++
			else {
				// Two-PC cycle: A→B→A… common for TST/BNE polls and DBF bodies.
				if (cpu.pc === prevPc && lastPc !== prevPc) cycle2Hits++
				else cycle2Hits = 0
				prevPc = lastPc
				lastPc = cpu.pc
				consecutiveHits = 1
			}
			if (!progressed) {
				if (consecutiveHits >= LOOP_HIT_THRESHOLD) {
					return finish('loop')
				}
				if (cycle2Hits >= LOOP_HIT_THRESHOLD) {
					return finish('loop')
				}
			} else {
				consecutiveHits = 0
				cycle2Hits = 0
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
			bootWrites,
			resetProofMagic: hasPi(writes),
			resetProofVector: writes.some(w => w.addr === 0x042a),
			hooks: hookNames(writes),
			memorySignatures: scanDirtyMemory(mem, dirtyPages, boot, {
				scanHighRam: shouldScanHighRam(dirtyPages, writes),
			}),
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
			bootWrites,
			resetProofMagic: hasPi(writes),
			resetProofVector: writes.some(w => w.addr === 0x042a),
			hooks: hookNames(writes),
			memorySignatures: scanDirtyMemory(mem, dirtyPages, boot, {
				scanHighRam: shouldScanHighRam(dirtyPages, writes),
			}),
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
		bootWrites: [],
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
		// RAM-limit writes are hiding behaviour, not a vector hook — reported separately.
		if (RAM_LIMIT_ADDRS.has(w.addr)) continue
		names.add(w.name)
	}
	return [...names]
}

/** Context handed to the trap stub so it can record side effects. */
interface TrapContext {
	mem: Uint8Array
	dirtyPages: Set<number>
	bootWrites: BootWriteAttempt[]
	atInstruction: () => number
}

/**
 * BIOS / XBIOS / GEMDOS stubs. Enough for install paths that re-read the
 * boot sector or probe disk presence. Returns success (D0=0) by default.
 * WRITE calls targeting the boot sector are recorded as propagation attempts
 * (and still succeed, so the code keeps running and reveals more).
 */
function handleTrap(
	trapNo: number,
	cpu: M68k,
	ctx: TrapContext,
): void {
	const { mem, dirtyPages, bootWrites } = ctx
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
				copyBootTo(mem, buf, dirtyPages)
			}
			if ((rwflag & 1) !== 0 && recno === 0 && count > 0) {
				bootWrites.push({
					via: 'BIOS Rwabs',
					buf: buf >>> 0,
					count,
					atInstruction: ctx.atInstruction(),
				})
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
				copyBootTo(mem, buf, dirtyPages)
			}
			if (fn === 9 && track === 0 && sector === 1) {
				bootWrites.push({
					via: 'XBIOS Flopwr',
					buf: buf >>> 0,
					count: cpu.read16(cpu.sp + 16),
					atInstruction: ctx.atInstruction(),
				})
			}
		}
		cpu.d[0] = 0
		return
	}
	// GEMDOS (#1) and anything else — succeed
	cpu.d[0] = 0
}

function copyBootTo(mem: Uint8Array, buf: number, dirtyPages: Set<number>): void {
	buf >>>= 0
	if (buf + BOOT_SECTOR_SIZE > mem.length) return
	mem.set(mem.subarray(BOOT_LOAD_ADDR, BOOT_LOAD_ADDR + BOOT_SECTOR_SIZE).slice(), buf)
	// mem.set bypasses onWrite — mark destination pages dirty so RAM
	// signature scans see relocated boot copies outside the high-RAM band.
	markDirtyRange(dirtyPages, buf, BOOT_SECTOR_SIZE)
}

/** Mark a byte range dirty (exported for unit tests). */
export function markDirtyRange(
	dirtyPages: Set<number>,
	addr: number,
	length: number,
): void {
	for (let off = 0; off < length; off += 1 << DIRTY_PAGE_SHIFT) {
		dirtyPages.add((addr + off) >>> DIRTY_PAGE_SHIFT)
	}
	if (length > 0) dirtyPages.add((addr + length - 1) >>> DIRTY_PAGE_SHIFT)
}

/**
 * Signature-scan 512-byte windows over dirty pages and, when residency is
 * hinted, a high-RAM band just below phystop (classic hide-under-_memtop).
 */
export function scanDirtyMemory(
	mem: Uint8Array,
	dirtyPages: Set<number>,
	originalBoot: Uint8Array,
	opts: { scanHighRam?: boolean } = {},
): MemorySignatureHit[] {
	const bases = new Set<number>()
	bases.add(BOOT_LOAD_ADDR)
	for (const page of dirtyPages) {
		const addr = page << DIRTY_PAGE_SHIFT
		// Align down to 256; also try 512-aligned
		bases.add(addr & ~0xff)
		bases.add(addr & ~0x1ff)
	}
	// Only walk the ~64 high-RAM windows when something already smells like
	// residency — dirty pages outside the boot buffer, or vector hooks.
	if (opts.scanHighRam) {
		for (let a = MEM_SIZE - 0x8000; a < MEM_SIZE - 0x200; a += 0x200) {
			bases.add(a)
		}
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

/** True when dirty/hooks suggest code may have relocated under phystop. */
export function shouldScanHighRam(
	dirtyPages: Set<number>,
	writes: SandboxWrite[],
): boolean {
	if (hasPi(writes) || writes.some(w => w.addr === 0x042a)) return true
	// RAM-limit tampering is exactly how code reserves a hideout under phystop.
	if (writes.some(w => RAM_LIMIT_ADDRS.has(w.addr))) return true
	if (hookNames(writes).length > 0) return true
	const bootLo = BOOT_LOAD_ADDR >>> DIRTY_PAGE_SHIFT
	const bootHi = (BOOT_LOAD_ADDR + BOOT_SECTOR_SIZE - 1) >>> DIRTY_PAGE_SHIFT
	for (const page of dirtyPages) {
		if (page < bootLo || page > bootHi) return true
	}
	return false
}

function write32raw(mem: Uint8Array, addr: number, value: number): void {
	mem[addr] = (value >>> 24) & 0xff
	mem[addr + 1] = (value >>> 16) & 0xff
	mem[addr + 2] = (value >>> 8) & 0xff
	mem[addr + 3] = value & 0xff
}

function read32raw(mem: Uint8Array, addr: number): number {
	return (
		(((mem[addr] ?? 0) << 24) |
			((mem[addr + 1] ?? 0) << 16) |
			((mem[addr + 2] ?? 0) << 8) |
			(mem[addr + 3] ?? 0)) >>>
		0
	)
}
