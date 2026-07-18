import { M68k, M68kError } from './m68k'
import { BOOT_SECTOR_SIZE, isBootSectorExecutable } from '../bootSector'

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

export interface SandboxResult {
	/** Did we attempt to run (executable boot)? */
	ran: boolean
	instructions: number
	haltReason: 'return' | 'limit' | 'unsupported' | 'error' | 'not-executable'
	/** Vector / system-var writes observed. */
	writes: SandboxWrite[]
	/** True if resvalid was set to π ($31415926). */
	resetProofMagic: boolean
	/** True if resvector was written. */
	resetProofVector: boolean
	/** Names of trap/hdv vectors that were written. */
	hooks: string[]
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
const BOOT_LOAD_ADDR = 0x00004000
const RETURN_SENTINEL = 0x00e00000 // fake "back in TOS" address
const STACK_TOP = 0x00080000

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
		return {
			ran: false,
			instructions: 0,
			haltReason: 'error',
			writes: [],
			resetProofMagic: false,
			resetProofVector: false,
			hooks: [],
			error: `Boot sector too short (${boot.length})`,
		}
	}

	if (!isBootSectorExecutable(boot)) {
		return {
			ran: false,
			instructions: 0,
			haltReason: 'not-executable',
			writes: [],
			resetProofMagic: false,
			resetProofVector: false,
			hooks: [],
		}
	}

	const mem = new Uint8Array(MEM_SIZE)

	// Stub trap vectors first (low RAM), before the boot image is loaded.
	// Address 0 means "ignore / return" in our TRAP handler.
	for (let t = 0; t < 16; t++) write32raw(mem, 0x80 + t * 4, 0)

	// Cold-boot-ish system variables
	write32raw(mem, 0x0420, 0x752019f3) // memvalid
	write32raw(mem, 0x042e, MEM_SIZE) // phystop
	write32raw(mem, 0x0432, 0x00000800) // _membot
	write32raw(mem, 0x0436, MEM_SIZE) // _memtop
	// Some boot viruses (Signum) treat $4C6 as a usable RAM pointer.
	write32raw(mem, 0x04c6, 0x00010000)

	// Boot sector in its own buffer — PC-relative code relocates with us.
	mem.set(boot.subarray(0, BOOT_SECTOR_SIZE), BOOT_LOAD_ADDR)

	const writes: SandboxWrite[] = []
	const seen = new Set<string>()
	let instructions = 0

	const cpu = new M68k(mem, (addr, size, value) => {
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

	cpu.pc = BOOT_LOAD_ADDR
	cpu.sp = STACK_TOP
	// Simulate TOS JSR boot: return address on stack.
	cpu.sp = (cpu.sp - 4) >>> 0
	write32raw(mem, cpu.sp, RETURN_SENTINEL)
	cpu.a[7] = cpu.sp

	try {
		while (instructions < limit) {
			if (cpu.pc === RETURN_SENTINEL) {
				return finish('return')
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
			resetProofMagic: writes.some(w => w.addr === 0x0426 && w.value === RESVALID_PI),
			resetProofVector: writes.some(w => w.addr === 0x042a),
			hooks: hookNames(writes),
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
			resetProofMagic: writes.some(w => w.addr === 0x0426 && w.value === RESVALID_PI),
			resetProofVector: writes.some(w => w.addr === 0x042a),
			hooks: hookNames(writes),
			finalPc: cpu.pc,
		}
	}
}

function hookNames(writes: SandboxWrite[]): string[] {
	const names = new Set<string>()
	for (const w of writes) {
		if (w.addr === 0x0426 || w.addr === 0x042a) continue
		names.add(w.name)
	}
	return [...names]
}

function write32raw(mem: Uint8Array, addr: number, value: number): void {
	mem[addr] = (value >>> 24) & 0xff
	mem[addr + 1] = (value >>> 16) & 0xff
	mem[addr + 2] = (value >>> 8) & 0xff
	mem[addr + 3] = value & 0xff
}
