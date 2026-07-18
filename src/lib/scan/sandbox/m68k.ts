/**
 * Minimal 68000 interpreter for boot-sector sandboxing.
 *
 * Not a full CPU — just enough user/supervisor integer ops for typical ST
 * boot viruses (Ghost, etc.). Unsupported opcodes throw with the PC.
 */

export class M68kError extends Error {
	constructor(
		message: string,
		readonly pc: number,
		readonly op: number,
	) {
		super(`${message} (PC=$${pc.toString(16)} op=$${op.toString(16).padStart(4, '0')})`)
		this.name = 'M68kError'
	}
}

export type MemWriteHook = (addr: number, size: 1 | 2 | 4, value: number) => void

/** If set, TRAP #n is handled here instead of vector dispatch. */
export type TrapHandler = (trapNo: number, cpu: M68k) => void

export class M68k {
	readonly d = new Uint32Array(8)
	readonly a = new Uint32Array(8)
	pc = 0
	sr = 0x2700 // supervisor, interrupts masked — typical boot state
	stopped = false
	trapHandler?: TrapHandler

	constructor(
		readonly mem: Uint8Array,
		readonly onWrite?: MemWriteHook,
	) {}

	get sp(): number {
		return this.a[7]!
	}
	set sp(v: number) {
		this.a[7] = v >>> 0
	}

	read8(addr: number): number {
		return this.mem[addr >>> 0] ?? 0
	}
	read16(addr: number): number {
		addr >>>= 0
		return ((this.mem[addr] ?? 0) << 8) | (this.mem[addr + 1] ?? 0)
	}
	read32(addr: number): number {
		return ((this.read16(addr) << 16) | this.read16(addr + 2)) >>> 0
	}

	write8(addr: number, value: number): void {
		addr >>>= 0
		const v = value & 0xff
		this.mem[addr] = v
		this.onWrite?.(addr, 1, v)
	}
	write16(addr: number, value: number): void {
		addr >>>= 0
		const v = value & 0xffff
		this.mem[addr] = v >>> 8
		this.mem[addr + 1] = v & 0xff
		this.onWrite?.(addr, 2, v)
	}
	write32(addr: number, value: number): void {
		addr >>>= 0
		const v = value >>> 0
		this.mem[addr] = (v >>> 24) & 0xff
		this.mem[addr + 1] = (v >>> 16) & 0xff
		this.mem[addr + 2] = (v >>> 8) & 0xff
		this.mem[addr + 3] = v & 0xff
		this.onWrite?.(addr, 4, v)
	}

	/** Fetch word at PC and advance. */
	fetch16(): number {
		const w = this.read16(this.pc)
		this.pc = (this.pc + 2) >>> 0
		return w
	}
	fetch32(): number {
		const w = this.fetch16()
		return ((w << 16) | this.fetch16()) >>> 0
	}

	private setNzFrom(size: 1 | 2 | 4, value: number): void {
		const mask = size === 1 ? 0xff : size === 2 ? 0xffff : 0xffffffff
		const v = value & mask
		const sign = size === 1 ? 0x80 : size === 2 ? 0x8000 : 0x80000000
		this.sr = (this.sr & ~0x0f) | (v === 0 ? 0x04 : 0) | (v & sign ? 0x08 : 0)
	}

	private flagZ(): boolean {
		return (this.sr & 0x04) !== 0
	}
	private flagN(): boolean {
		return (this.sr & 0x08) !== 0
	}
	private flagC(): boolean {
		return (this.sr & 0x01) !== 0
	}
	private flagV(): boolean {
		return (this.sr & 0x02) !== 0
	}

	/** Decode EA; returns { address } for memory or { reg, isA } for data/address regs. */
	private resolveEa(
		mode: number,
		reg: number,
		size: 1 | 2 | 4,
	): { addr: number } | { dn: number } | { an: number } {
		switch (mode) {
			case 0:
				return { dn: reg }
			case 1:
				return { an: reg }
			case 2:
				return { addr: this.a[reg]! >>> 0 }
			case 3: {
				const addr = this.a[reg]! >>> 0
				this.a[reg] = (addr + size) >>> 0
				return { addr }
			}
			case 4: {
				const addr = (this.a[reg]! - size) >>> 0
				this.a[reg] = addr
				return { addr }
			}
			case 5: {
				const disp = this.sign16(this.fetch16())
				return { addr: (this.a[reg]! + disp) >>> 0 }
			}
			case 6: {
				const ext = this.fetch16()
				const disp = this.sign8(ext & 0xff)
				const idxReg = (ext >> 12) & 7
				const idxIsA = (ext & 0x8000) !== 0
				let idx = idxIsA ? this.a[idxReg]! : this.d[idxReg]!
				if ((ext & 0x0800) === 0) idx = this.sign16(idx & 0xffff)
				return { addr: (this.a[reg]! + disp + idx) >>> 0 }
			}
			case 7:
				switch (reg) {
					case 0:
						return { addr: this.sign16(this.fetch16()) >>> 0 }
					case 1:
						return { addr: this.fetch32() }
					case 2: {
						const base = this.pc
						const disp = this.sign16(this.fetch16())
						return { addr: (base + disp) >>> 0 }
					}
					case 3: {
						const base = this.pc
						const ext = this.fetch16()
						const disp = this.sign8(ext & 0xff)
						const idxReg = (ext >> 12) & 7
						const idxIsA = (ext & 0x8000) !== 0
						let idx = idxIsA ? this.a[idxReg]! : this.d[idxReg]!
						if ((ext & 0x0800) === 0) idx = this.sign16(idx & 0xffff)
						return { addr: (base + disp + idx) >>> 0 }
					}
					case 4:
						// Immediate — caller must handle; address is PC before fetch
						return { addr: this.pc }
					default:
						throw new M68kError(`unsupported EA mode 7/${reg}`, this.pc, 0)
				}
			default:
				throw new M68kError(`unsupported EA mode ${mode}`, this.pc, 0)
		}
	}

	private readEa(ea: ReturnType<M68k['resolveEa']>, size: 1 | 2 | 4): number {
		if ('dn' in ea) {
			const v = this.d[ea.dn]!
			return size === 1 ? v & 0xff : size === 2 ? v & 0xffff : v >>> 0
		}
		if ('an' in ea) {
			const v = this.a[ea.an]!
			return size === 2 ? v & 0xffff : v >>> 0
		}
		if (size === 1) return this.read8(ea.addr)
		if (size === 2) return this.read16(ea.addr)
		return this.read32(ea.addr)
	}

	private writeEa(ea: ReturnType<M68k['resolveEa']>, size: 1 | 2 | 4, value: number): void {
		if ('dn' in ea) {
			if (size === 1) this.d[ea.dn] = (this.d[ea.dn]! & 0xffffff00) | (value & 0xff)
			else if (size === 2) this.d[ea.dn] = (this.d[ea.dn]! & 0xffff0000) | (value & 0xffff)
			else this.d[ea.dn] = value >>> 0
			return
		}
		if ('an' in ea) {
			this.a[ea.an] = size === 2 ? this.sign16(value & 0xffff) >>> 0 : value >>> 0
			return
		}
		if (size === 1) this.write8(ea.addr, value)
		else if (size === 2) this.write16(ea.addr, value)
		else this.write32(ea.addr, value)
	}

	private sign8(v: number): number {
		return v & 0x80 ? v - 0x100 : v
	}
	private sign16(v: number): number {
		return v & 0x8000 ? v - 0x10000 : v
	}

	step(): void {
		if (this.stopped) return
		// 68000 Trace: if T was set at the start of this instruction, take a
		// Trace exception after it completes. (MOVE to SR that enables T is
		// itself not traced — takeTrace is sampled before the instruction.)
		const takeTrace = (this.sr & 0x8000) !== 0
		this.stepInner()
		if (takeTrace && !this.stopped) this.raiseTrace()
	}

	/** Vector $24 — Trace exception. Stacks SR+PC, clears T, enters handler. */
	private raiseTrace(): void {
		const handler = this.read32(0x24)
		if (handler === 0) return // no handler installed
		this.sp = (this.sp - 4) >>> 0
		this.write32(this.sp, this.pc)
		this.sp = (this.sp - 2) >>> 0
		this.write16(this.sp, this.sr) // stacked SR still has T set for RTE
		this.sr = (this.sr | 0x2000) & ~0x8000 // supervisor, clear T
		this.pc = handler >>> 0
	}

	private stepInner(): void {
		const opPc = this.pc
		const op = this.fetch16()

		// NOP
		if (op === 0x4e71) return
		// RTS
		if (op === 0x4e75) {
			this.pc = this.read32(this.sp)
			this.sp = (this.sp + 4) >>> 0
			return
		}
		// RTE
		if (op === 0x4e73) {
			this.sr = this.read16(this.sp)
			this.sp = (this.sp + 2) >>> 0
			this.pc = this.read32(this.sp)
			this.sp = (this.sp + 4) >>> 0
			return
		}
		// JMP (An)
		if ((op & 0xfff8) === 0x4ed0) {
			this.pc = this.a[op & 7]! >>> 0
			return
		}
		// JMP Abs.W / Abs.L
		if (op === 0x4ef8) {
			this.pc = this.sign16(this.fetch16()) >>> 0
			return
		}
		if (op === 0x4ef9) {
			this.pc = this.fetch32()
			return
		}
		// JSR (An)
		if ((op & 0xfff8) === 0x4e90) {
			const dest = this.a[op & 7]! >>> 0
			this.sp = (this.sp - 4) >>> 0
			this.write32(this.sp, this.pc)
			this.pc = dest
			return
		}
		// JSR Abs.W / Abs.L
		if (op === 0x4eb8) {
			const dest = this.sign16(this.fetch16()) >>> 0
			this.sp = (this.sp - 4) >>> 0
			this.write32(this.sp, this.pc)
			this.pc = dest
			return
		}
		if (op === 0x4eb9) {
			const dest = this.fetch32()
			this.sp = (this.sp - 4) >>> 0
			this.write32(this.sp, this.pc)
			this.pc = dest
			return
		}
		// TRAP #n
		if ((op & 0xfff0) === 0x4e40) {
			const n = op & 0xf
			if (this.trapHandler) {
				this.trapHandler(n, this)
				return
			}
			// Vector at 0x80 + n*4; push SR+PC like a real trap, then jump.
			const vec = this.read32(0x80 + n * 4)
			this.sp = (this.sp - 4) >>> 0
			this.write32(this.sp, this.pc)
			this.sp = (this.sp - 2) >>> 0
			this.write16(this.sp, this.sr)
			this.pc = vec >>> 0
			if (vec === 0) {
				// Unhandled trap — bounce back as if RTE with no side effects
				this.sr = this.read16(this.sp)
				this.sp = (this.sp + 2) >>> 0
				this.pc = this.read32(this.sp)
				this.sp = (this.sp + 4) >>> 0
			}
			return
		}

		// Line-A ($Axxx) / Line-F ($Fxxx) — TOS / FPU; no-op for boot triage.
		if ((op & 0xf000) === 0xa000 || (op & 0xf000) === 0xf000) return

		// MOVE <ea>, SR  (46C0+) / MOVE #imm, SR (46FC)
		if ((op & 0xffc0) === 0x46c0) {
			const mode = (op >> 3) & 7
			const reg = op & 7
			let value: number
			if (mode === 7 && reg === 4) value = this.fetch16()
			else value = this.readEa(this.resolveEa(mode, reg, 2), 2)
			this.sr = value & 0xffff
			return
		}

		// MOVE SR, <ea>  (40C0+)
		if ((op & 0xffc0) === 0x40c0) {
			const mode = (op >> 3) & 7
			const reg = op & 7
			const ea = this.resolveEa(mode, reg, 2)
			this.writeEa(ea, 2, this.sr & 0xffff)
			return
		}

		// ORI/ANDI/EORI to CCR/SR
		if (op === 0x007c || op === 0x027c || op === 0x0a7c) {
			const imm = this.fetch16()
			if (op === 0x007c) this.sr = (this.sr | imm) & 0xffff // ORI to SR
			else if (op === 0x027c) this.sr = (this.sr & imm) & 0xffff // ANDI to SR
			else this.sr = (this.sr ^ imm) & 0xffff // EORI to SR
			return
		}
		if (op === 0x003c || op === 0x023c || op === 0x0a3c) {
			const imm = this.fetch16() & 0xff
			const ccr = this.sr & 0xff
			let next = ccr
			if (op === 0x003c) next = ccr | imm
			else if (op === 0x023c) next = ccr & imm
			else next = ccr ^ imm
			this.sr = (this.sr & 0xff00) | (next & 0xff)
			return
		}

		// TST.B / TST.W / TST.L
		if ((op & 0xff00) === 0x4a00) {
			const sizeBits = (op >> 6) & 3
			if (sizeBits <= 2) {
				const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
				const mode = (op >> 3) & 7
				const reg = op & 7
				const ea = this.resolveEa(mode, reg, size)
				const value = this.readEa(ea, size)
				this.setNzFrom(size, value)
				return
			}
		}

		// NOT.B / NOT.W / NOT.L
		if ((op & 0xff00) === 0x4600) {
			const sizeBits = (op >> 6) & 3
			if (sizeBits <= 2) {
				const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
				const mode = (op >> 3) & 7
				const reg = op & 7
				const ea = this.resolveEa(mode, reg, size)
				const value = this.readEa(ea, size)
				const result = ~value
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// BTST / BCHG / BCLR / BSET — static bit number
		if ((op & 0xff00) === 0x0800) {
			const sub = (op >> 6) & 3 // 0=BTST 1=BCHG 2=BCLR 3=BSET
			const bitImm = this.fetch16() & 0xff
			const mode = (op >> 3) & 7
			const reg = op & 7
			const size: 1 | 4 = mode === 0 ? 4 : 1 // Dn tests 32-bit; memory 8-bit
			const ea = this.resolveEa(mode, reg, size === 4 ? 4 : 1)
			const value = this.readEa(ea, size === 4 ? 4 : 1)
			const bit = size === 4 ? bitImm & 31 : bitImm & 7
			const mask = 1 << bit
			const z = (value & mask) === 0
			this.sr = (this.sr & ~0x04) | (z ? 0x04 : 0)
			if (sub === 1) this.writeEa(ea, size === 4 ? 4 : 1, value ^ mask)
			else if (sub === 2) this.writeEa(ea, size === 4 ? 4 : 1, value & ~mask)
			else if (sub === 3) this.writeEa(ea, size === 4 ? 4 : 1, value | mask)
			return
		}

		// BTST / BCHG / BCLR / BSET — dynamic (bit number in Dn)
		if ((op & 0xf100) === 0x0100 && ((op >> 6) & 3) <= 3 && (op & 0xf1c0) !== 0x0100) {
			// 0000 rrr 1ss MMM RRR with ss in 00..11 — overlaps MOVEP; skip MOVEP (mode 1)
			const mode = (op >> 3) & 7
			if (mode !== 1) {
				const sub = (op >> 6) & 3
				const dn = (op >> 9) & 7
				const reg = op & 7
				const size: 1 | 4 = mode === 0 ? 4 : 1
				const ea = this.resolveEa(mode, reg, size === 4 ? 4 : 1)
				const value = this.readEa(ea, size === 4 ? 4 : 1)
				const bit = size === 4 ? this.d[dn]! & 31 : this.d[dn]! & 7
				const mask = 1 << bit
				const z = (value & mask) === 0
				this.sr = (this.sr & ~0x04) | (z ? 0x04 : 0)
				if (sub === 1) this.writeEa(ea, size === 4 ? 4 : 1, value ^ mask)
				else if (sub === 2) this.writeEa(ea, size === 4 ? 4 : 1, value & ~mask)
				else if (sub === 3) this.writeEa(ea, size === 4 ? 4 : 1, value | mask)
				return
			}
		}

		// AND/OR/EOR with immediate to Dn via #imm forms already in 0xxx;
		// AND.B #imm,Dn as C0xx: 1100 rrr 000 111 100 = AND.B #imm, Dn
		if ((op & 0xf1bf) === 0xc03c || (op & 0xf1bf) === 0xc07c || (op & 0xf1bf) === 0xc0bc) {
			// AND #imm, Dn
			const dn = (op >> 9) & 7
			const sizeBits = (op >> 6) & 3
			const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
			const imm = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
			const cur = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
			const result = cur & imm
			this.writeEa({ dn }, size, result)
			this.setNzFrom(size, result)
			return
		}
		if ((op & 0xf1bf) === 0x803c || (op & 0xf1bf) === 0x807c || (op & 0xf1bf) === 0x80bc) {
			// OR #imm, Dn
			const dn = (op >> 9) & 7
			const sizeBits = (op >> 6) & 3
			const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
			const imm = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
			const cur = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
			const result = cur | imm
			this.writeEa({ dn }, size, result)
			this.setNzFrom(size, result)
			return
		}

		// Register shifts/rotates with immediate count
		if ((op & 0xf018) === 0xe000 || (op & 0xf018) === 0xe008 ||
			(op & 0xf018) === 0xe010 || (op & 0xf018) === 0xe018) {
			const countField = (op >> 9) & 7
			const sizeBits = (op >> 6) & 3
			if (sizeBits <= 2 && (op & 0x0020) === 0) {
				// bit 5 = 0 → immediate count; bit 5 = 1 → count in Dx (still OK with same mask area)
				const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
				const dn = op & 7
				const left = (op & 0x0100) !== 0
				const count = countField === 0 ? 8 : countField
				const mask = size === 1 ? 0xff : size === 2 ? 0xffff : 0xffffffff
				let value = this.d[dn]! & mask
				if (left) value = (value << count) & mask
				else value = (value >>> count) & mask
				this.writeEa({ dn }, size, value)
				this.setNzFrom(size, value)
				return
			}
		}

		// Memory-form shifts (word only): ASL/ASR/LSL/LSR/ROL/ROR/ROXL/ROXR <ea>
		if ((op & 0xf8c0) === 0xe0c0) {
			const mode = (op >> 3) & 7
			const reg = op & 7
			const ea = this.resolveEa(mode, reg, 2)
			let value = this.readEa(ea, 2) & 0xffff
			// Memory form: 1110 0tt 111 MMM RRR
			// 000 ASR, 001 LSR, 010 ROXR, 011 ROR, 100 ASL, 101 LSL, 110 ROXL, 111 ROL
			const kind = (op >> 9) & 7
			if (kind === 0 || kind === 1) value = value >>> 1
			else if (kind === 4 || kind === 5) value = (value << 1) & 0xffff
			else if (kind === 7 || kind === 6) value = ((value << 1) | (value >>> 15)) & 0xffff
			else value = ((value >>> 1) | ((value & 1) << 15)) & 0xffff
			this.writeEa(ea, 2, value)
			this.setNzFrom(2, value)
			return
		}

		// BRA / BSR / Bcc
		if ((op & 0xf000) === 0x6000) {
			const cond = (op >> 8) & 0xf
			let disp = op & 0xff
			let instSize = 2
			if (disp === 0) {
				disp = this.sign16(this.fetch16())
				instSize = 4
			} else {
				disp = this.sign8(disp)
			}
			const target = (opPc + 2 + disp) >>> 0
			if (cond === 0) {
				// BRA
				this.pc = target
				return
			}
			if (cond === 1) {
				// BSR
				this.sp = (this.sp - 4) >>> 0
				this.write32(this.sp, this.pc)
				this.pc = target
				return
			}
			if (this.testCc(cond)) this.pc = target
			else if (instSize === 2) {
				/* already advanced */
			}
			return
		}

		// DBcc
		if ((op & 0xf0f8) === 0x50c8) {
			const cond = (op >> 8) & 0xf
			const dn = op & 7
			const disp = this.sign16(this.fetch16())
			const target = (opPc + 2 + disp) >>> 0
			// DBcc: if cc false, Dn = Dn-1; if Dn != -1 branch
			if (!this.testCc(cond)) {
				const low = (this.d[dn]! - 1) & 0xffff
				this.d[dn] = (this.d[dn]! & 0xffff0000) | low
				if (low !== 0xffff) this.pc = target
			}
			return
		}

		// CHK <ea>, Dn — bounds check; assume in-range for sandbox (no trap).
		if ((op & 0xf1c0) === 0x4180) {
			const mode = (op >> 3) & 7
			const reg = op & 7
			// Consume EA / immediate without trapping
			if (mode === 7 && reg === 4) this.fetch16()
			else this.resolveEa(mode, reg, 2)
			return
		}

		// LEA
		if ((op & 0xf1c0) === 0x41c0) {
			const an = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			const ea = this.resolveEa(mode, reg, 4)
			if (!('addr' in ea)) throw new M68kError('LEA needs memory EA', opPc, op)
			this.a[an] = ea.addr
			return
		}

		// SWAP Dn
		if ((op & 0xfff8) === 0x4840) {
			const dn = op & 7
			const v = this.d[dn]!
			this.d[dn] = ((v & 0xffff) << 16) | (v >>> 16)
			this.setNzFrom(4, this.d[dn]!)
			return
		}

		// PEA
		if ((op & 0xffc0) === 0x4840) {
			const mode = (op >> 3) & 7
			const reg = op & 7
			const ea = this.resolveEa(mode, reg, 4)
			if (!('addr' in ea)) throw new M68kError('PEA needs memory EA', opPc, op)
			this.sp = (this.sp - 4) >>> 0
			this.write32(this.sp, ea.addr)
			return
		}

		// CLR
		if ((op & 0xff00) === 0x4200) {
			const sizeBits = (op >> 6) & 3
			const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
			const mode = (op >> 3) & 7
			const reg = op & 7
			const ea = this.resolveEa(mode, reg, size)
			this.writeEa(ea, size, 0)
			this.setNzFrom(size, 0)
			return
		}

		// MOVEQ
		if ((op & 0xf100) === 0x7000) {
			const dn = (op >> 9) & 7
			const imm = this.sign8(op & 0xff)
			this.d[dn] = imm >>> 0
			this.setNzFrom(4, imm)
			return
		}

		// MOVE.B / MOVE.W / MOVE.L / MOVEA.W / MOVEA.L
		// IMPORTANT: only opcodes 1xxx/2xxx/3xxx — using (op>>12)&3 falsely
		// matches 5xxx/6xxx/7xxx/9xxx/Bxxx/Dxxx (ADDQ, Bcc, SUB, CMP, ADD…).
		{
			const hiNibble = (op >> 12) & 0xf
			if (hiNibble === 1 || hiNibble === 2 || hiNibble === 3) {
				const size: 1 | 2 | 4 = hiNibble === 1 ? 1 : hiNibble === 3 ? 2 : 4
				const dstReg = (op >> 9) & 7
				const dstMode = (op >> 6) & 7
				const srcMode = (op >> 3) & 7
				const srcReg = op & 7

				let value: number
				if (srcMode === 7 && srcReg === 4) {
					value = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				} else {
					const sea = this.resolveEa(srcMode, srcReg, size)
					value = this.readEa(sea, size)
				}

				// MOVEA — destination mode is An; no CCR update, word is sign-extended.
				if (dstMode === 1) {
					this.a[dstReg] = size === 2 ? this.sign16(value & 0xffff) >>> 0 : value >>> 0
					return
				}

				const dea = this.resolveEa(dstMode, dstReg, size)
				this.writeEa(dea, size, value)
				this.setNzFrom(size, value)
				return
			}
		}

		// ADDQ / SUBQ
		if ((op & 0xf100) === 0x5000 || (op & 0xf100) === 0x5100) {
			const isSub = (op & 0x0100) !== 0
			let imm = (op >> 9) & 7
			if (imm === 0) imm = 8
			const sizeBits = (op >> 6) & 3
			if (sizeBits === 3) throw new M68kError('ADDQ/SUBQ size 3', opPc, op)
			const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
			const mode = (op >> 3) & 7
			const reg = op & 7
			const ea = this.resolveEa(mode, reg, size)
			const cur = this.readEa(ea, size)
			const result = isSub ? cur - imm : cur + imm
			this.writeEa(ea, size, result)
			if (mode !== 1) this.setNzFrom(size, result) // address reg ops don't set CCR the same; ignore
			return
		}

		// CMP / CMPA / EOR
		if ((op & 0xf000) === 0xb000) {
			const opmode = (op >> 6) & 7
			const dn = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			if (opmode === 0 || opmode === 1 || opmode === 2) {
				const size: 1 | 2 | 4 = opmode === 0 ? 1 : opmode === 1 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				const dst = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst - src
				this.setNzFrom(size, result)
				return
			}
			if (opmode === 3 || opmode === 7) {
				const size: 2 | 4 = opmode === 3 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				if (size === 2) src = this.sign16(src)
				const result = (this.a[dn]! >>> 0) - (src >>> 0)
				this.setNzFrom(4, result)
				return
			}
			// EOR Dn, <ea>
			if (opmode === 4 || opmode === 5 || opmode === 6) {
				const size: 1 | 2 | 4 = opmode === 4 ? 1 : opmode === 5 ? 2 : 4
				const ea = this.resolveEa(mode, reg, size)
				const dst = this.readEa(ea, size)
				const src = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst ^ src
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// MULS.W / MULU.W ea, Dn
		if ((op & 0xf1c0) === 0xc1c0 || (op & 0xf1c0) === 0xc0c0) {
			const dn = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			const signed = (op & 0x0100) !== 0
			let src: number
			if (mode === 7 && reg === 4) src = this.fetch16()
			else src = this.readEa(this.resolveEa(mode, reg, 2), 2)
			const dst = this.d[dn]! & 0xffff
			let result: number
			if (signed) result = (this.sign16(dst) * this.sign16(src)) | 0
			else result = ((dst * (src & 0xffff)) >>> 0)
			this.d[dn] = result >>> 0
			this.setNzFrom(4, result)
			return
		}

		// AND ea,Dn / AND Dn,ea
		if ((op & 0xf000) === 0xc000) {
			const opmode = (op >> 6) & 7
			const dn = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			if (opmode === 0 || opmode === 1 || opmode === 2) {
				const size: 1 | 2 | 4 = opmode === 0 ? 1 : opmode === 1 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				const dst = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst & src
				this.writeEa({ dn }, size, result)
				this.setNzFrom(size, result)
				return
			}
			if (opmode === 4 || opmode === 5 || opmode === 6) {
				const size: 1 | 2 | 4 = opmode === 4 ? 1 : opmode === 5 ? 2 : 4
				const ea = this.resolveEa(mode, reg, size)
				const dst = this.readEa(ea, size)
				const src = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst & src
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// OR ea,Dn / OR Dn,ea
		if ((op & 0xf000) === 0x8000) {
			const opmode = (op >> 6) & 7
			const dn = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			if (opmode === 0 || opmode === 1 || opmode === 2) {
				const size: 1 | 2 | 4 = opmode === 0 ? 1 : opmode === 1 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				const dst = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst | src
				this.writeEa({ dn }, size, result)
				this.setNzFrom(size, result)
				return
			}
			if (opmode === 4 || opmode === 5 || opmode === 6) {
				const size: 1 | 2 | 4 = opmode === 4 ? 1 : opmode === 5 ? 2 : 4
				const ea = this.resolveEa(mode, reg, size)
				const dst = this.readEa(ea, size)
				const src = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst | src
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// SUB / SUBA / SUBX — common forms: bits like ADD
		if ((op & 0xf000) === 0x9000) {
			const opmode = (op >> 6) & 7
			const dn = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			// SUBA
			if (opmode === 3 || opmode === 7) {
				const size: 2 | 4 = opmode === 3 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				if (size === 2) src = this.sign16(src)
				this.a[dn] = (this.a[dn]! - src) >>> 0
				return
			}
			// SUB ea, Dn
			if (opmode === 0 || opmode === 1 || opmode === 2) {
				const size: 1 | 2 | 4 = opmode === 0 ? 1 : opmode === 1 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				const dst = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst - src
				this.writeEa({ dn }, size, result)
				this.setNzFrom(size, result)
				return
			}
			// SUB Dn, ea
			if (opmode === 4 || opmode === 5 || opmode === 6) {
				const size: 1 | 2 | 4 = opmode === 4 ? 1 : opmode === 5 ? 2 : 4
				const ea = this.resolveEa(mode, reg, size)
				const dst = this.readEa(ea, size)
				const src = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst - src
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// ADD / ADDA
		if ((op & 0xf000) === 0xd000) {
			const opmode = (op >> 6) & 7
			const dn = (op >> 9) & 7
			const mode = (op >> 3) & 7
			const reg = op & 7
			if (opmode === 3 || opmode === 7) {
				const size: 2 | 4 = opmode === 3 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				if (size === 2) src = this.sign16(src)
				this.a[dn] = (this.a[dn]! + src) >>> 0
				return
			}
			if (opmode === 0 || opmode === 1 || opmode === 2) {
				const size: 1 | 2 | 4 = opmode === 0 ? 1 : opmode === 1 ? 2 : 4
				let src: number
				if (mode === 7 && reg === 4) {
					src = size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				} else {
					src = this.readEa(this.resolveEa(mode, reg, size), size)
				}
				const dst = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst + src
				this.writeEa({ dn }, size, result)
				this.setNzFrom(size, result)
				return
			}
			if (opmode === 4 || opmode === 5 || opmode === 6) {
				const size: 1 | 2 | 4 = opmode === 4 ? 1 : opmode === 5 ? 2 : 4
				const ea = this.resolveEa(mode, reg, size)
				const dst = this.readEa(ea, size)
				const src = size === 1 ? this.d[dn]! & 0xff : size === 2 ? this.d[dn]! & 0xffff : this.d[dn]!
				const result = dst + src
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// AND / OR / EOR immediate to CCR/SR — skip rare
		// ANDI / ORI / EORI / SUBI / ADDI / CMPI
		if ((op & 0xf000) === 0x0000) {
			const kind = (op >> 9) & 7
			const sizeBits = (op >> 6) & 3
			// kind 4 = BTST/BCHG/BCLR/BSET with immediate — not handled here
			if (sizeBits <= 2 && kind !== 4 && kind <= 6) {
				const size: 1 | 2 | 4 = sizeBits === 0 ? 1 : sizeBits === 1 ? 2 : 4
				const imm =
					size === 1 ? this.fetch16() & 0xff : size === 2 ? this.fetch16() : this.fetch32()
				const mode = (op >> 3) & 7
				const reg = op & 7
				if (mode === 7 && reg === 4) throw new M68kError('imm to imm', opPc, op)
				const ea = this.resolveEa(mode, reg, size)
				const dst = this.readEa(ea, size)
				let result = dst
				if (kind === 0) result = dst | imm // ORI
				else if (kind === 1) result = dst & imm // ANDI
				else if (kind === 2) result = dst - imm // SUBI
				else if (kind === 3) result = dst + imm // ADDI
				else if (kind === 5) result = dst ^ imm // EORI
				else if (kind === 6) {
					// CMPI
					this.setNzFrom(size, dst - imm)
					return
				}
				this.writeEa(ea, size, result)
				this.setNzFrom(size, result)
				return
			}
		}

		// EXT.W / EXT.L (must precede MOVEM — overlapping opcode space)
		if ((op & 0xfff8) === 0x4880 || (op & 0xfff8) === 0x48c0) {
			const dn = op & 7
			if ((op & 0xfff8) === 0x4880) {
				const b = this.sign8(this.d[dn]! & 0xff)
				this.d[dn] = (this.d[dn]! & 0xffff0000) | (b & 0xffff)
				this.setNzFrom(2, b)
			} else {
				const w = this.sign16(this.d[dn]! & 0xffff)
				this.d[dn] = w >>> 0
				this.setNzFrom(4, w)
			}
			return
		}

		// MOVEM — basic control/control-alterable forms
		if ((op & 0xfb80) === 0x4880) {
			const toReg = (op & 0x0400) !== 0
			const size: 2 | 4 = (op & 0x0040) !== 0 ? 4 : 2
			const list = this.fetch16()
			const mode = (op >> 3) & 7
			const reg = op & 7
			if (toReg) {
				let addr: number
				if (mode === 3) {
					addr = this.a[reg]! >>> 0
				} else {
					const ea = this.resolveEa(mode, reg, size)
					if (!('addr' in ea)) throw new M68kError('MOVEM needs mem', opPc, op)
					addr = ea.addr
				}
				for (let bit = 0; bit < 16; bit++) {
					if (list & (1 << bit)) {
						const v = size === 2 ? this.sign16(this.read16(addr)) >>> 0 : this.read32(addr)
						if (bit < 8) this.d[bit] = v
						else this.a[bit - 8] = v
						addr = (addr + size) >>> 0
					}
				}
				if (mode === 3) this.a[reg] = addr
			} else if (mode === 4) {
				let count = 0
				for (let i = 0; i < 16; i++) if (list & (1 << i)) count++
				let addr = (this.a[reg]! - count * size) >>> 0
				this.a[reg] = addr
				for (let bit = 0; bit < 16; bit++) {
					if (list & (1 << bit)) {
						const v = bit < 8 ? this.a[7 - bit]! : this.d[15 - bit]!
						if (size === 2) this.write16(addr, v)
						else this.write32(addr, v)
						addr = (addr + size) >>> 0
					}
				}
			} else {
				const ea = this.resolveEa(mode, reg, size)
				if (!('addr' in ea)) throw new M68kError('MOVEM needs mem', opPc, op)
				let addr = ea.addr
				for (let bit = 0; bit < 16; bit++) {
					if (list & (1 << bit)) {
						const v = bit < 8 ? this.d[bit]! : this.a[bit - 8]!
						if (size === 2) this.write16(addr, v)
						else this.write32(addr, v)
						addr = (addr + size) >>> 0
					}
				}
			}
			return
		}

		// LINK / UNLK
		if ((op & 0xfff8) === 0x4e50) {
			const an = op & 7
			const disp = this.sign16(this.fetch16())
			this.sp = (this.sp - 4) >>> 0
			this.write32(this.sp, this.a[an]!)
			this.a[an] = this.sp
			this.sp = (this.sp + disp) >>> 0
			return
		}
		if ((op & 0xfff8) === 0x4e58) {
			const an = op & 7
			this.sp = this.a[an]! >>> 0
			this.a[an] = this.read32(this.sp)
			this.sp = (this.sp + 4) >>> 0
			return
		}

		throw new M68kError('unimplemented opcode', opPc, op)
	}

	private testCc(cond: number): boolean {
		const N = this.flagN()
		const Z = this.flagZ()
		const V = this.flagV()
		const C = this.flagC()
		switch (cond) {
			case 0:
				return true // T (DBt)
			case 1:
				return false // F (DBf)
			case 2:
				return !C && !Z // HI
			case 3:
				return C || Z // LS
			case 4:
				return !C // CC
			case 5:
				return C // CS
			case 6:
				return !Z // NE
			case 7:
				return Z // EQ
			case 8:
				return !V // VC
			case 9:
				return V // VS
			case 10:
				return !N // PL
			case 11:
				return N // MI
			case 12:
				return N === V // GE
			case 13:
				return N !== V // LT
			case 14:
				return !Z && N === V // GT
			case 15:
				return Z || N !== V // LE
			default:
				return false
		}
	}
}
