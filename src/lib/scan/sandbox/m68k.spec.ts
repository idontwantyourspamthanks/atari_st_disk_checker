import { describe, it, expect } from 'vitest'
import { M68k } from './m68k'

/** Assemble big-endian words at $0 and run until RTS or limit. */
function runProgram(words: number[], setup?: (cpu: M68k) => void): M68k {
	const mem = new Uint8Array(0x1_0000)
	for (let i = 0; i < words.length; i++) {
		const w = words[i]!
		mem[i * 2] = (w >> 8) & 0xff
		mem[i * 2 + 1] = w & 0xff
	}
	const cpu = new M68k(mem)
	cpu.pc = 0
	cpu.sp = 0xf000
	// Return sentinel
	cpu.sp = (cpu.sp - 4) >>> 0
	mem[cpu.sp] = 0x00
	mem[cpu.sp + 1] = 0xe0
	mem[cpu.sp + 2] = 0x00
	mem[cpu.sp + 3] = 0x00
	setup?.(cpu)
	for (let i = 0; i < 64; i++) {
		if (cpu.pc === 0x00e00000) break
		cpu.step()
	}
	return cpu
}

describe('M68k CCR', () => {
	it('sets C on unsigned SUB borrow so BCS is taken', () => {
		// MOVEQ #1,D0 ; SUBQ.L #2,D0 ; BCS +4 ; MOVEQ #0,D1 ; RTS ; MOVEQ #1,D1 ; RTS
		// (Do not assert C after MOVEQ — MOVEQ clears C/V.)
		const cpu = runProgram([
			0x7001, // MOVEQ #1, D0
			0x5580, // SUBQ.L #2, D0
			0x6504, // BCS.S +4 → MOVEQ #1,D1
			0x7200, // MOVEQ #0, D1
			0x4e75, // RTS
			0x7201, // MOVEQ #1, D1
			0x4e75, // RTS
		])
		expect(cpu.d[1]).toBe(1)
	})

	it('SUBQ.L borrow sets C before a following MOVEQ can clear it', () => {
		const mem = new Uint8Array(0x10000)
		mem[0] = 0x70
		mem[1] = 0x01 // MOVEQ #1, D0
		mem[2] = 0x55
		mem[3] = 0x80 // SUBQ.L #2, D0
		const cpu = new M68k(mem)
		cpu.pc = 0
		cpu.step()
		cpu.step()
		expect(cpu.d[0]! >>> 0).toBe(0xffffffff)
		expect(cpu.sr & 0x01).toBe(0x01)
	})

	it('clears C on ADD without unsigned overflow so BCC is taken', () => {
		const cpu = runProgram([
			0x7001,
			0x5280, // ADDQ.L #1, D0
			0x6404, // BCC.S +4
			0x7200,
			0x4e75,
			0x7201,
			0x4e75,
		])
		expect(cpu.d[1]).toBe(1)
	})

	it('ADDQ without overflow leaves C clear', () => {
		const mem = new Uint8Array(0x10000)
		mem[0] = 0x70
		mem[1] = 0x01
		mem[2] = 0x52
		mem[3] = 0x80 // ADDQ.L #1, D0
		const cpu = new M68k(mem)
		cpu.pc = 0
		cpu.step()
		cpu.step()
		expect(cpu.d[0]).toBe(2)
		expect(cpu.sr & 0x01).toBe(0)
	})

	it('sets C on CMPI borrow without touching X', () => {
		const cpu = runProgram([
			0x7001, // MOVEQ #1, D0
			0x0c80, 0x0000, 0x0002, // CMPI.L #2, D0
			0x4e75,
		], c => {
			c.sr = 0x2700 // X clear
		})
		expect(cpu.sr & 0x01).toBe(0x01) // C
		expect(cpu.sr & 0x10).toBe(0) // X unchanged
	})
})

describe('M68k shifts', () => {
	it('ASR sign-extends', () => {
		// MOVEQ #-2,D0 ; ASR.L #1,D0 ; RTS
		const cpu = runProgram([
			0x70fe, // MOVEQ #-2, D0
			0xe280, // ASR.L #1, D0
			0x4e75,
		])
		expect(cpu.d[0]! >>> 0).toBe(0xffffffff) // -1
	})

	it('LSL shifts zeros in from the right', () => {
		const cpu = runProgram([
			0x7001, // MOVEQ #1, D0
			0xe388, // LSL.L #1, D0
			0x4e75,
		])
		expect(cpu.d[0]).toBe(2)
	})

	it('ROL.W rotates without affecting X', () => {
		const cpu = runProgram([
			0x303c, 0x8000, // MOVE.W #$8000, D0
			0xe358, // ROL.W #1, D0
			0x4e75,
		], c => {
			c.sr = 0x2710 // X set
		})
		expect(cpu.d[0]! & 0xffff).toBe(0x0001)
		expect(cpu.sr & 0x10).toBe(0x10) // X preserved
		expect(cpu.sr & 0x01).toBe(0x01) // C set (bit rotated out)
	})
})

describe('M68k Trace', () => {
	it('clears T when Trace vector is empty', () => {
		const mem = new Uint8Array(0x10000)
		// NOP ; NOP
		mem[0] = 0x4e
		mem[1] = 0x71
		mem[2] = 0x4e
		mem[3] = 0x71
		const cpu = new M68k(mem)
		cpu.pc = 0
		cpu.sr = 0xa700 // T set, supervisor
		// $24 = 0
		cpu.step()
		expect(cpu.sr & 0x8000).toBe(0)
		expect(cpu.pc).toBe(2)
	})
})
