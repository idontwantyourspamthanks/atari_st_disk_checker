/**
 * Synthesized bootsector viruses — web/scripts/viruses/*.s built by
 * web/scripts/build-viruses.mjs into the gitignored diskimages/ corpus.
 * Skips cleanly when the images have not been built.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { scanImage } from './scanner'
import { getBootSector } from './bootSector'
import { runBootSandbox } from './sandbox/bootSandbox'

const dir = join(import.meta.dirname, '..', '..', '..', '..', 'diskimages')

export const DAD = 'virus synth 1 dad.st'
export const MOUSE = 'virus synth 2 mouse.st'
export const NERD = 'virus synth 3 nerd.st'

function load(name: string) {
	const bytes = new Uint8Array(readFileSync(join(dir, name)))
	return { bytes, report: scanImage(bytes, name), boot: getBootSector(bytes) }
}

function bootText(boot: Uint8Array): string {
	return Buffer.from(boot).toString('latin1')
}

describe('synthesized bootsector viruses', () => {
	it('dad: reset-resident, propagating, prints its message', () => {
		if (!existsSync(join(dir, DAD))) return
		const { report, boot } = load(DAD)

		expect(report.bootSectorChecksum).toBe(0x1234)
		expect(report.bootSectorExecutable).toBe(true)
		expect(report.status).toBe('suspicious')
		const names = report.findings.map(f => f.name)
		expect(names).toContain('Sandbox: reset-proof install')
		expect(names).toContain('Sandbox: system vector hook')
		expect(names).toContain('Sandbox: boot-sector write attempt')
		expect(bootText(boot)).toContain('dad.prg woz ere')

		const r = runBootSandbox(boot)
		expect(['return', 'loop', 'limit']).toContain(r.haltReason)
		expect(r.resetProofMagic).toBe(true)
		expect(r.resetProofVector).toBe(true)
		expect(r.hooks).toContain('hdv_bpb')
		expect(r.bootWrites.length).toBeGreaterThan(0)
	})

	it('mouse: reset-resident, propagating, hooks mouse vector, no message', () => {
		if (!existsSync(join(dir, MOUSE))) return
		const { report, boot } = load(MOUSE)

		expect(report.bootSectorChecksum).toBe(0x1234)
		expect(report.status).toBe('suspicious')
		const names = report.findings.map(f => f.name)
		expect(names).toContain('Sandbox: reset-proof install')
		expect(names).toContain('Sandbox: system vector hook')
		expect(names).toContain('Sandbox: boot-sector write attempt')
		expect(bootText(boot)).not.toContain('woz ere')

		const r = runBootSandbox(boot)
		expect(['return', 'loop', 'limit']).toContain(r.haltReason)
		expect(r.resetProofMagic).toBe(true)
		expect(r.resetProofVector).toBe(true)
		expect(r.hooks).toContain('hdv_bpb')
		expect(r.bootWrites.length).toBeGreaterThan(0)
	})

	it('nerd: propagates in-session but does NOT survive reset', () => {
		if (!existsSync(join(dir, NERD))) return
		const { report, boot } = load(NERD)

		expect(report.bootSectorChecksum).toBe(0x1234)
		expect(report.status).toBe('suspicious')
		const names = report.findings.map(f => f.name)
		expect(names).not.toContain('Sandbox: reset-proof install')
		expect(names).toContain('Sandbox: system vector hook')
		expect(names).toContain('Sandbox: boot-sector write attempt')
		expect(bootText(boot)).toContain('this disk is infected by AI nerd magic')

		const r = runBootSandbox(boot)
		expect(['return', 'loop', 'limit']).toContain(r.haltReason)
		expect(r.resetProofMagic).toBe(false)
		expect(r.resetProofVector).toBe(false)
		expect(r.hooks).toContain('hdv_bpb')
		expect(r.bootWrites.length).toBeGreaterThan(0)
	})
})
