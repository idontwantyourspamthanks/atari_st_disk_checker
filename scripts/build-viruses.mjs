#!/usr/bin/env node
/**
 * Build the synthetic bootsector-virus corpus images.
 *
 * For each virus: assemble with vasm (org 0, raw binary), create a fresh
 * 720K image with mformat, splice the virus into sector 0 while preserving
 * the mformat BPB at $02-$1D, fix the 256-word big-endian sum to $1234,
 * and write the image into ../diskimages/.
 *
 * Usage: node scripts/build-viruses.mjs
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const web = join(here, '..')
const outDir = join(web, '..', 'diskimages')
const tmpDir = join(web, 'tools', 'build')
const VASM = join(web, 'tools', 'vasmm68k_mot')

const VIRUSES = [
	{ src: 'synth1-dad.s', out: 'virus synth 1 dad.st' },
	{ src: 'synth2-mouse.s', out: 'virus synth 2 mouse.st' },
	{ src: 'synth3-nerd.s', out: 'virus synth 3 nerd.st' },
]

if (!existsSync(VASM)) {
	console.error('vasm not found at tools/vasmm68k_mot — see Task 1 of the plan')
	process.exit(1)
}
mkdirSync(tmpDir, { recursive: true })
mkdirSync(outDir, { recursive: true })

for (const v of VIRUSES) {
	const srcPath = join(here, 'viruses', v.src)
	if (!existsSync(srcPath)) {
		console.log(`skip ${v.src} (not present yet)`)
		continue
	}
	const bin = join(tmpDir, v.src.replace(/\.s$/, '.bin'))
	execFileSync(VASM, ['-Fbin', '-nosym', '-o', bin, srcPath], { stdio: 'inherit' })
	const virus = readFileSync(bin)
	if (virus.length > 510) {
		throw new Error(`${v.src}: ${virus.length} bytes — too big for a boot sector (max 510)`)
	}

	// Fresh 720K image; mformat writes a DOS-style boot sector with a BPB.
	const img = join(tmpDir, v.out)
	execFileSync('mformat', ['-f', '720', '-C', '-i', img, '::'], { stdio: 'inherit' })
	const disk = readFileSync(img)
	if (disk.length !== 720 * 1024) throw new Error(`unexpected image size ${disk.length}`)

	// Splice: our BRA at $00-$01, keep mformat bytes $02-$1D (OEM+BPB),
	// zero the rest, then our body from $1E.
	const sector = Buffer.alloc(512)
	disk.copy(sector, 0, 0, 512)
	sector.fill(0, 0x1e, 0x1fe)
	virus.copy(sector, 0, 0, 2)
	virus.copy(sector, 0x1e, 0x1e)

	// Checksum: 256 big-endian words must sum to $1234. Fix the last word.
	let sum = 0
	for (let i = 0; i < 0x1fe; i += 2) sum = (sum + sector.readUInt16BE(i)) & 0xffff
	sector.writeUInt16BE((0x1234 - sum) & 0xffff, 0x1fe)

	// Paranoia: verify.
	let check = 0
	for (let i = 0; i < 0x200; i += 2) check = (check + sector.readUInt16BE(i)) & 0xffff
	if (check !== 0x1234) throw new Error('checksum fixup failed')

	sector.copy(disk, 0)
	const outPath = join(outDir, v.out)
	writeFileSync(outPath, disk)
	console.log(`wrote ${outPath} (virus body ${virus.length} bytes)`)
}
