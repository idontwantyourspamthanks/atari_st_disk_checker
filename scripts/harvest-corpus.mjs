#!/usr/bin/env node
/**
 * Corpus harvester, stage 1: download a CD-image zip and recursively
 * extract Atari ST disk images (.st/.msa/.stx) out of it (including zips
 * nested inside zips, to depth 3).
 *
 * Usage: node scripts/harvest-corpus.mjs <cdZipUrl> <label>
 *   e.g. node scripts/harvest-corpus.mjs "https://ftp.pigwa.net/stuff/.../CD1of5.zip" cd1
 *
 * Writes ../diskimages/_staging/<label>/… and candidates.json.
 * Classification happens in src/lib/scan/harvest.probe.spec.ts (stage 2).
 */
import { execFileSync, execSync } from 'node:child_process'
import {
	existsSync, mkdirSync, readdirSync, statSync, writeFileSync, readFileSync,
} from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import zlib from 'node:zlib'

const [url, label = 'cd1'] = process.argv.slice(2)
if (!url) {
	console.error('usage: node scripts/harvest-corpus.mjs <cdZipUrl> <label>')
	process.exit(1)
}

const here = dirname(fileURLToPath(import.meta.url))
const staging = join(here, '..', '..', 'diskimages', '_staging')
const work = join(staging, label)
mkdirSync(work, { recursive: true })

const zipPath = join(staging, `${label}.zip`)

// --- 1. disk space guard (need ~4x zip size free) ---
const df = execSync(`df -k ${JSON.stringify(staging)}`).toString().trim().split('\n').pop()
const freeKb = parseInt(df.trim().split(/\s+/)[3], 10)
if (freeKb < 4 * 1024 * 1024) throw new Error(`low disk space: ${freeKb} KiB free`)

// --- 2. download (skip if cached) ---
if (!existsSync(zipPath)) {
	console.log(`downloading ${url}`)
	execFileSync('curl', ['-fSL', '--retry', '3', '-C', '-', '-o', zipPath, url], { stdio: 'inherit' })
} else {
	console.log(`cached: ${zipPath} (${statSync(zipPath).size} bytes)`)
}

// --- 3. best-effort CRC32 vs sibling .sfv (warn only) ---
try {
	const sfvUrl = url.replace(/\.zip$/i, '.sfv')
	const sfv = execFileSync('curl', ['-fsSL', sfvUrl]).toString()
	const m = sfv.match(/([0-9A-Fa-f]{8})\s*$/m)
	if (m) {
		let crc = 0
		const buf = readFileSync(zipPath)
		const CHUNK = 1 << 20
		for (let i = 0; i < buf.length; i += CHUNK) crc = zlib.crc32(buf.subarray(i, i + CHUNK), crc)
		const got = (crc >>> 0).toString(16).toUpperCase().padStart(8, '0')
		console.log(got === m[1].toUpperCase() ? 'CRC32 OK' : `CRC32 MISMATCH: got ${got}, want ${m[1]} (continuing anyway)`)
	}
} catch { console.log('sfv check skipped') }

// --- 4. extract top-level CD zip ---
console.log('extracting CD zip (this takes a while)')
execFileSync('unzip', ['-o', '-q', zipPath, '-d', work], { stdio: 'inherit' })

// --- 5. recursively pull disk images out of nested zips ---
const IMG = /\.(st|msa|stx)$/i
const ZIP = /\.zip$/i

function* walk(dir) {
	for (const e of readdirSync(dir, { withFileTypes: true })) {
		const p = join(dir, e.name)
		if (e.isDirectory()) yield* walk(p)
		else yield p
	}
}

const candidates = []
let frontier = [...walk(work)].filter(p => ZIP.test(p))
const seen = new Set()
for (let depth = 0; depth < 3 && frontier.length > 0; depth++) {
	const next = []
	for (const z of frontier) {
		if (seen.has(z)) continue
		seen.add(z)
		const dest = join(work, '_unzipped', relative(work, z).replace(/[\\/]/g, '__'))
		mkdirSync(dest, { recursive: true })
		// -C: case-insensitive patterns; keep paths (no -j) to avoid collisions
		try {
			execFileSync('unzip', ['-o', '-q', '-C', z, '*.st', '*.msa', '*.stx', '*.zip', '-d', dest], { stdio: 'pipe' })
		} catch { /* unzip exits 1 when no member matched — fine */ }
		for (const p of walk(dest)) {
			if (IMG.test(p)) candidates.push({ path: p, source: relative(work, z) })
			else if (ZIP.test(p)) next.push(p)
		}
	}
	frontier = next
}

// top-level loose images too
for (const p of walk(work)) {
	if (IMG.test(p) && !p.includes('_unzipped')) candidates.push({ path: p, source: '(toplevel)' })
}

writeFileSync(join(staging, 'candidates.json'), JSON.stringify(candidates, null, 1))
console.log(`candidates: ${candidates.length} disk images -> ${join(staging, 'candidates.json')}`)
