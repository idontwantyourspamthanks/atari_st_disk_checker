#!/usr/bin/env node
// Generates a small Atari ST / FAT12 .st disk-image fixture for the FAT12
// walker's integration test, plus an .msa version encoded from it. Requires
// GNU mtools (mformat / mcopy / mmd) on PATH.
//
// Output:
//   src/lib/disk/__fixtures__/sample.st
//   src/lib/disk/__fixtures__/sample.msa
//
// The image contains a known set of files so the test can assert against them:
//
//   /HELLO.TXT      "Hello, Atari ST!\r\n"
//   /READ.ME        "This is diskcheck's fixture image.\r\n"
//   /SUB/INSIDE.TXT "I live in a subdirectory.\r\n"

import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
const here = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(here, '..', 'src', 'lib', 'disk', '__fixtures__')
const tmpDir = join(fixturesDir, '.tmp')

const stPath = join(fixturesDir, 'sample.st')
const msaPath = join(fixturesDir, 'sample.msa')

console.log('Cleaning previous fixtures…')
rmSync(fixturesDir, { recursive: true, force: true })
mkdirSync(tmpDir, { recursive: true })

console.log('Building .st image with mtools…')
// 720KB double-sided double-density — standard Atari ST floppy geometry.
// mformat requires the target file to pre-exist (LemonAndLime's st_disk_image.rb
// does the same pre-zeroing).
const SECTOR_SIZE = 512
const TOTAL_SECTORS_720KB = 1440
writeFileSync(stPath, Buffer.alloc(SECTOR_SIZE * TOTAL_SECTORS_720KB))
execSync(`mformat -i "${stPath}" -f 720 ::`, { stdio: 'inherit' })
execSync(`mmd -i "${stPath}" ::/SUB`, { stdio: 'inherit' })

// Write the known-content files into a scratch dir, then mcopy them in.
const files = {
	'HELLO.TXT':  'Hello, Atari ST!\r\n',
	'READ.ME':    "This is diskcheck's fixture image.\r\n",
	'SUB/INSIDE.TXT': 'I live in a subdirectory.\r\n',
}
for (const [name, content] of Object.entries(files)) {
	const baseName = name.split('/').pop()
	writeFileSync(join(tmpDir, baseName), content, 'latin1')
	const localPath = join(tmpDir, baseName)
	const target = `::/${name}`
	execSync(`mcopy -i "${stPath}" "${localPath}" "${target}"`, { stdio: 'inherit' })
}

console.log('Encoding .msa from .st…')
// We hand-encode a minimal MSA from the .st — there's no standard CLI tool
// for .msa on Linux. Run via a small inline JS module that loads ./msa-encode.mjs.
execSync(`node "${join(here, 'msa-encode.mjs')}" "${stPath}" "${msaPath}"`, {
	stdio: 'inherit',
})

console.log('Encoding .stx from .st…')
execSync(`node "${join(here, 'stx-encode.mjs')}"`, { stdio: 'inherit' })

rmSync(tmpDir, { recursive: true, force: true })
const stxPath = join(fixturesDir, 'sample.stx')
console.log(`Wrote:\n  ${stPath}\n  ${msaPath}\n  ${stxPath}`)
