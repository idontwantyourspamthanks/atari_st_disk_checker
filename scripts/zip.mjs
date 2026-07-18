#!/usr/bin/env node
// Bundles the built dist/ folder into a zip ready to share, alongside a
// README explaining how to open it. Requires the production build to have
// been run already (`npm run build`); this script invokes it for you.
//
//   npm run zip
//
// Output: dist-diskcheck-<timestamp>.zip in the project root.

import { zipSync, strToU8 } from 'fflate'
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, sep } from 'node:path'
import { execSync } from 'node:child_process'

const here = dirname(fileURLToPath(import.meta.url))
const webRoot = join(here, '..')
const distDir = join(webRoot, 'dist')
const readmeSrc = join(webRoot, 'dist-README.md')

// Make sure dist is fresh.
console.log('Building production bundle…')
execSync('npm run build', { cwd: webRoot, stdio: 'inherit' })

if (!existsSync(distDir)) {
	console.error('dist/ not found after build')
	process.exit(1)
}
if (!existsSync(readmeSrc)) {
	console.error('dist-README.md not found at', readmeSrc)
	process.exit(1)
}

// Walk dist/ and add every file to the zip tree.
const tree = {}
function walk(dir, prefix) {
	for (const name of readdirSync(dir)) {
		const fullPath = join(dir, name)
		const rel = prefix ? `${prefix}/${name}` : name
		if (statSync(fullPath).isDirectory()) {
			walk(fullPath, rel)
		} else {
			tree[`diskcheck/${rel}`] = readFileSync(fullPath)
		}
	}
}
walk(distDir, '')

// Add the README at the zip root too.
tree['diskcheck/README.md'] = strToU8(readFileSync(readmeSrc, 'utf-8'))

const zipped = zipSync(tree)

const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
const outPath = join(webRoot, `diskcheck-dist-${stamp}.zip`)
writeFileSync(outPath, zipped)

const kb = (zipped.length / 1024).toFixed(1)
console.log(`\nWrote ${relative(webRoot, outPath)} (${kb} KB)`)
console.log('Contains:')
for (const path of Object.keys(tree).sort()) {
	console.log('  ' + path)
}
