# DiskCheck

Browser-only tools for Atari ST disk images. No backend, no accounts, no
uploads — every byte stays on the machine you're browsing from.

| Tool | What it does |
|------|----------------|
| **Files** | Render ST text and image formats (`.PI1`, `.NEO`, `.IFF`, …). Drop a `.ST`, `.MSA`, or `.STX` disk image to browse files inside it. |
| **Scan** | Heuristic + signature boot-sector virus scanner for `.ST` / `.MSA` / `.STX` images, including ZIP batches. |

The production build is a single self-contained `index.html` (~350 KB) that
runs from `file://` in any modern browser — no server required.

---

## How the virus scanner works

The scanner analyses the **boot sector** (sector 0, 512 bytes) of each disk
image. `.MSA` and `.STX` images are decoded to raw sectors first; ZIPs are
unpacked in-browser and each image inside is scanned in turn.

Everything hinges on one fact about TOS: after reading a boot sector, TOS
sums its 256 big-endian words and, **only if the checksum equals `0x1234`,
jumps to offset 0 and runs it**. That single rule both defines what a boot
virus must do to live (make its sector executable) and what an immunized
disk looks like (carry a virus's marker bytes *without* the executable
checksum) — so the scanner can tell "infected with X" apart from
"vaccinated against X" instead of crying wolf.

Four detection layers run over every boot sector, in sequence:

### 1. Heuristics — the primary detector

Behavioural checks catch *unknown* viruses and new variants, which is why
they — not the signature database — are the primary layer:

- **Executable boot sector** with a recognised 68000 entry opcode, or with
  a substantial code payload despite a disguised entry byte.
- **Reset-proofing**: the π magic longword `$31415926` (Ghost's signature
  move), and `MOVE.L` stores to the TOS `resvalid`/`resvector` system
  variables that let code survive a warm reset.
- **Residency hooks**: `MOVE.L` stores to the Trap #1/#13/#14 vectors or
  the `hdv_*` disk vectors — how a virus stays in memory and infects disks
  on later access.
- **High-entropy payload**: Shannon entropy ≥ 7 bits/byte over the code
  region suggests an encrypted or polymorphic body.
- **Evasion shapes**: a TOS-executable sector dressed as an MS-DOS boot
  sector (the Zorro A / Pharaoh disguise), runnable code with a corrupted
  BPB, or an entry branch that leaves the code region.

### 2. Signature database — naming the virus

~40 catalogued ST boot viruses (Signum, Ghost, Kobold, Beilstein, …),
sourced from Ultimate Virus Killer 2000 and retrovirology.ca with
per-entry traceability (UVK catalogue number, year, origin, confidence).
Patterns come in four kinds: exact bytes at a fixed offset,
case-insensitive ASCII, byte sequences anywhere, and **masked hex** with
`??`/nibble wildcards for polymorphic families whose bytes vary per copy.

The database is deliberately conservative: UVK "immunization" markers are
often shared with legitimate boot loaders, so viruses documented only by a
too-broad marker (Mad A, Puke, Macumba 3.3, …) ship with no pattern and
are left to the heuristic and sandbox layers rather than risk false
positives.

### 3. Protector database — avoiding false alarms

~35 known antivirus / demo-crew bootblocks (Sagrotan, UVK/AVK, FastCopy,
Medway Boys, …). A named protector explains an executable boot sector, so
the generic boot-code heuristics are demoted to informational — while
genuinely alarming sandbox evidence stays loud.

### 4. 68000 sandbox — executing the suspect

The boot sector runs in a small hand-written 68000 emulator (up to 50,000
instructions, with loop/spin detection) inside a 1 MiB scratch RAM seeded
with TOS system variables. While it runs, the sandbox watches for:

- writes to trap / `hdv_*` / `etv_*` vectors and `resvalid`/`resvector`
  (residency and reset-proof installs),
- **_memtop/_membot tampering** — carving out RAM to hide resident code,
- **boot-sector write attempts** via BIOS `Rwabs` or XBIOS `Flopwr` —
  self-propagation, the defining behaviour of a boot virus,
- **relocated or decrypted virus bodies**: after the run, every dirty
  memory page (plus a high-RAM band when residency is hinted) is
  re-scanned against the signature database, catching viruses that only
  reveal themselves after decrypting in place — something no static scan
  can see.

### Verdicts

Findings are fused into one status per disk:

| Status | Meaning |
|--------|---------|
| `infected` | A named virus signature matched on a live, executable boot sector. |
| `suspicious` | No named virus, but high/medium heuristic or sandbox evidence (e.g. reset-proofing, propagation attempts). |
| `protected` | A known antivirus/protector bootblock, nothing hostile. |
| `clean` | Nothing concerning. |

Each finding highlights the exact bytes that tripped it in the built-in
hex viewer, and batch scans export to JSON/CSV. The design rule
throughout: **behaviour first, names second** — a brand-new virus with no
signature should still light up the heuristic and sandbox layers.

---

## Use it (no install)

**Downloaded the zip?** That's the intended end-user experience.

1. Unzip `diskcheck-dist-*.zip`.
2. Open `diskcheck/index.html` in Chrome, Firefox, Edge, Brave, or Safari.

Double-clicking `index.html` works on most systems. The whole app is inlined
into that one file — no extra assets, no network access, no installation.

---

## Develop locally

**Requirements:** [Node.js](https://nodejs.org/) 20+ (LTS recommended) and npm.

```bash
git clone <your-repo-url>
cd diskcheck          # this repository root
npm install
npm run dev           # http://localhost:5173
```

Other useful commands:

```bash
npm test              # run the test suite once
npm run test:watch    # vitest in watch mode
npm run build         # production build → dist/
npm run preview       # serve dist/ locally at http://localhost:4173
```

`npm run preview` is the quickest way to sanity-check the production bundle
before you zip it or upload it anywhere.

---

## Build a distribution zip

```bash
npm run zip
```

This runs a production build and writes `diskcheck-dist-<timestamp>.zip` in
the project root. The archive contains:

```
diskcheck/
├── index.html    ← the whole app, inlined
└── README.md     ← short instructions for whoever receives the zip
```

Share that zip as-is. Recipients do not need Node.js.

---

## Deploy remotely

DiskCheck is a static site. Deploy the contents of `dist/` (effectively just
`index.html`) to any static host. No server-side code, database, or API keys.

Because the build uses **relative asset paths** (`base: './'` in
`vite.config.ts`) and **hash routing** (`#/text`, `#/scan`), it works when:

- hosted at a domain root (`https://example.com/`)
- hosted in a subdirectory (`https://example.com/diskcheck/`)
- opened from `file://` after download

No URL rewrites or SPA fallback rules are required.

### GitHub Pages

1. `npm run build`
2. Push `dist/` to a `gh-pages` branch, or use a GitHub Action that runs
   `npm ci && npm run build` and publishes `dist/`.
3. In the repo's **Settings → Pages**, set the source to that branch / the
   `dist` folder (depending on your workflow).

If you use a project site (`https://<user>.github.io/<repo>/`), the relative
`base` already points assets at the right place — no config change needed.

### Cloudflare Pages

1. Connect the repository.
2. **Build command:** `npm run build`
3. **Build output directory:** `dist`
4. **Node version:** 20 or later (set in Environment variables if needed).

### nginx (or any static file server)

Copy `dist/index.html` to your web root (or a subdirectory):

```bash
npm run build
rsync -a dist/ /var/www/diskcheck/
```

A minimal nginx location block is enough — no `try_files` fallback to
`index.html` for client routes, because routing is hash-based:

```nginx
location /diskcheck/ {
    alias /var/www/diskcheck/;
    index index.html;
}
```

### Verify after deploy

Open the site and check both tools load:

- `https://your-host/#/` — home
- `https://your-host/#/text` — file viewer
- `https://your-host/#/scan` — virus scanner

---

## How the build works

| Setting | Why |
|---------|-----|
| `base: './'` | Relative paths — works under `file://` and in subdirectories. |
| `vite-plugin-singlefile` | Inlines all JS/CSS into one `index.html`. Fixes Firefox blocking module scripts over `file://`. |
| `createWebHashHistory()` | Links become `index.html#/text`, not `/text`, so they work without a server rewriting paths. |

---

## Tests

```bash
npm test
```

Fixture images under `src/lib/**/__fixtures__/` are checked in so tests run
offline. To regenerate disk-image fixtures (requires GNU `mtools`):

```bash
npm run gen:fixtures
```

Image-parser fixtures are pure JS:

```bash
npm run gen:image-fixtures
```

### Optional local scanner corpus

For deeper scanner regression against a folder of real images, create
`diskimages/` at the repo root (gitignored). Name files by class:
`virus*`, `prot*`, `other*`. `src/lib/scan/diskimages.corpus.spec.ts` picks
this up automatically and skips cleanly when the folder is absent.

---

## Regenerating the charset table

The Atari ST → Unicode table in `src/lib/charsets/atariST.ts` is generated
from the Unicode Consortium mapping checked in at `scripts/ATARIST.TXT`:

```bash
npm run gen:atarist
```

To refresh from upstream:

```bash
curl -o scripts/ATARIST.TXT \
  https://www.unicode.org/Public/MAPPINGS/VENDORS/MISC/ATARIST.TXT
npm run gen:atarist
```

---

## Stack

| Layer | Choice |
|-------|--------|
| Framework | Vue 3 + TypeScript |
| Build | Vite |
| Test | Vitest + jsdom |
| Deploy target | Any static host |

---

## Project layout

```
├── dist-README.md           # README bundled into distribution zips
├── scripts/
│   ├── gen-atarist.mjs      # generates src/lib/charsets/atariST.ts
│   ├── gen-fixtures.mjs     # disk-image fixtures (needs mtools)
│   ├── gen-image-fixtures.mjs
│   ├── msa-encode.mjs
│   ├── stx-encode.mjs
│   └── zip.mjs              # npm run zip
└── src/
    ├── lib/                 # disk, image, scan, charset logic
    ├── components/
    ├── views/
    ├── App.vue
    ├── main.ts
    ├── router.ts
    └── style.css
```
