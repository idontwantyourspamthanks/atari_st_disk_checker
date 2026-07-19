# DiskCheck — Atari ST disk-image tools

A small in-browser toolkit for Atari ST files and disk images. Two tools:

- **Files** — render ST text files and `.PI1` / `.NEO` / `.IFF` images.
  Drop a `.ST`, `.MSA`, or `.STX` disk image to pick a file out of it.
- **Scan** — scan `.ST` / `.MSA` / `.STX` images (or a ZIP of them) for Atari ST
  boot-sector viruses.

The scanner checks each disk's boot sector four ways: behavioural
heuristics (reset-proofing, vector hooks, encryption, MS-DOS disguise),
a signature database of ~40 catalogued ST viruses, a database of known
antivirus bootblocks so those aren't false alarms, and a 68000 sandbox
that actually *executes* the boot sector to catch viruses that hide by
relocating, decrypting, or writing themselves back to disk. Verdicts are
`infected` / `suspicious` / `protected` / `clean`, with the exact bytes
behind each finding shown in a hex viewer.

Everything runs entirely in your browser. No server, no accounts, no uploads —
your bytes stay on your machine.

## Running it

1. Unzip this archive.
2. **Open `index.html`** in any modern browser (double-click is fine).

That's it. The whole app is inlined into `index.html` (no external asset
files, no network access), so it runs identically from `file://`, a USB
stick, a network share, or a static web host.

Tested in Chrome, Firefox, Edge, Brave, and Safari.

## What's in here

```
diskcheck/
├── index.html              ← the whole app, inlined
└── README.md               ← this file
```

No installation, no telemetry, no internet connection required once you've
unzipped it.

## Hosting it on a website

Upload `index.html` to any static web host (GitHub Pages, Cloudflare Pages,
nginx, S3 + CloudFront, etc.). Hash-based links (`#/text`, `#/scan`) mean no
special server configuration is needed.

## Source code

Full source, tests, and developer documentation are in the project
repository. Clone it and see `README.md` there for `npm install`, `npm run
dev`, and deployment details.
