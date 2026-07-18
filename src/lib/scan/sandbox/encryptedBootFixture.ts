/**
 * Synthetic XOR-encrypted boot sector for sandbox tests.
 *
 * Layout (after BRA over BPB to $3E):
 *   decrypt stub  — MOVEA.L #payload,A0 / MOVE.W #len-1,D0 /
 *                   EORI.B #key,(A0)+ / DBF D0,*-6
 *   encrypted body — residency install + Ghost MOVE.L #π,D0 needle
 *
 * Static scan sees no Ghost / no π stores; after the stub runs, in-place
 * decrypt reveals both the signature and the reset-proof / hdv hooks.
 */

import { BOOT_SECTOR_SIZE, ST_BOOT_SECTOR_EXE_SUM, bootSectorChecksum } from '../bootSector'

const KEY = 0x5a

/** Plaintext payload that runs after decrypt (absolute addresses). */
function plaintextPayload(): number[] {
	return [
		// MOVE.L #$31415926, $426 — reset-proof magic
		0x23, 0xfc, 0x31, 0x41, 0x59, 0x26, 0x00, 0x00, 0x04, 0x26,
		// MOVE.L #$5000, $472 — hdv_bpb hook
		0x23, 0xfc, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x04, 0x72,
		// MOVE.L #$31415926, D0 — Ghost bytes-scan needle
		0x20, 0x3c, 0x31, 0x41, 0x59, 0x26,
		// RTS
		0x4e, 0x75,
	]
}

function fixChecksum(boot: Uint8Array): void {
	let sum = 0
	for (let i = 0; i < 254; i++) {
		sum = (sum + ((boot[i * 2]! << 8) | boot[i * 2 + 1]!)) & 0xffff
	}
	const last = ((boot[0x1fe]! << 8) | boot[0x1ff]!) & 0xffff
	const tuning = (ST_BOOT_SECTOR_EXE_SUM - sum - last) & 0xffff
	boot[0x1fc] = tuning >> 8
	boot[0x1fd] = tuning & 0xff
	if (bootSectorChecksum(boot) !== ST_BOOT_SECTOR_EXE_SUM) {
		throw new Error('encrypted boot checksum fixup failed')
	}
}

/**
 * Build an executable boot whose interesting body is XOR-encrypted.
 * @param key XOR key (default 0x5A)
 */
export function buildXorEncryptedBoot(key = KEY): Uint8Array {
	const boot = new Uint8Array(BOOT_SECTOR_SIZE)
	// BRA.B to $3E
	boot[0] = 0x60
	boot[1] = 0x3c
	// Plausible BPB
	boot[0x0b] = 0x00
	boot[0x0c] = 0x02
	boot[0x0d] = 2
	boot[0x15] = 0xfd
	boot[0x16] = 5

	const plain = plaintextPayload()
	const stubOff = 0x3e
	// Stub length: MOVEA.L #abs (6) + MOVE.W #n (4) + EORI (4) + DBF (4) = 18
	const stubLen = 18
	const payloadOff = stubOff + stubLen
	// Absolute load address of payload when boot is mapped at $4000
	const payloadAbs = 0x4000 + payloadOff

	const stub: number[] = [
		// MOVEA.L #payloadAbs, A0
		0x20, 0x7c,
		(payloadAbs >>> 24) & 0xff,
		(payloadAbs >>> 16) & 0xff,
		(payloadAbs >>> 8) & 0xff,
		payloadAbs & 0xff,
		// MOVE.W #len-1, D0
		0x30, 0x3c,
		0x00, (plain.length - 1) & 0xff,
		// loop: EORI.B #key, (A0)+
		0x0a, 0x18, 0x00, key & 0xff,
		// DBF D0, loop — disp = -6
		0x51, 0xc8, 0xff, 0xfa,
	]
	if (stub.length !== stubLen) {
		throw new Error(`stub length mismatch: ${stub.length}`)
	}

	boot.set(stub, stubOff)
	for (let i = 0; i < plain.length; i++) {
		boot[payloadOff + i] = plain[i]! ^ key
	}

	// Pad remaining code region with more XOR'd pseudo-noise so entropy
	// heuristics notice a packed-looking payload (optional but useful).
	for (let i = payloadOff + plain.length; i < 0x1c0; i++) {
		boot[i] = ((i * 17) ^ key ^ 0xa5) & 0xff
	}

	fixChecksum(boot)
	return boot
}

/** Same boot with the body left in clear (control: static scan should see Ghost). */
export function buildCleartextSiblingBoot(): Uint8Array {
	const boot = buildXorEncryptedBoot(0) // key 0 = clear
	return boot
}
