.arch armv8-a
.global _start

_start:
    // Restore original bytes in read() through mem file
        mov     x8, #0x3e
        mov     x0, #3
        mov     x1, #-0x10
        mov     x2, #1     // SEEK_CUR
        svc     #0         // lseek
        mov     x8, #0x40
        mov     x0, #3
        adr     x1, data
        add     x1, x1, #0x28
        mov     x2, #0x10
        svc     #0         // write

    // Read ELF in memory
        mov     x8, #0xde // mmap
        mov     x2, #3    // RW
        mov     x3, #0x22 // MAP_ANON | MAP_PRIVATE
        movn    x4, #0    // -1
        mov     x5, #0
        adr     x19, data
        ldr     x1, [x19] // lib_fsize
        mov     x0, #0
        svc     #0
        ldr     x25, [x19, #0x20] // stack_top
        str     x0,  [x25, #-8]   // lib_addr
        stp     xzr, xzr, [x25, #-0x18]
        mov     x8, #0x3f // read
        mov     x2, x1
        mov     x1, x0
        mov     x0, #9 // fd
        svc     #0

    // Install signal handler for SIGILL
        mov     x9, #0xa
    memset:
        stp     xzr, xzr, [sp, #-0x10]!
        subs    x9, x9, #1
        bne     memset
        adr     x9, sigill_handler
        str     x9, [sp]  // Now we have a struct sigaction in stack
        mov     x0, #4    // SIGILL
        mov     x1, sp
        mov     x2, #0
        mov     x3, #8
        mov     x8, #0x86 // sigaction
        svc     #0

    // Change svc #0 instructions in loader with undefined ones
        mov     x8, #0xe2         // mprotect
        ldr     x10, [x19, #0x08] // ld_end_addr
        ldr     x9,  [x19, #0x10] // ld_start_addr
        sub     x1, x10, x9
        mov     x2, #3 // RW
        mov     x0, x9
        svc     #0 // mprotect
        bl      search_syscall
        sub     x1, x10, x9
        mov     x2, #5 // RX
        mov     x0, x9
        svc     #0 // mprotect

    // Call dlopen(FAKE_LIB, RTLD_NOW | RTLD_GLOBAL)
        ldr     x2, [x19, #0x18] // libdl base address
        add     x2, x2, #0x1000
        add     x2, x2, #0x0100  // dlopen offset = 0x1100
        adr     x0, FAKE_LIB
        mov     x1, #0x102 // RLTD_NOW | RTLD_GLOBAL
        blr     x2

        adr     x19, data
        ldr     x19, [x19, #0x20] // stack_top
        ldr     x13, [x19, #-0x18] // lib_base
        add     x13, x13, #0x0780 // entrypoint
        add     x13, x13, #0x5000
        blr     x13
        .word   0xfabada // won't be hit



search_syscall:
        mov     x0, x9
        movz    x1, #0xd400, lsl #0x10
        orr     x1, x1, #1
        b       check
    loop:
        ldr     w2, [x0], #4
        cmp     w2, w1
        bne     check
        str     wzr, [x0, #-4]
    check:
        cmp     x0, x10
        blo     loop
        ret

sigill_handler:
        // Can't leave PC pointing to ILL instruction
        ldr     x9, [sp, #0x238]
        add     x9, x9, #4
        str     x9, [sp, #0x238]

        // All arguments intended for the syscall
        ldp     x0, x1, [sp, #0x138]
        ldp     x2, x3, [sp, #0x148]
        ldp     x4, x5, [sp, #0x158]
        ldr     x8, [sp, #0x178]

        adr     x19, data
        ldr     x25, [x19, #0x20] // stack_top
        mov     x11, #0x1337

        cmp     x8, #0x3f
        beq     sim_read
        cmp     x8, #0xde
        beq     sim_mmap
        cmp     x8, #0x38
        beq     sim_openat
        cmp     x8, #0x50
        beq     sim_fstat
        cmp     x8, #0x4f
        beq     sim_newfstatat
        cmp     x8, #0x39
        beq     sim_close
        b       legit_syscall

sim_read:
        cmp     x0, x11
        bne     legit_syscall
        mov     x11, #0
        ldr     x20, [x25, #-8]    // lib_addr
        ldr     x21, [x25, #-0x10] // fakefp
        add     x12, x20, x21 // x12 = lib_addr + fakefp
    sim_read_1:
        cmp     x11, x2
        beq     sim_read_2
        ldrb    w10, [x12, x11]
        strb    w10, [ x1, x11]
        add     x11, x11, #1
        b       sim_read_1
    sim_read_2:
        str     x2, [sp, #0x138]
        add     x21, x21, x2
        str     x21, [x25, #-0x10]
        ret

sim_mmap:
        cmp     x4, x11
        bne     legit_syscall
        mov     x13, x2
        mov     x14, x5
        mov     x2, #3        // RW
        and     x3, x3, #0x10 // MAP_FIXED
        mov     x11, 0x22
        orr     x3, x3, x11   // MAP_ANON | MAP_PRIVATE
        movn    x4, #0        // -1
        mov     x5, #0
        svc     #0
        cmp     x14, #0
        bne     sim_mmap_1
        str     x0, [x25, #-0x18] // lib_base
    sim_mmap_1:
        str     x0, [sp, #0x138]
        add     x11, x1, x14 // x11 = size + offset
        ldr     x19, [x19]   // lib_fsize
        cmp     x11, x19
        bls     sim_mmap_2
        sub     x19, x19, x14
    sim_mmap_2: // memcpy
        mov     x11, #0
        ldr     x20, [x25, #-8] // lib_addr
        add     x12, x20, x14
    sim_mmap_3:
        cmp     x11, x19
        beq     sim_mmap_4
        ldrb    w10, [x12, x11]
        strb    w10, [ x0, x11]
        add     x11, x11, #1
        b       sim_mmap_3
    sim_mmap_4:
        mov     x8, #0xe2 // mprotect
        mov     x2, x13
        svc     #0
        ret

sim_openat:
        mov     x9, x1
    sim_openat_1:
        ldrb    w12, [x9], #1
        cmp     x12, #0
        bne     sim_openat_1
        sub     x9, x9, #1 // x9 pointing to null terminator
    sim_openat_2:
        ldrb    w12, [x9, #-1]!
        cmp     x12, #0x2f // '/'
        bne     sim_openat_2
        add     x9, x9, #1 // x9 now pointing (in theory) to basename
        adr     x10, FAKE_LIB
    sim_openat_3:
        ldrb    w12, [x10], #1
        ldrb    w11, [ x9], #1
        cmp     x11, x12
        bne     legit_syscall
        cmp     x11, #0
        beq     sim_openat_4
        b       sim_openat_3
    sim_openat_4:
        mov     x21, #0
        str     x21, [x25, #-0x10]
        mov     x0, #0x1337
        str     x0, [sp, 0x138]
        ret

sim_fstat:
        mov     x2, x1
sim_newfstatat:
        cmp     x0, x11
        bne     legit_syscall
        // st_dev
        movz    x9, #0xdead, lsl #0x10
        movk    x9, #0xbeef
        str     x9, [x2, #0x00]
        // st_ino
        movz    x9, #0xcafe, lsl #0x10
        movk    x9, #0xbabe
        str     x9, [x2, #0x08]
        // st_nlink
        mov     x9, #1
        str     x9, [x2, #0x10]
        // st_mode
        mov     x9, #0x81ed
        str     w9, [x2, #0x18]
        // st_uid and st_gid
        str     xzr, [x2, #0x1c]
        // st_rdev
        str     xzr, [x2, #0x28]
        // st_size
        ldr     x19, [x19] // lib_fsize
        str     x19, [x2, #0x30]
        // st_blksize
        mov     x9, #0x1000
        str     x9, [x2, #0x38]
        // st_blocks
        mov     x10, #0x200
        udiv    x9, x19, x10
        msub    x10, x9, x10, x19
        cmp     x10, #0
        beq     sim_newfstat_1
        add     x9, x9, #1
    sim_newfstat_1:
        str     x9, [x2, #0x40]
        // st_atim, st_mtim and st_ctim
        stp     xzr, xzr, [x2, #0x48]
        stp     xzr, xzr, [x2, #0x58]
        stp     xzr, xzr, [x2, #0x68]
        str     xzr, [sp, 0x138]
        ret

sim_close:
        cmp     x0, x11
        bne     legit_syscall
        str     xzr, [sp, #0x138]
        ret

legit_syscall:
        svc     #0
        str     x0, [sp, #0x138]
        ret


FAKE_LIB: .asciz "asd"
.align
data    :
// lib_fsize     : .dword 0
// ld_end_addr   : .dword 0
// ld_start_addr : .dword 0
// libdl_addr    : .dword 0
// stack_top     : .dword 0
// original      : .zero 16