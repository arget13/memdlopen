.arch armv8.2-a
.global _start

_start:
    // Restore original bytes in read() through mem file
        mov     x0, #3
        mov     x1, #-0x10
        mov     x2, #1             // SEEK_CUR
        mov     x8, #0x3e
        svc     #0                 // lseek
        mov     x0, #3
        adr     x19, data
        add     x1, x19, data.original
        mov     x2, #0x10
        mov     x8, #0x40
        svc     #0                 // write
        mov     x0, #3
        mov     x8, #0x39
        svc     #0                 // close

    // Read ELF in memory
        mov     x0, #0
        mov     x1, #0x1000
        mov     x2, #3             // RW
        mov     x3, #0x22          // MAP_ANON | MAP_PRIVATE
        mov     x4, #-1
        mov     x5, #0
        mov     x8, #0xde
        svc     #0                 // mmap

        mov     x27, x0
        mov     x20, #0
        b       read
    mremap:
        mov     x0, x27
        mov     x1, x20
        add     x2, x20, #0x1000
        mov     x3, #1             // MREMAP_MAYMOVE
        mov     x8, #0xd8
        svc     #0                 // mremap
        mov     x27, x0

    read:
        mov     x2, #0x1000
        add     x1, x0, x20
        mov     x0, #0
        mov     x8, #0x3f
        svc     #0                 // read
        tbnz    x0, #63, _exit     // Error while reading
        add     x20, x20, x0
        cmp     x0, #0x1000
        beq     mremap

        ldr     x25, [x19, data.stack_top]
        str     x27, [x25, -globals.elf_addr]
        str     x20, [x25, -globals.fsize]
        stp     xzr, xzr, [x25, -globals.base] // Zero out base & fakefp

    // Save program's entrypoint
        ldr     x9, [x27, #0x18]
        str     x9, [x25, -globals.entry]

    // Patch ELF (make it look like a library)
        // Elf64_Ehdr.e_type = ET_DYN
        mov     x9, #0x03
        strh    w9, [x1, #0x10]
        // In section .dynamic remove DF_1_PIE bit from DT_FLAGS_1 entry
        adr     x0, dynamic
        mov     x1, x27
        bl      search_section
        add     x0, x0, x27
    next_dyn_entry:
        ldp     x9, x10, [x0], #0x10    // x9 = d_tag; x10 = d_val
        movz    x11, #0xfffb
        movk    x11, #0x6fff, lsl #0x10 // DT_FLAGS_1
        cmp     x9, x11
        beq     dyn_entry_found
        subs    x1, x1, #0x10
        bne     next_dyn_entry
        b       dyn_entry_not_found
    dyn_entry_found:
        bfc     x10, #27, #1       // Clear DF_1_PIE bit
        str     x10, [x0, #-8]
    dyn_entry_not_found:


    // Install signal handler for SIGILL
        mov     x9, #0xa
    memset:
        stp     xzr, xzr, [sp, #-0x10]!
        subs    x9, x9, #1
        bne     memset
        adr     x9, sigill_handler
        str     x9, [sp]           // Now we have a sigaction structure in stack
        mov     x0, #4             // SIGILL
        mov     x1, sp
        mov     x2, #0
        mov     x3, #8
        mov     x8, #0x86
        svc     #0                 // sigaction

    // Change svc #0 instructions in loader with undefined ones
        ldr     x10, [x19, data.ld_end_addr]
        ldr     x9,  [x19, data.ld_start_addr]
        sub     x1, x10, x9
        mov     x2, #3             // RW
        mov     x0, x9
        mov     x8, #0xe2
        svc     #0                 // mprotect
        bl      search_syscall
        sub     x1, x10, x9
        mov     x2, #5             // RX
        mov     x0, x9
        svc     #0                 // mprotect

    // Obtain dlopen offset
        // Map libdl in memory first
        mov     x0, #-100          // AT_FDCWD
        adr     x1, libdlpath
        mov     x2, #0             // O_RDONLY
        mov     x8, #0x38
        svc     #0                 // openat
        mov     x4, x0

        mov     x1, #0
        mov     x2, #2             // SEEK_END
        mov     x8, #0x3e
        svc     #0                 // lseek

        mov     x5, #0
        mov     x3, #2             // MAP_PRIVATE
        mov     x2, #3             // RW
        mov     x1, x0
        mov     x0, #0
        mov     x8, #0xde
        svc     #0                 // mmap
        mov     x3, x0

        mov     x0, x4
        mov     x8, #0x39
        svc     #0                 // close

        // Now search the symbol
        mov     x1, x3
        adr     x0, dynsym
        bl      search_section
        add     x4, x0, x3         // x4 = &.dynsym

        mov     x1, x3
        adr     x0, dynstr
        bl      search_section
        add     x5, x0, x3         // x5 = &.dynstr

        adr     x10, dlopen
    next_symbol:
        ldr     w9, [x4], #0x18    // st_name
        add     x9, x9, x5
        bl      strcmp
        cmp     x11, #0
        beq     symbol_found
        subs    x1, x1, #0x18
        bne     next_symbol
        // Couldn't locate dlopen, just do the right thing and die
        b       _exit
    symbol_found:
        ldr     x9, [x4, #(-0x18 + 8)]
        ldr     x3, [x19, data.libdl_addr]
        add     x3, x3, x9

    // Call dlopen(FAKE_LIB, RTLD_NOW | RTLD_GLOBAL)
        adr     x0, FAKE_LIB
        mov     x1, #0x102         // RLTD_NOW | RTLD_GLOBAL
        blr     x3                 // dlopen(), finally!

        adr     x19, data
    // Unmap raw binary
        ldr     x25, [x19, data.stack_top]
        ldr     x0 , [x25, -globals.elf_addr]
        ldr     x1 , [x25, -globals.fsize]
        mov     x8 , #0xd7
        svc     #0                 // munmap


    // The binary has been loaded, only remains to lay arguments in stack
        mov     x5, #0
        mov     x4, #-1
        movz    x3, #0x2, lsl #0x10
        mov     x3, #0x22          // MAP_ANON | MAP_PRIVATE | MAP_STACK
        mov     x2, #3             // RW
        mov     x1, #0x21
        lsl     x1, x1, #0xc
        mov     x0, #0
        mov     x8, #0xde
        svc     #0                 // mmap
        add     x0, x0, x1

        ldr     x13, [x25, -globals.base]
        ldr     x17, [x19, data.argc]
        str     xzr, [x0, #-8]                // NULL at the end of stack
        sub     x0, x0, #0x18                 // Space for two NULLs and argc
        sub     x0, x0, x17, lsl #3           // x0 -= argc * 8
        and     x0, x0, #-0x10                // sp must not misalign!
        str     x17, [x0]                     // *x0 = argc
        mov     sp , x0

        cmp     x17, #0
        beq     run

        add     x19, x19, data.args
    nextarg:
        str     x19, [x0, #8]!     // *++sp = argv[n]
        subs    x17, x17, #1
        beq     run
    nextchar:
        ldrb    w1 , [x19], #1
        cmp     w1 , #0
        beq     nextarg
        b       nextchar


    run:
        stp     xzr, xzr, [x0, #8] // argv[argc] = NULL; *envp = NULL
        mov     x0, #2
        mov     x1, #0
        mov     x2, #0
        mov     x8, #0x18
        svc     #0                 // dup3

    // Jump to program's entry
        adr     x0 , _exit
        ldr     x13, [x25, -globals.entry]
        ldr     x12, [x25, -globals.base]
        add     x13, x13, x12
        br      x13
        .dword  0xfabada           // won't be hit

_exit:
        mov     x0, #0
        mov     x8, #0x5e
        svc     #0                 // exit_group

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
        ldr     x8,     [sp, #0x178]

        adr     x19, data
        ldr     x25, [x19, data.stack_top]
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
        ldr     x20, [x25, -globals.elf_addr]
        ldr     x21, [x25, -globals.fakefp]
        add     x12, x20, x21      // x12 = elf_addr + fakefp
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
        str     x21, [x25, -globals.fakefp]
        ret

sim_mmap:
        cmp     x4, x11
        bne     legit_syscall
        mov     x13, x2
        mov     x14, x5
        mov     x2, #3             // RW
        and     x3, x3, #0x10      // MAP_FIXED
        mov     x11, 0x22
        orr     x3, x3, x11        // MAP_ANON | MAP_PRIVATE
        movn    x4, #0             // -1
        mov     x5, #0
        svc     #0                 // mmap
        cmp     x14, #0
        bne     sim_mmap_1
        str     x0, [x25, -globals.base]
    sim_mmap_1:
        str     x0, [sp, #0x138]
        add     x11, x1, x14       // x11 = size + offset
        ldr     x19, [x25, -globals.fsize]
        cmp     x11, x19
        bls     sim_mmap_2
        sub     x19, x19, x14
    sim_mmap_2: // memcpy
        mov     x11, #0
        ldr     x20, [x25, -globals.elf_addr]
        add     x12, x20, x14
    sim_mmap_3:
        cmp     x11, x19
        beq     sim_mmap_4
        ldrb    w10, [x12, x11]
        strb    w10, [ x0, x11]
        add     x11, x11, #1
        b       sim_mmap_3
    sim_mmap_4:
        mov     x2, x13
        mov     x8, #0xe2
        svc     #0                 // mprotect
        ret

sim_openat:
        mov     x9, x1
    sim_openat_1:
        ldrb    w12, [x9], #1
        cmp     x12, #0
        bne     sim_openat_1
        sub     x9, x9, #1         // x9 pointing to null terminator
    sim_openat_2:
        ldrb    w12, [x9, #-1]!
        cmp     x12, #0x2f         // '/'
        bne     sim_openat_2
        add     x9, x9, #1         // x9 now pointing (in theory) to basename
        adr     x10, FAKE_LIB
        mov     x26, lr
        bl      strcmp
        mov     lr, x26
        cmp     x11, #0
        bne     legit_syscall
        mov     x21, #0
        str     x21, [x25, -globals.fakefp]
        mov     x0, #0x1337
        str     x0, [sp, #0x138]
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
        ldr     x19, [x25, -globals.fsize]
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
        str     xzr, [sp, #0x138]
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

// x9 = str2; x10 = str1 (not modified); x11 = ret value; x12, x15 clobbered
strcmp:
        mov     x15, x10
    next_byte:
        ldrb    w12, [x15], #1
        ldrb    w11, [ x9], #1
        subs    x11, x11, x12
        bne     strcmp_ret         // Found a non-matching pair of bytes
        cmp     x12, #0
        bne     next_byte          // Still didn't reach end of string
    strcmp_ret:
        ret

// x0 = section name; x1 = raw ELF base address; x0, x1 = ret values
search_section:
        ldr     x20, [x1, #0x28]   // e_shoff
        ldrh    w21, [x1, #0x3c]   // e_shnum
        ldrh    w22, [x1, #0x3e]   // e_shstrndx
        add     x20, x20, x1

        add     x23, x20, x22, lsl #0x6 // Reach shdr that describes .shstrtab
        ldr     x22, [x23, #0x18]  // x22 = &shstrtab
        add     x22, x22, x1

        mov     x8, lr
        mov     x10, x0
    next_section:
        ldr     w9 , [x20, #0]     // sh_name
        add     x9, x9, x22
        bl      strcmp
        cmp     x11, #0
        beq     section_found

        subs    x21, x21, #1
        add     x20, x20, #0x40    // sizeof(Elf64_Shdr) = 0x40
        bne     next_section
        mov     x0, #0
        br      x8

    section_found:
        // ldr     x2, [x20, #0x10]   // sh_addr
        ldr     x1, [x20, #0x20]   // sh_size
        ldr     x0, [x20, #0x18]   // sh_offset
        br      x8


FAKE_LIB  : .asciz "libasdf"
dynstr    : .asciz ".dynstr"
dynsym    : .asciz ".dynsym"
dynamic   : .asciz ".dynamic"
dlopen    : .asciz "dlopen"
libdlpath : .asciz "/lib/aarch64-linux-gnu/libdl.so.2"
.align
data               :

.struct 0
data.ld_end_addr   : .space 8
data.ld_start_addr : .space 8
data.libdl_addr    : .space 8
data.stack_top     : .space 8
data.original      : .space 16
data.argc          : .space 8
data.args          :

.struct 0
globals            : .space 8
globals.elf_addr   : .space 8
globals.fakefp     : .space 8
globals.base       : .space 8
globals.entry      : .space 8
globals.fsize      : .space 8
