#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <link.h>

#include <elf.h>

#include <sys/stat.h>
#include <libgen.h>

#define FAKE_LIB "asd"
#define MAGIC_FD 0x1337
#if defined(__x86_64__)
    #define SYSCALL_INST 0x050f
    typedef uint16_t inst_t;
    #define ILL_INST 0x0b0f
#elif defined(__aarch64__)
    #define SYSCALL_INST 0xd4000001
    typedef uint32_t inst_t;
    #define ILL_INST 0x00000000
#endif

#define ISPIE 1
#define ISLIB 2

uint8_t* lib_addr;
size_t lib_fsize;
uint64_t lib_base;

void* search_syscall(void* start, void* stop)
{
    for(uint8_t* ptr = start; (void*) ptr < (stop - sizeof(inst_t) - 1); ++ptr)
        if(*(inst_t*) ptr == SYSCALL_INST)
            *(inst_t*) ptr = ILL_INST;
}

#if defined(__x86_64__)
struct sigcontext_t
{
    uint64_t _1[5];
    uint64_t arg5; // r8
    uint64_t arg6; // r9
    uint64_t arg4; // r10
    uint64_t _2[5];
    uint64_t arg1; // rdi
    uint64_t arg2; // rsi
    uint64_t _3[2];
    uint64_t arg3; // rdx
    uint64_t nr;   // rax
    uint64_t _4[2];
    uint64_t pc;   // rip
};
#elif defined(__aarch64__)
struct sigcontext_t
{
    uint64_t arg1; // x0
    uint64_t arg2; // x1
    uint64_t arg3; // x2
    uint64_t arg4; // x3
    uint64_t arg5; // x4
    uint64_t arg6; // x5
    uint64_t _1[2];
    uint64_t nr;   // x8
    uint64_t _2[23];
    uint64_t pc;
};
#endif

void sigill_handler(int s)
{
    struct sigcontext_t* sigctx;
    uint64_t  nr, arg1, arg2, arg3, arg4, arg5, arg6, * ret;
    char* fmt = NULL;
    static uint64_t fakefp = 0;

    #if defined(__x86_64__)
    asm volatile("lea 0x10(%%rbp), %0;"
                 : "=r" (sigctx));
    ret = &sigctx->nr;
    #elif defined(__aarch64__)
    asm("ldr x28, [sp];"
        "sub  %0, x28, #0x1000;"
        "sub  %0,  %0, #0x0118;"
        : "=r" (sigctx) : : "x28");
    ret = &sigctx->arg1;
    #endif
    nr  = sigctx->nr;
    arg1  = sigctx->arg1;
    arg2  = sigctx->arg2;
    arg3  = sigctx->arg3;
    arg4  = sigctx->arg4;
    arg5  = sigctx->arg5;
    arg6  = sigctx->arg6;
    sigctx->pc += sizeof(inst_t); // Can't leave the PC pointing to the ill instruction

    switch(nr)
    {
        case SYS_pread64:
            fmt = "pread(0x%lx, 0x%lx, 0x%lx, 0x%lx)";
            if(arg1 != MAGIC_FD)
                goto legit_syscall;
            (uint64_t) memcpy((void*) arg2, lib_addr + arg4, arg3);
            *ret = arg3;
            break;
        case SYS_read:
            fmt = "read(0x%lx, 0x%lx, 0x%lx)";
            if(arg1 != MAGIC_FD)
                goto legit_syscall;
            (uint64_t) memcpy((void*) arg2, lib_addr + fakefp, arg3);
            fakefp += arg3;
            *ret = arg3;
            break;
        case SYS_mmap:
            fmt = "mmap(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)";
            if(arg5 != MAGIC_FD)
                goto legit_syscall;
            uint64_t flags = MAP_PRIVATE | MAP_ANONYMOUS | (arg4 & MAP_FIXED);
            *ret =
                (uint64_t) mmap((void*) arg1, arg2,
                                PROT_READ | PROT_WRITE,
                                flags, -1, 0);
            memcpy((void*) *ret, lib_addr + arg6,
                   ((arg6 + arg2) > lib_fsize) ? lib_fsize - arg6 : arg2);
            mprotect((void*) *ret, arg2, arg3);
            if(arg6 == 0) lib_base = *ret;
            break;
        case SYS_openat:
            fmt = "openat(0x%lx, %s, 0x%lx)";
            if(strcmp(basename((char*) arg2), FAKE_LIB))
                goto legit_syscall;
            *ret = MAGIC_FD;
            break;
        case SYS_fstat:
            fmt = "fstat(0x%lx, 0x%lx)";
        case SYS_newfstatat:
            if(nr == SYS_newfstatat) fmt = "fstatat(0x%lx, %s, 0x%lx, 0x%lx)";
            if(arg1 != MAGIC_FD)
                goto legit_syscall;
            struct timespec ts = { 0 };
            struct stat* st = (struct stat*) ((nr == SYS_newfstatat) ? arg3 : arg2);
            st->st_dev = 0xdeadbeef;
            st->st_ino = 0xcafebabe;
            st->st_mode = S_IFREG | 0755;
            st->st_nlink = 1;
            st->st_uid = 0;
            st->st_gid = 0;
            st->st_rdev = 0;
            st->st_size = lib_fsize;
            st->st_blksize = 4096;
            st->st_blocks = lib_fsize / 512 + !!(lib_fsize % 512);
            st->st_atim = ts;
            st->st_mtim = ts;
            st->st_ctim = ts;
            *ret = 0;
            break;
        case SYS_close:
            fmt = "close(0x%lx)";
            if(arg1 != MAGIC_FD)
                goto legit_syscall;
            *ret = 0;
            break;
        case SYS_mprotect:
            fmt = "mprotect(0x%lx, 0x%lx, 0x%lx)";
        case SYS_munmap:
            fmt = "munmap(0x%lx, 0x%lx)";
        default:
            goto legit_syscall;
    }
    if(getenv("DEBUG"))
    {
        printf("Simulated : ");
        printf(fmt, arg1, arg2, arg3, arg4, arg5, arg6, nr);
        printf(" = 0x%lx\n", *ret);
    }
    return;

    legit_syscall:
    *ret = syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
    if(fmt == NULL)
        fmt = "syscall(0x%7$lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)";

    if(getenv("DEBUG"))
    {
        printf("Detected  : ");
        printf(fmt, arg1, arg2, arg3, arg4, arg5, arg6, nr);
        printf(" = 0x%lx\n", *ret);
    }
    return;
}

uint64_t search_section(void* elf, char* section)
{
    Elf64_Ehdr* ehdr = elf;
    Elf64_Shdr* shdr = elf + ehdr->e_shoff;
    uint16_t shnum = ehdr->e_shnum;
    uint16_t shstrndx = ehdr->e_shstrndx;
    char* shstrtab = elf + shdr[shstrndx].sh_offset;

    for(int i = 0; i < shnum; ++i)
        if(!strcmp(&shstrtab[shdr[i].sh_name], section))
            return shdr[i].sh_offset;
    return 0;
}

int patch_elf()
{
    int ret = ISPIE | ISLIB;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*) lib_addr;
    Elf64_Dyn* dyn = (void*) lib_addr + search_section(lib_addr, ".dynamic");
    uint16_t shnum = ehdr->e_shnum;

    if(ehdr->e_type == ET_EXEC)
    {
        ehdr->e_type = ET_DYN;
        return 0; // Not PIE and therefore not a library
    }

    for(int i = 0; i < shnum; ++i)
    {
        if(dyn[i].d_tag == DT_SONAME)
            break; // A library
        if((dyn[i].d_tag == DT_FLAGS_1) && (dyn[i].d_tag & DF_1_PIE))
        {
            dyn[i].d_tag &= ~DF_1_PIE;
            return ISPIE; // PIE but not a library
        }
    }
    return ISPIE | ISLIB; // A library
}

#define READ_SIZE 0x10000
void read_elf()
{
    size_t r = 0;

    lib_addr = malloc(READ_SIZE);
    while((r = read(0, &lib_addr[lib_fsize], READ_SIZE)) == READ_SIZE)
    {
        lib_fsize += r;
        lib_addr = realloc(lib_addr, lib_fsize + READ_SIZE);
    }
    lib_fsize += r;
}

void* ld_addr(size_t* len)
{
    FILE* f = fopen("/proc/self/maps", "rb");
    char buf[1024];
    void* p1, * p2;
    while(fgets(buf, sizeof buf, f))
    {
        if(strncmp(basename(strchr(buf, '/')), "ld", 2)) continue;
        if(strncmp(strchr(buf, ' ') + 1, "r-x", 3)) continue;
        sscanf(buf, "%lx-%lx", &p1, &p2);
        *len = p2 - p1;
        fclose(f);
        return p1;
    }
    fclose(f);
    return NULL;
}

void fini()
{
    _exit(0);
}

int main(int argc, char** argv)
{
    void** sp;
    char* stack;
    struct link_map* map;
    uint64_t entry;
    int type;

    size_t len;
    void* ld, *h;
    read_elf();
    type = patch_elf();

    signal(SIGILL, sigill_handler);
    ld = ld_addr(&len);
    mprotect(ld, len, PROT_READ | PROT_WRITE);
    search_syscall(ld, ld + len);
    mprotect(ld, len, PROT_READ | PROT_EXEC);

    h = dlopen(FAKE_LIB, RTLD_NOW | RTLD_GLOBAL);
    if(h == NULL)
    {
        printf("Error in dlopen(): %s.\n", dlerror());
        return 1;
    }
    free(lib_addr);

    if(type & ISLIB)
    {
        ((void (*)(char*))dlsym(h, argv[1]))(argv[2]);
        return 0;
    }

    if(type & ISPIE)
        entry = ((Elf64_Ehdr*) lib_base)->e_entry + lib_base;
    else
        entry = ((Elf64_Ehdr*) lib_base)->e_entry;

    stack = mmap(NULL, 0x21000, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK, -1, 0);
    sp = (void**) &stack[0x21000];
    *--sp = NULL; // End of stack
    argc--; argv++;

    if(argc % 2)
        *--sp = NULL; // Keep stack aligned
    *--sp = NULL;     // End of envp
    *--sp = NULL;     // End of argv
    sp -= argc; memcpy(sp, argv, argc * 8);
    *(size_t*) --sp = argc;

    #if defined(__x86_64__)
    asm volatile("mov %0, %%rsp;"
                 "jmp *%1;"
                 : : "r"(sp), "r"(entry), "d"(fini));
    #elif defined(__aarch64__)
    asm volatile("mov x1, sp;"
                 "sub sp, sp, x1;"
                 "add sp, sp, %0;"
                 "mov x0, %2;"
                 "br  %1;"
                 : : "r"(sp), "r"(entry), "r"(fini) : "x0", "x1");
    #endif

    __builtin_unreachable();
    return 0;
}
