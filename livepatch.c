/**
 * Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>
 * All rights reserved.
 * This is free software with ABSOLUTELY NO WARRANTY.
 *
 * You can redistribute it and/or modify it under the terms of
 * the GNU General Public License version 2.
 */
static char rcsid[] = "$Id: livepatch.c 351 2004-11-08 16:05:26Z ukai $";
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <stdint.h>
#include <bfd.h>
#include <elf.h>
#include <link.h>
#define _GNU_SOURCE
#include <getopt.h>

/*****************/

int opt_debug;
int opt_verbose;
int opt_quiet;

#define DEBUG(fmt,...)    do {if (opt_debug) printf(fmt, __VA_ARGS__);} while (0)
#define INFO(fmt,...) do {if (opt_verbose) printf(fmt, __VA_ARGS__);} while (0)
#define NOTICE(fmt,...) do {if (!opt_quiet) printf(fmt, __VA_ARGS__);} while (0)
#define ERROR(fmt,...) do { fprintf(stderr, "%s (%d): "fmt, __func__, __LINE__, __VA_ARGS__);} while (0)


/*****************/
#if defined(linux)
/* sysdeps/i386/dl-machine.h */
/* The i386 never uses Elf32_Rela relocations for the dynamic linker.
 *    Prelinked libraries may use Elf32_Rela though.  */
#   define ELF_MACHINE_PLT_REL 1
#else
#   error Unsupported platform
#endif

/* glibc/elf/dl-runtime.c */
#if (!defined ELF_MACHINE_NO_RELA && !defined ELF_MACHINE_PLT_REL) \
    || ELF_MACHINE_NO_REL
# define PLTREL  ElfW(Rela)
#else
# define PLTREL  ElfW(Rel)
#endif

/* glibc/sysdeps/generic/ldsodefs.h */
#define ELFW(type)      _ElfW (ELF, __ELF_NATIVE_CLASS, type)

/* FIXME: too slow lookup, use hashtable or so */
struct symaddr {
    struct symaddr *next;
    char *name;
    long addr;
} *symaddrs;

long
lookup_symaddr(char *name, struct symaddr *symaddr0)
{
    struct symaddr *sa;
    for (sa = symaddr0; sa != NULL && sa->name != NULL; sa = sa->next) {
        if (strcmp(name, sa->name) == 0) {
            return sa->addr;
        }
    }
    DEBUG("[symaddr %s not found]\n", name);
    return 0;
}

void
add_symaddr(const char *name, long addr, struct symaddr **symaddrp)
{
    struct symaddr *sa;

    if (*name == '\0')
    return;

    sa = (struct symaddr *)malloc(sizeof(struct symaddr));
    memset(sa, 0, sizeof(struct symaddr));
    sa->name = strdup(name);
    sa->addr = addr;
    sa->next = *symaddrp;
    *symaddrp = sa;
    return;
}

int
bfd_read_symbols(bfd *abfd, long offset, struct symaddr **symaddrp)
{
    long storage_needed;
    asymbol **symbol_table = NULL;
    long number_of_symbols;
    long i;
    int ret = 0;

    /* symbol table */
    DEBUG("%s(%d): %s offset = %lx\n", __func__, __LINE__, "SYMBOL TABLE:", offset);
    storage_needed = bfd_get_symtab_upper_bound (abfd);
    if (storage_needed < 0) {
        bfd_perror("bfd_get_symtab_upper_bound");
        ret = -1;
        goto dynsym;
    }
    if (storage_needed == 0) {
        DEBUG("%s\n", "no symbols");
        goto dynsym;
    }
    symbol_table = (asymbol **)malloc (storage_needed);
    number_of_symbols = bfd_canonicalize_symtab (abfd, symbol_table);
    if (number_of_symbols < 0) {
        bfd_perror("bfd_canonicalize_symtab");
        ret = -1;
        goto dynsym;
    }
    for (i = 0; i < number_of_symbols; i++) {
        asymbol *asym = symbol_table[i];
        const char *sym_name = bfd_asymbol_name(asym);
        int symclass = bfd_decode_symclass(asym);
        long sym_value = bfd_asymbol_value(asym) + offset;
        if (*sym_name == '\0')
            continue;
        if (bfd_is_undefined_symclass(symclass))
            continue;
        DEBUG("%s(%d): %s=%p\n", __func__, __LINE__, sym_name, (void *)sym_value);
        add_symaddr(sym_name, sym_value, symaddrp);
    }
dynsym:
    if (symbol_table)
        free(symbol_table);
    symbol_table = NULL;

    DEBUG("%s\n", "DYNAMIC SYMBOL TABLE:");
    storage_needed = bfd_get_dynamic_symtab_upper_bound (abfd);
    if (storage_needed < 0) {
        bfd_perror("bfd_get_dynamic_symtab_upper_bound");
        ret = -1;
        goto out;
    }
    if (storage_needed == 0) {
        DEBUG("%s\n", "no symbols");
        goto out;
    }
    symbol_table = (asymbol **)malloc (storage_needed);
    number_of_symbols = bfd_canonicalize_dynamic_symtab (abfd, symbol_table);
    if (number_of_symbols < 0) {
        bfd_perror("bfd_canonicalize_symtab");
        ret = -1;
        goto out;
    }
    for (i = 0; i < number_of_symbols; i++) {
        asymbol *asym = symbol_table[i];
        const char *sym_name = bfd_asymbol_name(asym);
        int symclass = bfd_decode_symclass(asym);
        long sym_value = bfd_asymbol_value(asym) + offset;
        if (*sym_name == '\0')
            continue;
        if (bfd_is_undefined_symclass(symclass))
            continue;
        DEBUG(" %s=%p\n", sym_name, (void *)sym_value);
        add_symaddr(sym_name, sym_value, symaddrp);
    }
out:
    if (symbol_table)
        free(symbol_table);
    return ret;
}

void *
bfd_load_section(bfd *abfd, char *sect_name, int *sz)
{
    asection *sect;
    int size;
    char *buf;
    sect = bfd_get_section_by_name(abfd, sect_name);
    if (sect == NULL) {
        return NULL;
    }
    // size = bfd_section_size_before_reloc(sect);
    size = bfd_section_size(sect);
    buf = (char *)malloc(size);
    bfd_get_section_contents(abfd, sect, buf, 0, size);
    if (sz)
    *sz = size;
    return buf;
}

void
fixup(bfd *abfd, ElfW(Sym) *symtab, char *strtab, PLTREL *reloc,
      struct symaddr *symaddr0, char *outbuf, int outsize)
{
    ElfW(Sym) *sym;
    long rel_addr;
    long addr;
    char *sym_name;

    sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
    rel_addr = reloc->r_offset;
    sym_name = &strtab[sym->st_name];
    INFO("%s @ %ld 0x%lx ", sym_name, rel_addr, rel_addr);
    addr = lookup_symaddr(sym_name, symaddr0);
    if (addr) {
        *(int *)(outbuf + rel_addr) = addr;
        INFO("= %p\n", (void *)addr);
    } else {
        INFO("= %s\n", "*UND*");
    }
    return;
}

int
fixups(bfd *abfd, struct symaddr *symaddr0, char *outbuf, int outsize)
{
    ElfW(Sym) *symtab;
    char *strtab;
    PLTREL *reloc, *reloc_end;
    int reloc_size;


    DEBUG("%s...\n", "fixups");
    symtab = (ElfW(Sym)*)bfd_load_section(abfd, ".dynsym", NULL);
    if (symtab == NULL) {
        ERROR("load error %s\n", ".dynsym");
        return -1;
    }
    strtab = (char *)bfd_load_section(abfd, ".dynstr", NULL);
    if (strtab == NULL) {
        ERROR("load error %s\n", ".dynstr");
        return -1;
    }
    reloc = (PLTREL *)bfd_load_section(abfd, ".rela.dyn", &reloc_size);
    if (reloc == NULL) {
        ERROR("load error? %s\n", ".rela.dyn");
        goto rel_plt;
    }
    reloc_end = (PLTREL *)((char *)reloc + reloc_size);
    DEBUG(".rela.dyn reloc_size = %d\n", reloc_size);
    for (; reloc < reloc_end; reloc++) {
        fixup(abfd, symtab, strtab, reloc, symaddr0, outbuf, outsize);
    }

rel_plt:
    reloc = (PLTREL *)bfd_load_section(abfd, ".rela.plt", &reloc_size);
    if (reloc == NULL) {
        ERROR("load error %s\n", ".rela.plt");
        return -1;
    }
    reloc_end = (PLTREL *)((char *)reloc + reloc_size);
    DEBUG(".rela.plt reloc_size = %d\n", reloc_size);
    for (; reloc < reloc_end; reloc++) {
        fixup(abfd, symtab, strtab, reloc, symaddr0, outbuf, outsize);
    }
    return 0;
}

void
bfd_map_section_alloc_size(bfd *abfd, asection *sect, void *obj)
{
    int *outsizep = (int *)obj;
    int vma = bfd_section_vma(sect);
    int size = bfd_section_size(sect);
    // bfd_section_size_before_reloc
    int flags = bfd_section_flags(sect);
    if ((flags & (SEC_ALLOC|SEC_LOAD)) != 0) {
    if ((vma + size) > *outsizep)
        *outsizep = align_power(vma + size,
                    bfd_section_alignment(sect));
    }
}

void
bfd_map_section_buf(bfd *abfd, asection *sect, void *obj)
{
    char *outbuf = (char *)obj;
    long vma = bfd_section_vma(sect);
    int size = bfd_section_size(sect);
    int flags = bfd_section_flags(sect);
    if ((flags & (SEC_ALLOC|SEC_LOAD)) != 0) {
    DEBUG("section %s @ %p size %d flags 0x%0x\n",
          bfd_section_name(sect), (void *)vma, size, flags);
    bfd_get_section_contents(abfd, sect, outbuf + vma, 0, size);
    }
}

int
target_symbol_initialize(pid_t pid, char *filename)
{
    bfd *abfd;
    char buf[4096];
    FILE *fp;

    DEBUG("%s(%d): target symbol initialize: pid %d filename %s\n",
            __func__, __LINE__, pid, filename);
    snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
    DEBUG("proc map %s\n", buf);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        perror("open /proc/$$/maps");
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        /* linux/fs/proc/task_mmu.c */
        long vm_start, vm_end;
        int pgoff, major, minor, ino;
        char flags[5], mfilename[4096];
        if (sscanf(buf, "%lx-%lx %4s %x %d:%x %d %s",
            &vm_start, &vm_end, flags, &pgoff, &major, &minor, &ino,
            mfilename) < 7) {
            ERROR("E: invalid format in /proc/$$/maps? %s\n", buf);
            ERROR("E: invalid format in /proc/$$/maps? %d\n", ino);
            continue;
        }

        if (flags[0] == 'r' && flags[2] == 'x' && flags[3] == 'p'
            && pgoff != 0  && ino != 0 && *mfilename != '\0') {
            // printf("%s(%d)- 0x%lx-0x%lx %s 0x%x %s\n",
            //     __func__, __LINE__,
            //     vm_start, vm_end, flags, pgoff, mfilename);
            // printf("%s(%d): file %s @ %p\n", __func__, __LINE__,
            //     mfilename, (void *)vm_start);
            abfd = bfd_openr(mfilename, NULL);
            if (abfd == NULL) {
                bfd_perror("bfd_openr");
                continue;
            }
            bfd_check_format(abfd, bfd_object);
            bfd_read_symbols(abfd, vm_start-pgoff, &symaddrs);
            bfd_close(abfd);
        }
    }

    return 0;
}

/*****************/
int
push_stack(pid_t pid, struct user_regs_struct *regs, long v)
{
    regs->rsp -= 4;
    if (ptrace(PTRACE_POKEDATA, pid, regs->rsp, v) < 0) {
        perror("ptrace poke stack");
        return -1;
    }
    return 0;
}

long
target_alloc(pid_t pid, size_t siz)
{
    struct user_regs_struct regs, oregs;
    long lv;
    size_t bk_code;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &oregs) < 0) {
        perror("ptrace getregs");
        return 0;
    }

    regs = oregs;
    DEBUG("%s(%d): %%rsp = %p\n", __func__, __LINE__, (void* )regs.rsp);
    if ( (bk_code = ptrace(PTRACE_PEEKDATA, pid, (regs.rip), NULL)) < 0) {
        perror("ptrace get rip fail");
        return 0;
    }
#if SYSTEM32
    regs.rsp -= sizeof(int);
    memcpy(&lv, code, 4);
    if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, lv) < 0) {
        perror("ptrace poke code");
        return 0;
    }
    regs.rip = regs.rsp;  /* int $0x80 */
    raddr = regs.rsp + 2; /* int3 */
    /*
     * mmap(NULL, siz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
     */

    push_stack(pid, &regs, 0); /* arg 6 (offset) */
    push_stack(pid, &regs, -1);
    push_stack(pid, &regs, MAP_PRIVATE|MAP_ANONYMOUS);
    push_stack(pid, &regs, PROT_READ|PROT_WRITE);
    push_stack(pid, &regs, siz);
    push_stack(pid, &regs, 0);
    push_stack(pid, &regs, raddr);
    regs.rbx = regs.rsp + 4; /* arg 1 (ptr to args) */
    regs.rax = SYS_mmap; /* system call number */
    /**
     * stack will be:
     *     %rsp: return address
     *  4(%rsp): arg 1 <- %rbx : pointer to args  value  = 0
     *  8(%rsp): arg 2                            value  = -1
     * 12(%rsp): arg 3                            value  = MAP_PRIVATE|MAP_ANONYMOUS
     * 16(%rsp): arg 4
     * 20(%rsp): arg 5
     * 24(%rsp): arg 6
     * 28(%rsp): int $0x80    <- %rip jump address
     * 30(%rsp): int3        <- return address
     * 31(%rsp): --
     * 32(%rsp): original rsp
     *
     * glibc/sysdeps/unix/sysv/linux/i386/mmap.S
     */
#else

    regs.rax = SYS_mmap;                        /* system call number (mmap) */
    regs.rdi = 0;                               /* addr (arg 1) */
    regs.rsi = siz;                             /* length (arg 2) */
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;          /* prot (arg 3) */
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;     /* flags (arg 4) */
    regs.r8  = 0;                              /* fd (arg 5) */
    regs.r9  = 0;                               /* offset (arg 6) */
#endif

    DEBUG("%s(%d): target_alloc %s\n", __func__, __LINE__, "set regs");
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace set regs");
        return 0;
    }

    DEBUG("%s(%d): target_alloc %s\n", __func__, __LINE__, "PTRACE_POKEDATA");
    if (ptrace(PTRACE_POKEDATA, pid, regs.rip, 0x050f) < 0) { // syscall = 0f05
        perror("ptrace PTRACE_POKEDATA");
        return 0;
    }

    DEBUG("%s(%d): target_alloc %s\n", __func__, __LINE__, "PTRACE_SINGLESTEP");
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
        perror("PTRACE_SINGLESTEP");
        return 0;
    }

    wait(NULL);

    DEBUG("%s(%d): target_alloc %s\n", __func__, __LINE__, "mmap done");
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace get regs of mmap");
        return 0;
    }
    lv = regs.rax; /* return value */
    DEBUG("%s(%d): %%rax = %p\n", __func__, __LINE__, (void* )regs.rax);
    if (lv == (long) MAP_FAILED) {
        DEBUG("target_alloc failed %p\n", (void *)0);
        return 0;
    }
    INFO("allocated = %p %ld bytes\n", (void*)lv, siz);

    /* restore old regs */
    if (ptrace(PTRACE_POKEDATA, pid, oregs.rip, bk_code) < 0) {
        perror("ptrace restore rip");
        return 0;
    }
    if (ptrace(PTRACE_SETREGS, pid, NULL, &oregs) < 0) {
        perror("ptrace restore regs");
        return 0;
    }

    return lv;
}

#if SYSTEM32
#   define SYSTEM_ALIGN_TYPE int
#else
#   define SYSTEM_ALIGN_TYPE long
#endif
int
set_data(pid_t pid, long addr, void *val, int vlen)
{
    int i;

    // int addr0 = addr & ~3;
    // int len = (((addr + vlen) - addr0) + 3)/4;
    int len;
    long addr0;
    addr0 = addr & ~(sizeof(SYSTEM_ALIGN_TYPE) - 1);
    len = (((addr + vlen) - addr0) + (sizeof(SYSTEM_ALIGN_TYPE) - 1))/sizeof(SYSTEM_ALIGN_TYPE);

    long *lv = malloc(len * sizeof(SYSTEM_ALIGN_TYPE));

    DEBUG("peek: %d", len);
    for (i = 0; i < len; i++) {
        if (i % 4 == 0) {
            DEBUG("\n %p  ", (void *)(addr0 + i * sizeof(SYSTEM_ALIGN_TYPE)));
        }
        errno = 0;
        DEBUG("%s(%d): pid == %d(%lu)\n", __func__, __LINE__,
                pid, addr0 + i * sizeof(SYSTEM_ALIGN_TYPE));

        lv[i] = ptrace(PTRACE_PEEKDATA, pid,
                addr0 + i * sizeof(SYSTEM_ALIGN_TYPE), NULL);
        if (lv[i] == -1 && errno != 0) {
            ERROR("ptrace peek(%d) (%d)\n",i, errno);
            return -1;
        }
        DEBUG("%08lx ", lv[i]);
    }
    memcpy((char *)lv + (addr - addr0), val, vlen);
    DEBUG("\npoke: %d", len);
    for (i = 0; i < len; i++) {
        if (i % 4 == 0) {
            DEBUG("\n %p  ", (void *)(addr0 + i * sizeof(SYSTEM_ALIGN_TYPE)));
        }
        if (ptrace(PTRACE_POKEDATA, pid,
            addr0 + i * sizeof(SYSTEM_ALIGN_TYPE), lv[i]) < 0) {
            perror("ptrace poke");
            return -1;
        }
        DEBUG("%08lx ", lv[i]);
    }
    DEBUG("%s", "\n"); /* XXX */

    // for debug using...
    // long written_data1 = ptrace(PTRACE_PEEKTEXT, pid, addr + 0x1139, NULL);
    // long written_data2 = ptrace(PTRACE_PEEKTEXT, pid, addr + 0x1141, NULL);

    // printf("addr data check: 0x%lx 0x%lx\n", written_data1, written_data2);
    return 0;
}

struct memvar {
    struct memvar *next;
    char *name;
    long addr;
    struct symaddr *syms;
} *memvartab;

long
lookup_memvar(char *name)
{
    struct memvar *mv;
    int namelen = strlen(name);
    char *sym = strchr(name, ':');
    if (sym) {
        namelen = sym - name;
        sym += 1;
    }
    DEBUG("%s(%d): lookup_memvar %s sym %s\n", __func__, __LINE__, name, sym);
    for (mv = memvartab; mv != NULL && mv->name != NULL; mv = mv->next) {
        if (strncmp(name, mv->name, namelen) == 0) {
            if (sym != NULL) {
                if (isdigit(*sym)) {
                    int offset = strtol(sym, NULL, 0);
                    return mv->addr + offset;
                } else if (mv->syms != NULL) {
                    return lookup_symaddr(sym, mv->syms);
                }
            } else {
                return mv->addr;
            }
        }
    }
    ERROR("memvar %s not found\n", name);
    return 0;
}

void
set_memvar(char *name, long addr, struct symaddr *syms)
{
    struct memvar *mv = (struct memvar *)malloc(sizeof(struct memvar));
    memset(mv, 0, sizeof(struct memvar));
    mv->name = strdup(name);
    mv->addr = addr;
    mv->syms = syms;
    mv->next = memvartab;
    memvartab = mv;
    DEBUG("%s(%d): memvar %s set to %p syms:%p\n",
                __func__, __LINE__, name, (void *)addr, syms);
    return;
}

long
lookup_addr(char *addrinfo) {
    long addr = 0;
    DEBUG("lookup_addr %s => ", addrinfo);
    if (*addrinfo == '$') {
        addr = lookup_memvar(addrinfo+1);
    } else if (isdigit(*addrinfo)) {
        addr = strtol(addrinfo, NULL, 0);
    } else {
        addr = lookup_symaddr(addrinfo, symaddrs);
    }
    DEBUG("%p\n", (void *)addr);
    return addr;
}

void
parse_data(char *type, char *p, void **vptr, int *vlenp)
{
    DEBUG("data type=%s\n", type);
    if (strcmp(type, "int") == 0) {
        *vptr = (int*)malloc(sizeof(int));
        *vlenp = sizeof(int);
        *(int *)*vptr = strtol(p, NULL, 0);
    } else if (strcmp(type, "str") == 0) {
        *vlenp = strlen(p);
        *vptr = malloc(*vlenp);
        memcpy(*vptr, p, *vlenp);
    } else if (strcmp(type, "addr") == 0) {
        *vptr = (int*)malloc(sizeof(int));
        *vlenp = sizeof(int);
        *(long *)*vptr = lookup_addr(p);
    } else if (strcmp(type, "hex") == 0) {
        int i;
        int v;
        *vlenp = (strlen(p) + 1)/2;
        *vptr = malloc(*vlenp);
        for (i = 0; i < *vlenp; i++) {
            sscanf(p+i*2, "%02x", &v);
            ((char *)*vptr)[i] = v;
        }
    }
    return;
}

char *
format_data(char *type, char *p, void *vptr, int vlen)
{
    static char databuf[4096]; /* XXX */

    if (strcmp(type, "int") == 0) {
        snprintf(databuf, sizeof(databuf)-1, "%d (%s)", *(int*)vptr, p);
    } else if (strcmp(type, "str") == 0) {
        snprintf(databuf, sizeof(databuf)-1, "\"%s\" [%d]",
            (char *)vptr, vlen);
    } else if (strcmp(type, "addr") == 0) {
        snprintf(databuf, sizeof(databuf)-1, "@%p (%s)",
            (void *)((int *)vptr), p);
    } else if (strcmp(type, "hex") == 0) {
        snprintf(databuf, sizeof(databuf)-1, "hex [%d]", vlen);
    }
    return databuf;
}

void
usage(char *prog)
{
    printf("Usage: %s [option] <pid> <target-binary>\n"
       "  apply binary patches to running process.\n"
       "  read stdin for patch instructions.\n"
       "  --help    help message.\n"
       "  --quiet    quiet mode.\n"
       "  --verbose    verbose mode.\n"
       "  --debug    turn on debug message.\n"
       "\n"
       "%s\n"
           "Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>\n"
       "All rights reserved.\n"
       "This is free software with ABSOLUTELY NO WARRANTY.\n",
       prog, rcsid);
    return;
}

void
help(char *prog)
{
    usage(prog);
    printf("\n");
    printf("patch instructions:\n"
       "[instruction line]\n"
       "set <addr> <type> <value>     # set value to address\n"
       "new <memname> <size>          # allocate new memory space\n"
       "load <memname> <filename>     # load file in memory space\n"
       "dl <memname> <filename>       # load & symbol fixups.\n"
       "jmp <addr1> <addr2>           # set jmp to addr2 at addr1.\n"
       "\n"
       "[parameter]\n"
       "addr := <integer> | $<memname> | $<memname>:<symbol> | <symbol>\n"
       "type := int | str | hex | addr\n"
       "  int - integer parsed by strtol(i,NULL,0); size = 4\n"
       "  str - string until '\\n'\n"
       "  hex - ([0-9A-Fa-f]{2})*\n"
       "  addr - addr above\n"
       "\n");
    return;
}

void print_mem(pid_t pid, long addr) {
    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (errno != 0) {
        perror("ptrace peektext");
    } else {
        printf("Memory at %p: 0x%lx\n",(void *) addr, data);
    }
}


void print_regs(struct user_regs_struct regs) {

    printf("RIP: 0x%llx\n", regs.rip);
    printf("RAX: 0x%llx\n", regs.rax);
    printf("RBX: 0x%llx\n", regs.rbx);
    printf("RCX: 0x%llx\n", regs.rcx);
    printf("RDX: 0x%llx\n", regs.rdx);
    printf("RSI: 0x%llx\n", regs.rsi);
    printf("RDI: 0x%llx\n", regs.rdi);
    printf("RSP: 0x%llx\n", regs.rsp);
    printf("RBP: 0x%llx\n", regs.rbp);
}

void set_jmp_cmd(pid_t pid, long ofunc_addr, long nfunc_addr)
{
    unsigned char endbr64[] = {0xf3, 0x0f, 0x1e, 0xfa};
    /* set "mov rax, addr2" cmd*/
    unsigned char mov_rax[10] = {0x48, 0xB8};
    *(unsigned long *)&mov_rax[2] = (unsigned long)nfunc_addr;
    /* set "jmp rax" cmd*/
    unsigned char jmp_rax[2] = {0xFF, 0xE0};

    unsigned char code[16];
    memcpy(code, endbr64, sizeof(endbr64));
    memcpy(code + sizeof(endbr64), mov_rax, sizeof(mov_rax));
    memcpy(code + sizeof(endbr64) + sizeof(mov_rax), jmp_rax, sizeof(jmp_rax));

#if DEBUGMODE
    struct user_regs_struct regs;
    int status;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
        printf("before status\n");
        print_regs(regs);
    } else {
        perror("ptrace getregs");
    }
#endif

    ptrace(PTRACE_POKETEXT, pid, ofunc_addr, *(long *)&code[0]);
    ptrace(PTRACE_POKETEXT, pid, ofunc_addr + 8, *(long *)&code[8]);

#if DEBUGMODE
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
        printf("after set jump status\n");
        print_regs(regs);
    } else {
        perror("ptrace getregs");
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("ptrace singlestep");
        exit(EXIT_FAILURE);
    }

    waitpid(pid, &status, 0);
    long oldrip = regs.rip;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
        printf("start run set jump status\n");
        print_regs(regs);
    } else {
        perror("ptrace getregs");
    }

    while (WIFSTOPPED(status)) {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
            perror("ptrace singlestep");
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);

        long ofunc_offset = 0x1189;
        long main_offset = 0x11e3;
        long nfunc_offset = 0x1139;
        long mmap_addr = 0x7f0000000000;
        char key;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
            if (oldrip != regs.rip && regs.rip < mmap_addr) {
                printf("\nAfter single step: func_J(%p), main(%p), func1(%p)\n",
                                (void *)ofunc_addr,
                                (void *)(ofunc_addr - ofunc_offset + main_offset),
                                (void *)nfunc_addr);

                if (regs.rip >= (ofunc_addr) &&
                        regs.rip < (ofunc_addr - ofunc_offset + main_offset) ) {
                    printf("in the func_J call\n");
                } else if (regs.rip >= (ofunc_addr - ofunc_offset + main_offset) ){
                    printf("in the main call\n");
                } else {
                    printf("in the system call\n");
                }
                print_regs(regs);
                key = getchar();
            } else if (oldrip != regs.rip && regs.rip >= (nfunc_addr - nfunc_offset) ) {
                printf("\nAfter single step: func_J(%p), main(%p), func1(%p)\n",
                                (void *)ofunc_addr,
                                (void *)(ofunc_addr - ofunc_offset + main_offset),
                                (void *)nfunc_addr);
                printf("in the new function call\n");
                print_regs(regs);

                print_mem(pid, regs.rdi);
                print_mem(pid, regs.rdi+8);
                key=getchar();
            }
            oldrip = regs.rip;;
            if(key == 'q')
                break;
        } else {
            perror("ptrace(PTRACE_GETREGS)");
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("Process exited or was killed\n");
            break;
        }
    }

#endif

}

int
main(int argc, char *argv[])
{
    pid_t target_pid;
    char *target_filename;
    char buf[4096];
    static struct option long_opts[] = {
        {"debug", no_argument, &opt_debug, 1},
        {"verbose", no_argument, &opt_verbose, 1},
        {"quiet", no_argument, &opt_quiet, 1},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int opt_index;

    while (1) {
        int c;
        c = getopt_long(argc, argv, "dvqh", long_opts, &opt_index);
        if (c == -1)
            break;
        switch (c) {
            case 0: /* long options */; break;
            case 'd': opt_debug = 1; break;
            case 'v': opt_verbose = 1; break;
            case 'q': opt_quiet = 1; break;
            case 'h': help(argv[0]); exit(0);
            case '?': /* FALLTHROUGH */
            default:
                usage(argv[0]); exit(1);
        }
    }
    if (opt_quiet) {
        opt_debug = opt_verbose = 0;
    }

    if (argc < optind + 2) {
        usage(argv[0]);
        exit(1);
    }
    bfd_init();
    target_pid = atoi(argv[optind]);
    target_filename = argv[optind+1];
    target_symbol_initialize(target_pid, target_filename);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        exit(1);
    }
    DEBUG("attached %d\n", target_pid);
    wait(NULL);

    /**
     * see help()
     */
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        DEBUG("I: %s", buf);
        if (strncmp(buf, "set ", 4) == 0) {
            char addrinfo[4096];
            char type[4096];
            char val[4096];
            long addr;
            void *v;
            int vlen;

            if (sscanf(buf, "set %s %s %s\n", addrinfo, type, val) != 3) {
                ERROR("E: invalid set line: %s", buf);
                continue;
            }
            printf("%s(%d): -------- call set %s %s %s-------\n",
                __func__, __LINE__, addrinfo, type, val);
            addr = lookup_addr(addrinfo);
            parse_data(type, val, &v, &vlen);

            INFO("set pid=%d addr=%p value=%s\n", target_pid,
                (void *)addr, format_data(type, val, v, vlen));
            if (set_data(target_pid, addr, v, vlen) < 0) {
                ERROR("E: set %p %s %s failed\n", (void *)addr, type, val);
                continue;
            }
            NOTICE("set %p %s %s\n", (void *)addr, type, val);

        } else if (strncmp(buf, "new ", 4) == 0) {
            char memname[4096];
            char sizeinfo[4096];
            int siz;
            long addr;

            if (sscanf(buf, "new %s %s\n", memname, sizeinfo) != 2) {
                ERROR("E: invalid new line: %s", buf);
                continue;
            }
            siz = strtol(sizeinfo, NULL, 0);
            INFO("new pid=%d memvar=%s size=%d\n", target_pid,
            memname, siz);
            addr = target_alloc(target_pid, siz);
            if (addr == 0) {
                ERROR("E: target_alloc failed. pid=%d size=%d\n",
                    target_pid, siz);
                continue;
            }
            set_memvar(memname, addr, NULL);
            NOTICE("new %s @ %p [%d]\n", memname, (void *)addr, siz);

        } else if (strncmp(buf, "load ", 5) == 0) {
            char memname[4096];
            char filename[4096];
            struct stat st;
            char *p;
            long addr;
            FILE *fp;

            if (sscanf(buf, "load %s %s\n", memname, filename) != 2) {
                ERROR("E: invalid load line: %s", buf);
                continue;
            }
            if (stat(filename, &st) < 0) {
                perror("stat");
                continue;
            }
            INFO("load pid=%d memvar=%s filename=%s size=%ld\n",
            target_pid, memname, filename, st.st_size);
            /*
            * TODO: mmap on file in target?
            */
            p = malloc(st.st_size);
            if (p == NULL) {
                ERROR("E: malloc failed. size=%ld\n", st.st_size);
                continue;
            }
            fp = fopen(filename, "r");
            if (fp == NULL) {
                ERROR("E: fopen %s error\n", filename);
                continue;
            }
            if (fread(p, st.st_size, 1, fp) == 0) {
                ERROR("E: fread error. %ld\n", st.st_size);
                continue;
            }
            fclose(fp);

            addr = target_alloc(target_pid, st.st_size);
            if (addr == 0) {
                ERROR("E: target_alloc failed. pid=%d size=%ld\n",
                    target_pid, st.st_size);
                continue;
            }
            if (set_data(target_pid, addr, p, st.st_size) < 0) {
                ERROR("E: load %s @ %p failed.\n", filename, (void *)addr);
                continue;
            }
            set_memvar(memname, addr, NULL);
            NOTICE("load %s @ %p [%ld] %s\n", memname, (void *)addr,
            st.st_size, filename);

        } else if (strncmp(buf, "dl ", 3) == 0) {
            char memname[4096];
            char filename[4096];
            bfd *abfd;
            char *outbuf;
            int outsize;
            long addr;
            struct symaddr *symaddr0 = NULL;

            if (sscanf(buf, "dl %s %s\n", memname, filename) != 2) {
                ERROR("E: invalid dl line: %s", buf);
                continue;
            }
            printf("%s(%d): -------- call dl %s %s -------\n",
                __func__, __LINE__, memname, filename);
            INFO("%s(%d): dl pid=%d memvar=%s filename=%s\n",
                        __func__, __LINE__, target_pid, memname, filename);

            abfd = bfd_openr(filename, NULL);
            if (abfd == NULL) {
                bfd_perror("bfd_openr");
                continue;
            }
            bfd_check_format(abfd, bfd_object);
            outsize = 0;
            bfd_map_over_sections(abfd, bfd_map_section_alloc_size, &outsize);
            outbuf = (char *)malloc(outsize);
            if (outbuf == NULL) {
                ERROR("E: malloc failed. size=%d\n", outsize);
                continue;
            }
            memset(outbuf, 0, outsize);
            /* XXX: size parameter */
            bfd_map_over_sections(abfd, bfd_map_section_buf, outbuf);

            /* global */
            INFO("global symbol fixups %s\n", filename);
            fixups(abfd, symaddrs, outbuf, outsize);

            addr = target_alloc(target_pid, outsize); //call mmap to create new section
            if (addr == 0) {
                ERROR("E: target_alloc failed. pid=%d size=%d\n",
                    target_pid, outsize);
                continue;
            }

            bfd_read_symbols(abfd, addr, &symaddr0);
            /* local */
            INFO("%s(%d): local symbol fixups %s offset %p\n", __func__, __LINE__,
                filename, (void *)addr);
            fixups(abfd, symaddr0, outbuf, outsize);
            bfd_close(abfd);


            if (set_data(target_pid, addr, outbuf, outsize) < 0) {
                ERROR("E: dl %s @ %p failed.\n", filename, (void *)addr);
                continue;
            }
            set_memvar(memname, addr, symaddr0);
            NOTICE("dl %s @ %p [%d] %s\n", memname, (void *)addr,
                        outsize, filename);

        } else if (strncmp(buf, "jmp ", 4) == 0) {
            char addrinfo[4096];
            char addr2info[4096];
            long base_addr;
            long addr;
            long addr2;

            if (sscanf(buf, "jmp %s %s\n", addrinfo, addr2info) != 2) {
                ERROR("E: invalid jmp line: %s", buf);
                continue;
            }
            printf("%s(%d): -------- call jmp %s %s -------\n",
                    __func__, __LINE__, addrinfo, addr2info);

            addr = lookup_addr(addrinfo);
            base_addr = lookup_addr("_init");
            addr2 = lookup_addr(addr2info);

            INFO("%s(%d):jmp pid=%d addr=%p(%p) addr2=%p\n",
                    __func__, __LINE__, target_pid,
                    (void *)addr, (void *)base_addr, (void *)addr2);

#if SYSTEM32
            long jmp_relative;
            char jmpbuf[5];

            if (sscanf(buf, "jmp %s %s\n", addrinfo, addr2info) != 2) {
                ERROR("E: invalid jmp line: %s", buf);
                continue;
            }
            addr = lookup_addr(addrinfo);
            addr2 = lookup_addr(addr2info);
            INFO("jmp pid=%d addr=%p addr2=%p\n",
                target_pid,
                (void *)addr, (void *)addr);
            jmp_relative = addr2 - (addr + 5);
            INFO("jmp relative %ld (0x%08lx)\n", jmp_relative, jmp_relative);
            jmpbuf[0] = 0xe9; /* jmp */
            memcpy(jmpbuf+1, &jmp_relative, sizeof(int));
            if (set_data(target_pid, addr, jmpbuf, sizeof(jmpbuf)) < 0) {
                ERROR("E: jmp %p %p failed.\n", (void *)addr, (void *)addr2);
                continue;
            }
            NOTICE("jmp %p %p\n", (void *)addr, (void *)addr2);
#else
            set_jmp_cmd(target_pid, addr, addr2);
#endif
        } else if (strncmp(buf, "q", 1) == 0) {
            break;
        } else {
            ERROR("E: unknown command %s\n", buf);
        }
    }
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    DEBUG("detached %d\n", target_pid);
    exit(0);
}