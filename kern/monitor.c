// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display stack backtrace", mon_backtrace },
	{ "time", "Test the running time of a command, Usage: time [command]" , mon_time },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

int
mon_time(int argc, char **argv, struct Trapframe *tf)
{
	uint64_t tsc_start, tsc_end;
	int i;

	// Lookup and invoke the command
	if (argc == 1) {
		cprintf("Usage: time [command]\n");
		return 0;
	}
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[1], commands[i].name) == 0) {
			tsc_start = read_tsc();
			commands[i].func(argc - 1, argv + 1, tf);
			tsc_end = read_tsc();
			cprintf("%s cycles: %llu\n", argv[1], tsc_end - tsc_start);
			return 0;
		}
	}
	cprintf("Unknown command '%s'\n", argv[1]);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

	char str[256] = {};
	int i;
	char *pret_addr;
	uint32_t overflow_addr = (uint32_t) do_overflow;

	pret_addr = (char *) read_pretaddr();
	for (i = 0; i < 4; i++) {
		memset(str, 0, 256);
		memset(str, 0xd, (unsigned char)(*(pret_addr + i)));
		cprintf("%s%n", str, pret_addr + 4 + i);
	}
	for (i = 0; i < 4; i++) {
		memset(str, 0, 256);
		memset(str, 0xd, (overflow_addr >> (8*i)) & 0xFF);
		cprintf("%s%n", str, pret_addr + i);
	}

}

void
overflow_me(void)
{
    start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    uint32_t *ebp;
    struct Eipdebuginfo info;

    overflow_me();
    cprintf("Stack backtrace:\n");
    ebp = (uint32_t *) read_ebp();
    while (ebp != NULL) {
        cprintf("  eip %08x  ebp %08x  args %08x %08x %08x %08x %08x\n",
                *(ebp+1), (uint32_t)ebp, *(ebp+2), *(ebp+3), *(ebp+4),
                *(ebp+5), *(ebp+6));
        debuginfo_eip((uintptr_t)(*(ebp+1)), &info);
        cprintf("        %s:%u %.*s+%u\n",info.eip_file, info.eip_line,
                info.eip_fn_namelen, info.eip_fn_name,
                (*(ebp+1)) - (uint32_t)info.eip_fn_addr);
        ebp = (uint32_t *) (*ebp);
    }
    cprintf("Backtrace success\n");
    return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
