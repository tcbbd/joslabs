#include <inc/lib.h>
#include <inc/elf.h>
#include <inc/x86.h>

#define UTEMP2USTACK(addr)	((void*) (addr) + (USTACKTOP - PGSIZE) - UTEMP)
#define UTEMP2			(UTEMP + PGSIZE)
#define UTEMP3			(UTEMP2 + PGSIZE)

// Maximum number of file descriptors a program may hold open concurrently
#define MAXFD		32
// Bottom of file descriptor area
#define FDTABLE		0xD0000000
// Bottom of file data area.  We reserve one data page for each FD,
// which devices can use if they choose.
#define FILEDATA	(FDTABLE + MAXFD*PGSIZE)

extern unsigned char libtext[], libend[];

// All the functions we use here should be placed in ".lib" section.

// Helper functions for exec.
static int init_stack(const char **argv, uintptr_t *init_esp, uint32_t entry) __attribute__((section(".lib")));
static int map_segment(uintptr_t va, size_t memsz, int fd,
	size_t filesz, off_t fileoffset, int perm) __attribute__((section(".lib")));
static void map_stack() __attribute__((section(".lib")));
static int start_program(uintptr_t init_esp) __attribute__((section(".lib")));

// Execute from a program image loaded from the file system.
// prog: the pathname of the program to run.
// argv: pointer to null-terminated array of pointers to strings,
// 	 which will be passed to the program as its command-line arguments.
// Doesn't return on success, return < 0 on recoverable failure and destroy the
// environment on severe failure.
// Note: Opened fds are not closed after calling this function.
int
execv(const char *prog, const char **argv)
{
	unsigned char elf_buf[512];
	uintptr_t addr;

	int fd, i, r;
	struct Elf *elf;
	struct Proghdr *ph;
	int perm;

	uintptr_t init_esp;

	// This code follows this procedure:
	//
	//   - Open the program file.
	//
	//   - Read the ELF header, as you have before, and sanity check its
	//     magic number.  (Check out your load_icode!)
	//
	//   - Call the init_stack() function above to set up
	//     the initial stack(in a temporary position) for the new program.
	//
	//   - Free all of the enviroment's pages in use.
	//
	//   - Map all of the program's segments that are of p_type
	//     ELF_PROG_LOAD into the environment's address space.
	//     Use the p_flags field in the Proghdr for each segment
	//     to determine how to map the segment.
	//
	//     Note: None of the segment addresses or lengths above
	//     are guaranteed to be page-aligned, so you must deal with
	//     these non-page-aligned values appropriately.
	//     The ELF linker does, however, guarantee that no two segments
	//     will overlap on the same page; and it guarantees that
	//     PGOFF(ph->p_offset) == PGOFF(ph->p_va).
	//
	//   - Call the init_stack() function above to set up
	//     the initial stack for the new program and then run it.

	if ((r = open(prog, O_RDONLY)) < 0)
		return r;
	fd = r;

	// Read elf header
	elf = (struct Elf*) elf_buf;
	if (readn(fd, elf_buf, sizeof(elf_buf)) != sizeof(elf_buf)
	    || elf->e_magic != ELF_MAGIC) {
		close(fd);
		cprintf("elf magic %08x want %08x\n", elf->e_magic, ELF_MAGIC);
		return -E_NOT_EXEC;
	}

	// Initlalize the stack
	if ((r = init_stack(argv, &init_esp, elf->e_entry)) < 0)
		goto error;

	// Free pages in use
	for (addr = 0; addr < USTACKTOP - PGSIZE; addr += PGSIZE) {
		if (!(vpd[PDX(addr)] & PTE_P)) {
			addr += PGSIZE * (NPTENTRIES - 1);
			continue;
		}
		if (!(vpt[PGNUM(addr)] & PTE_P))
			continue;
		if (addr == (uintptr_t) UTEMP)
			continue;
		if ((uintptr_t) libtext <= addr && addr <= ROUNDDOWN((uintptr_t) libend, PGSIZE))
			continue;
		if (FDTABLE <= addr && addr <= FILEDATA + MAXFD * PGSIZE)
			continue;
		sys_page_unmap(0, (char *)addr);
	}

	// Set up program segments as defined in ELF header.
	ph = (struct Proghdr*) (elf_buf + elf->e_phoff);
	for (i = 0; i < elf->e_phnum; i++, ph++) {
		if (ph->p_type != ELF_PROG_LOAD)
			continue;
		// Note: Here we make an assumption that every environment
		// uses the same lib module(i.e. ".lib" section), so that we haven't
		// to deal with the conflict on ".lib" section with the loaded program
		if ((uintptr_t) libtext <= ph->p_va && ph->p_va <= (uintptr_t) libend)
			continue;
		perm = PTE_P | PTE_U;
		if (ph->p_flags & ELF_PROG_FLAG_WRITE)
			perm |= PTE_W;
		if ((r = map_segment(ph->p_va, ph->p_memsz, fd, ph->p_filesz, ph->p_offset, perm)) < 0)
			goto destroy;
		// Note: Brk added in Lab 3 would not be set properly
		// (unless we define a new syscall to manually set brk)
	}
	close(fd);
	fd = -1;
	if ((r = (start_program(init_esp)) < 0))
		goto destroy;

	// Should never reach here.
	return 0;

error:
	close(fd);
	return r;
destroy:
	exit();
	return r;
}

// Exec, taking command-line arguments array directly on the stack.
// NOTE: Must have a sentinal of NULL at the end of the args
// (none of the args may be NULL).
int
execl(const char *prog, const char *arg0, ...)
{
	// We calculate argc by advancing the args until we hit NULL.
	// The contract of the function guarantees that the last
	// argument will always be NULL, and that none of the other
	// arguments will be NULL.
	int argc=0;
	va_list vl;
	va_start(vl, arg0);
	while(va_arg(vl, void *) != NULL)
		argc++;
	va_end(vl);

	// Now that we have the size of the args, do a second pass
	// and store the values in a VLA, which has the format of argv
	const char *argv[argc+2];
	argv[0] = arg0;
	argv[argc+1] = NULL;

	va_start(vl, arg0);
	unsigned i;
	for(i=0;i<argc;i++)
		argv[i+1] = va_arg(vl, const char *);
	va_end(vl);
	return execv(prog, argv);
}

// Set up the initial stack page for the new program using the arguments array
// pointed to by 'argv', which is a null-terminated array of pointers to
// null-terminated strings.
//
// On success, returns 0 and sets *init_esp to the initial stack pointer with
// which the program should start.
// Returns < 0 on failure.
static int
init_stack(const char **argv, uintptr_t *init_esp, uint32_t entry)
{
	size_t string_size;
	int argc, i, r;
	char *string_store;
	uintptr_t *argv_store;

	// Count the number of arguments (argc)
	// and the total amount of space needed for strings (string_size).
	string_size = 0;
	for (argc = 0; argv[argc] != 0; argc++)
		string_size += strlen(argv[argc]) + 1;

	// Determine where to place the strings and the argv array.
	// Set up pointers into the temporary page 'UTEMP'; we'll map a page
	// there later, then map that page into the stack at (USTACKTOP - PGSIZE).
	// strings is the topmost thing on the stack.
	string_store = (char*) UTEMP + PGSIZE - string_size;
	// argv is below that.  There's one argument pointer per argument, plus
	// a null pointer.
	argv_store = (uintptr_t*) (ROUNDDOWN(string_store, 4) - 4 * (argc + 1));

	// Make sure that argv, strings, and the 2 words that hold 'argc'
	// and 'argv' themselves will all fit in a single stack page.
	if ((void*) (argv_store - 2) < (void*) UTEMP)
		return -E_NO_MEM;

	// Allocate the single stack page at UTEMP.
	if ((r = sys_page_alloc(0, (void*) UTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		goto error;

	//	* Initialize 'argv_store[i]' to point to argument string i,
	//	  for all 0 <= i < argc.
	//	  Also, copy the argument strings from 'argv' into the
	//	  newly-allocated stack page.
	//
	//	* Set 'argv_store[argc]' to 0 to null-terminate the args array.
	//
	//	* Push two more words onto the new stack below 'args',
	//	  containing the argc and argv parameters to be passed
	//	  to the new program's umain() function.
	//	  argv should be below argc on the stack.
	//
	//	* Push the entry point of the new program onto the new stack so that
	//	  we can start the new program when stack is properly set.
	for (i = 0; i < argc; i++) {
		argv_store[i] = UTEMP2USTACK(string_store);
		strcpy(string_store, argv[i]);
		string_store += strlen(argv[i]) + 1;
	}
	argv_store[argc] = 0;
	assert(string_store == (char*)UTEMP + PGSIZE);

	argv_store[-1] = UTEMP2USTACK(argv_store);
	argv_store[-2] = argc;
	argv_store[-3] = entry;
	*init_esp = UTEMP2USTACK(&argv_store[-3]);
	return 0;

error:
	sys_page_unmap(0, UTEMP);
	return r;
}


// Helper function for start_program
static void
map_stack() {
	if (sys_page_map(0, UTEMP, 0, (void*) (USTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W) < 0)
		exit();
	sys_page_unmap(0, UTEMP);
}

// Map the already initialized stack into user stack and transfer the control
// to the new program.
//
// On success, sets esp to the initial stack pointer and eip to the entry point
// of the new program, and clear other general purpose registers, doesn't return.
// Returns < 0 on failure.
static int
start_program(uintptr_t init_esp)
{
	uintptr_t *temp_stack;
	int r;

	// After completing the stack, first change the current stack to a
	// temporary one.
	if ((r = sys_page_alloc(0, (void *) UTEMP2, PTE_P|PTE_U|PTE_W) < 0))
		return r;
	temp_stack = (uintptr_t *) (UTEMP2 + PGSIZE);
	temp_stack[-1] = init_esp;
	asm volatile ("movl $0, %%ebp\n\t"
			"movl %0, %%esp\n\t"

	// Then map the new stack into the user stack page
	// and unmap it from temp stack.
			"call %1\n\t"

	// And change the current stack back to the user stack
			"popl %%esp\n\t"
			"pushl %2\n\t"
			"pushl $0\n\t"
			"call sys_page_unmap\n\t"
			"addl $8, %%esp\n\t"

	// Then clear the registers and use "ret" to
	// transfer the control to the new program.
			"movl $0, %%eax\n\t"
			"movl $0, %%ebx\n\t"
			"movl $0, %%ecx\n\t"
			"movl $0, %%edx\n\t"
			"movl $0, %%esi\n\t"
			"movl $0, %%edi\n\t"
			"ret"
			:: "r" ((uintptr_t) (temp_stack - 1)), "m"(map_stack), "i" (UTEMP2));

	// Should never reach here!
	return 0;
}

static int
map_segment(uintptr_t va, size_t memsz, int fd,
	size_t filesz, off_t fileoffset, int perm)
{
	char *vaddr = ROUNDDOWN((char *) va, PGSIZE);
	char *file_end = ROUNDDOWN((char *) (va + filesz - 1), PGSIZE);
	char *mem_end = ROUNDDOWN((char *) (va + memsz - 1), PGSIZE);
	int r;

	for(; vaddr <= mem_end; vaddr += PGSIZE) {
		if (vaddr > file_end) {
			if ((r = sys_page_alloc(0, vaddr, perm)) < 0)
				return r;
		}
		else {
			if ((r = sys_page_alloc(0, UTEMP2, PTE_P|PTE_U|PTE_W)) < 0)
				return r;
			if ((r = seek(fd, fileoffset + MAX(va, (uintptr_t) vaddr) - va)) < 0)
				return r;
			if ((r = readn(fd,
					(char *) UTEMP2 + MAX(va, (uintptr_t) vaddr) - (uintptr_t) vaddr,
					MIN(va + filesz, (uintptr_t) vaddr + PGSIZE) - MAX(va, (uintptr_t) vaddr))) < 0)
				return r;
			if ((r = sys_page_map(0, UTEMP2, 0, vaddr, perm)) < 0)
				return r;
			sys_page_unmap(0, UTEMP2);
		}
	}
	return 0;
}


