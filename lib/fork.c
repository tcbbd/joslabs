// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	if (!(err & FEC_WR) || !(vpt[PGNUM(addr)] & PTE_COW))
		panic("pgfault: non COW page fault!");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	if ((r = sys_page_alloc(0, (void *) PFTEMP, PTE_P | PTE_U | PTE_W)) < 0)
		panic("sys_page_alloc: %e", r);
	memmove((void*) PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);
	if ((r = sys_page_map(0, (void *) PFTEMP, 0, ROUNDDOWN(addr, PGSIZE),
					PTE_P | PTE_U | PTE_W)) < 0)
		panic("sys_page_map: %e", r);
	if ((r = sys_page_unmap(0, (void *) PFTEMP)) < 0)
		panic("sys_page_unmap: %e", r);

}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	if ((vpt[pn] & PTE_W) || (vpt[pn] & PTE_COW)) {
		if ((r = sys_page_map(0, (void *) (pn * PGSIZE), envid,
						(void *) (pn * PGSIZE), PTE_P | PTE_U | PTE_COW)) < 0)
		return r;
		if ((r = sys_page_map(0, (void *) (pn * PGSIZE), 0,
						(void *) (pn * PGSIZE), PTE_P | PTE_U | PTE_COW)) < 0)
		return r;
	}
	else {
		if ((r = sys_page_map(0, (void *) (pn * PGSIZE), envid,
						(void *) (pn * PGSIZE), vpt[pn] & PTE_SYSCALL)) < 0)
		return r;
	}
	return 0;
}

extern void _pgfault_upcall(void);

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	envid_t envid;
	uintptr_t addr;
	int r;
	extern unsigned char end[];

	set_pgfault_handler(pgfault);

	// Allocate a new child environment.
	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0) {
		// Child
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// Allocate user exception stack of child environment.
	if ((r = sys_page_alloc(envid, (void *) (UXSTACKTOP - PGSIZE), PTE_P |
					PTE_U | PTE_W)) < 0)
		return r;

	// Map the pages according to flags in PTE
	for (addr = 0; addr < UXSTACKTOP - PGSIZE; addr += PGSIZE) {
		if (!(vpd[PDX(addr)] & PTE_P)) {
			addr += PGSIZE * (NPTENTRIES - 1);
			continue;
		}
		if (!(vpt[PGNUM(addr)] & PTE_P))
			continue;
		if ((r = duppage(envid, PGNUM(addr))) < 0)
			return r;
	}

	if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) < 0)
		return r;
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		return r;
	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
