#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}

extern void sysenter_handler();

extern void _divide_zero();
extern void _debug();
//extern void _NMI();
extern void _breakpoint();
extern void _overflow();
extern void _bound();
extern void _invalid_opcode();
extern void _device();
extern void _double_fault();
//extern void _coproc();
extern void _invalid_tss();
extern void _seg_not_present();
extern void _stack_fault();
extern void _general_protection();
extern void _page_fault();
//extern void _reserved();
extern void _x87FPU_error();
extern void _align_check();
extern void _machine_check();
extern void _SIMD_FPerror();
extern void _virtualization();

extern void _timer();
extern void _keyboard();
extern void _serial_port();
extern void _spurious_interrupt();
extern void _ide_driver();
extern void _apic_error();

extern void _system_call();

void
trap_init(void)
{
	extern struct Segdesc gdt[];

	//Traps, but trap() suggests that IF should be cleared whether it is caused
	//by interrupt or exception, so they are all set to Interrupt Gates.
	SETGATE(idt[T_DIVIDE], 0, GD_KT, _divide_zero, 0);
	SETGATE(idt[T_DEBUG], 0, GD_KT, _debug, 0);
	//SETGATE(idt[T_NMI], 0, GD_KT, _NMI, 0); intr will be set in next lab
	SETGATE(idt[T_BRKPT], 0, GD_KT, _breakpoint, 3);
	SETGATE(idt[T_OFLOW], 0, GD_KT, _overflow, 3);
	SETGATE(idt[T_BOUND], 0, GD_KT, _bound, 0);
	SETGATE(idt[T_ILLOP], 0, GD_KT, _invalid_opcode, 0);
	SETGATE(idt[T_DEVICE], 0, GD_KT, _device, 0);
	SETGATE(idt[T_DBLFLT], 0, GD_KT, _double_fault, 0);
	//SETGATE(idt[T_COPROC], 0, GD_KT, _coproc, 0);
	SETGATE(idt[T_TSS], 0, GD_KT, _invalid_tss, 0);
	SETGATE(idt[T_SEGNP], 0, GD_KT, _seg_not_present, 0);
	SETGATE(idt[T_STACK], 0, GD_KT, _stack_fault, 0);
	SETGATE(idt[T_GPFLT], 0, GD_KT, _general_protection, 0);
	SETGATE(idt[T_PGFLT], 0, GD_KT, _page_fault, 0);
	//SETGATE(idt[T_RES], 0, GD_KT, _reserved, 0);
	SETGATE(idt[T_FPERR], 0, GD_KT, _x87FPU_error, 0);
	SETGATE(idt[T_ALIGN], 0, GD_KT, _align_check, 0);
	SETGATE(idt[T_MCHK], 0, GD_KT, _machine_check, 0);
	SETGATE(idt[T_SIMDERR], 0, GD_KT, _SIMD_FPerror, 0);
	SETGATE(idt[T_VIRT], 0, GD_KT, _virtualization, 0);

	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0, GD_KT, _timer, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_KBD], 0, GD_KT, _keyboard, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL], 0, GD_KT, _serial_port, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0, GD_KT, _spurious_interrupt, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_IDE], 0, GD_KT, _ide_driver, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_ERROR], 0, GD_KT, _apic_error, 0);

	SETGATE(idt[T_SYSCALL], 0, GD_KT, _system_call, 3);

	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct Cpu;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.

	// when it is called in trap_init, lapic is not initialized, so thiscpu
	// would be cpus[0]
	struct Taskstate * ts_percpu = &thiscpu->cpu_ts;
	int i = cpunum();

	//init for sysenter
	write_msr(IA32_SYSENTER_CS, GD_KT);
	write_msr(IA32_SYSENTER_ESP, KSTACKTOP - i * (KSTKSIZE + KSTKGAP));
	write_msr(IA32_SYSENTER_EIP, (uint32_t)(char *) sysenter_handler);

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts_percpu->ts_esp0 = KSTACKTOP - i * (KSTKSIZE + KSTKGAP);
	ts_percpu->ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3) + i] = SEG16(STS_T32A, (uint32_t) (ts_percpu),
					sizeof(struct Taskstate), 0);
	gdt[(GD_TSS0 >> 3) + i].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0 + (i << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	switch (tf->tf_trapno) {
		case T_DEBUG:
			//only support stepi now
			//theorically possible to support watchpoint
			monitor_stepi(tf);
			return;
		case T_BRKPT:
			//user can exit the monitor
			monitor(tf);
			return;
		case T_PGFLT:
			page_fault_handler(tf);
			break;
		case T_SYSCALL:
			// According to Lab 3 we should not use int $T_SYSCALL to do system
			// call, but it seems not consistent with Lab 4
			tf->tf_regs.reg_eax = syscall(tf->tf_regs.reg_eax,
					tf->tf_regs.reg_ebx, tf->tf_regs.reg_ecx,
					tf->tf_regs.reg_edx, tf->tf_regs.reg_esi,
					tf->tf_regs.reg_edi);
			return;
		default:
			break;
	}

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
		lapic_eoi();
		sched_yield();
		return;
	}

	// Add time tick increment to clock interrupts.
	// Be careful! In multiprocessors, clock interrupts are
	// triggered on every CPU.
	// LAB 6: Your code here.


	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		lock_kernel();
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;
	struct UTrapframe *utf;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();
	// Handle kernel-mode page faults.

	if ((tf->tf_err & FEC_U) == 0)
		panic("Page fault in kernel");

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	if (curenv->env_pgfault_upcall == NULL)
		goto destroy;

	if (UXSTACKTOP - PGSIZE <= tf->tf_esp && tf->tf_esp < UXSTACKTOP)
		utf = (struct UTrapframe *)(tf->tf_esp - 4 - sizeof(struct UTrapframe));
	else if (USTACKTOP - PGSIZE <= tf->tf_esp && tf->tf_esp < USTACKTOP)
		utf = (struct UTrapframe *)(UXSTACKTOP - sizeof(struct UTrapframe));
	else
		goto destroy;
	user_mem_assert(curenv, utf, sizeof(utf), PTE_W);
	utf->utf_fault_va = fault_va;
	utf->utf_err = tf->tf_err;
	utf->utf_regs = tf->tf_regs;
	utf->utf_eip = tf->tf_eip;
	utf->utf_eflags = tf->tf_eflags;
	utf->utf_esp = tf->tf_esp;
	tf->tf_esp = (uintptr_t) utf;
	tf->tf_eip = (uintptr_t) curenv->env_pgfault_upcall;
	env_run(curenv);

destroy:
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

