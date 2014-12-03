/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC(_divide_zero, 0)
TRAPHANDLER_NOEC(_debug, 1)
/*TRAPHANDLER_NOEC(_NMI, 2) not a trap*/
TRAPHANDLER_NOEC(_breakpoint, 3)
TRAPHANDLER_NOEC(_overflow, 4)
TRAPHANDLER_NOEC(_bound, 5)
TRAPHANDLER_NOEC(_invalid_opcode, 6)
TRAPHANDLER_NOEC(_device, 7)
TRAPHANDLER(_double_fault, 8)
/*TRAPHANDLER_NOEC(_coproc, 9)*/
TRAPHANDLER(_invalid_tss, 10)
TRAPHANDLER(_seg_not_present, 11)
TRAPHANDLER(_stack_fault, 12)
TRAPHANDLER(_general_protection, 13)
TRAPHANDLER(_page_fault, 14)
/*TRAPHANDLER_NOEC(_reserved, 15)*/
TRAPHANDLER_NOEC(_x87FPU_error, 16)
TRAPHANDLER(_align_check, 17)
TRAPHANDLER_NOEC(_machine_check, 18)
TRAPHANDLER_NOEC(_SIMD_FPerror, 19)
TRAPHANDLER_NOEC(_virtualization, 20)

TRAPHANDLER_NOEC(_timer, IRQ_OFFSET + IRQ_TIMER)
TRAPHANDLER_NOEC(_keyboard, IRQ_OFFSET + IRQ_KBD)
TRAPHANDLER_NOEC(_serial_port, IRQ_OFFSET + IRQ_SERIAL)
TRAPHANDLER_NOEC(_spurious_interrupt, IRQ_OFFSET + IRQ_SPURIOUS)
TRAPHANDLER_NOEC(_ide_driver, IRQ_OFFSET + IRQ_IDE)
TRAPHANDLER_NOEC(_apic_error, IRQ_OFFSET + IRQ_ERROR)

TRAPHANDLER_NOEC(_system_call, T_SYSCALL)

.globl sysenter_handler;
.type sysenter_handler, @function;
.align 2;
sysenter_handler:
	pushal
	pushfl

	pushl %edi
	pushl %esi
	pushl %edx
	pushl %ecx
	pushl %ebx
	pushl %eax
	movw $GD_KD, %ax
	movw %ax, %ds
	movw %ax, %es
	call syscall_sysenter
	movw $(GD_UD | 3), %dx
	movw %dx, %ds
	movw %dx, %es
/*saved esp and eip*/
	movl %ebp, %ecx
	movl (%ebp), %edx
/*sysenter will automatically disable interrupt, but sysexit won't recover it*/
	sti
/*possible to be interrupted here?*/
	sysexit
sysenter_spin:
	jmp sysenter_spin

_alltraps:
	pushl %ds
	pushl %es
	pushal
	movw $GD_KD, %ax
	movw %ax, %ds
	movw %ax, %es
	pushl %esp
	call trap
