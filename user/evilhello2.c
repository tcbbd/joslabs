// evil hello world -- kernel pointer passed to kernel
// kernel should destroy user environment in response

#include <inc/lib.h>
#include <inc/mmu.h>
#include <inc/x86.h>


// Call this function with ring0 privilege
void evil()
{
	// Kernel memory access
	*(char*)0xf010000a = 0;

	// Out put something via outb
	outb(0x3f8, 'I');
	outb(0x3f8, 'N');
	outb(0x3f8, ' ');
	outb(0x3f8, 'R');
	outb(0x3f8, 'I');
	outb(0x3f8, 'N');
	outb(0x3f8, 'G');
	outb(0x3f8, '0');
	outb(0x3f8, '!');
	outb(0x3f8, '!');
	outb(0x3f8, '!');
	outb(0x3f8, '\n');
}

static void
sgdt(struct Pseudodesc* gdtd)
{
	__asm __volatile("sgdt %0" :  "=m" (*gdtd));
}

static void (*ring0_called_func)(void) = NULL;

static void
ring0_call_wrapper() {
	ring0_called_func();
	__asm __volatile ("leave\n\t"
			"lret");
}

// Invoke a given function pointer with ring0 privilege, then return to ring3
void ring0_call(void (*fun_ptr)(void)) {
    // Here's some hints on how to achieve this.
    // 1. Store the GDT descripter to memory (sgdt instruction)
    // 2. Map GDT in user space (sys_map_kernel_page)
    // 3. Setup a CALLGATE in GDT (SETCALLGATE macro)
    // 4. Enter ring0 (lcall instruction)
    // 5. Call the function pointer
    // 6. Recover GDT entry modified in step 3 (if any)
    // 7. Leave ring0 (lret instruction)

    // Hint : use a wrapper function to call fun_ptr. Feel free
    //        to add any functions or global variables in this 
    //        file if necessary.

	struct Pseudodesc gdtr;
	struct Gatedesc *gdt, replaced_seg;
	char *gdt_page = (char *) 0x80000000;

	sgdt(&gdtr);
	sys_map_kernel_page((char *) gdtr.pd_base, gdt_page);
	gdt = (struct Gatedesc *) (gdt_page + (gdtr.pd_base % PGSIZE));

	// replace TSS descriptor with call gate
	ring0_called_func = fun_ptr;
	replaced_seg = gdt[5];
	SETCALLGATE(((struct Gatedesc volatile *)gdt)[5], GD_KT, ring0_call_wrapper, 3);

	// call the function through far call instruction
	__asm __volatile ("lcall %0, $0" : : "i"(GD_TSS0));
	gdt[5] = replaced_seg;
}

void
umain(int argc, char **argv)
{
        // call the evil function in ring0
	ring0_call(&evil);

	// call the evil function in ring3
	evil();
}

