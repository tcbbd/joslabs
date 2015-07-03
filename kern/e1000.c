#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pcireg.h>
#include <inc/x86.h>
#include <inc/lib.h>

static volatile uint32_t *e1000_memreg;
static volatile uint8_t *e1000_memflash; // QEMU emulated E1000 has no memory flash space?
// And we'll not use I/O space.

int pci_e1000_attach(struct pci_func *pcif) {
	pci_func_enable(pcif);
	e1000_memreg = pcif->reg_base[0];
	return 1;
};
