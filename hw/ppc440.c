/*
 * Qemu PowerPC 440 board emualtion
 *
 * Copyright 2007 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 * 	    Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 */


#include "hw.h"
#include "hw/isa.h"
#include "ppc440.h"

#define PPC440EP_PCI_CONFIG 0xeec00000
#define PPC440EP_PCI_INTACK 0xeed00000
#define PPC440EP_PCI_SPECIAL 0xeed00000
#define PPC440EP_PCI_REGS 0xef400000
#define PPC440EP_PCI_IO 0xe8000000
#define PPC440EP_PCI_IOLEN 0x10000
#define PPC440EP_PCI_MEM 0xa0000000
#define PPC440EP_PCI_MEMLEN 0x20000000


void ppc440ep_init(CPUState *env,
		target_phys_addr_t ram_bases[PPC440_MAX_RAM_SLOTS],
		target_phys_addr_t ram_sizes[PPC440_MAX_RAM_SLOTS],
		int nbanks,
		qemu_irq **picp,
		ppc4xx_pci_t **pcip,
		int do_init)
{
	ppc4xx_mmio_t *mmio;
	qemu_irq *pic, *irqs;
	ppc4xx_pci_t *pci;
	int i;

	ppc_dcr_init(env, NULL, NULL);

	/* mmio */
	printf("setup mmio\n");
	mmio = ppc4xx_mmio_init(env, 0xEF600000);

	/* universal controller */
	printf("setup universal controller\n");
	irqs = qemu_mallocz(sizeof(qemu_irq) * PPCUIC_OUTPUT_NB);
	irqs[PPCUIC_OUTPUT_INT] =
		((qemu_irq *)env->irq_inputs)[PPC40x_INPUT_INT];
	irqs[PPCUIC_OUTPUT_CINT] =
		((qemu_irq *)env->irq_inputs)[PPC40x_INPUT_CINT];
	pic = ppcuic_init(env, irqs, 0x0C0, 0, 1);
	*picp = pic;

	/* SDRAM controller */
	printf("trying to setup sdram controller\n");
	/* XXX 440EP's ECC interrupts are on UIC1 */
	ppc405_sdram_init(env, pic[14], nbanks, ram_bases, ram_sizes, do_init);

	/* PCI */
	pci = ppc4xx_pci_init(env, pic,
	                      PPC440EP_PCI_CONFIG,
	                      PPC440EP_PCI_INTACK,
	                      PPC440EP_PCI_SPECIAL,
	                      PPC440EP_PCI_REGS);
	if (!pci)
		printf("couldn't create PCI controller!\n");
	*pcip = pci;

	isa_mmio_init(PPC440EP_PCI_IO, PPC440EP_PCI_IOLEN);

	/* serial ports on page 126 of 440EP user manual */
	if (serial_hds[0]) {
		printf("Initializing first serial port\n");
		ppc405_serial_init(env, mmio,0x300, pic[0], serial_hds[0]);
	}
	if (serial_hds[1]) {
		printf("Initializing 2nd serial port\n");
		ppc405_serial_init(env, mmio,0x400, pic[1], serial_hds[1]);
	}
}
