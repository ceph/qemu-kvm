/*
 * Qemu PowerPC 440 board emualtion
 *
 * Copyright 2007 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 */

#include "ppc440.h"

void ppc440ep_init(CPUState *env,
		target_phys_addr_t ram_bases[2],
		target_phys_addr_t ram_sizes[2],
		qemu_irq **picp,
		int do_init)
{
	ppc4xx_mmio_t *mmio;
	qemu_irq *pic, *irqs;
	ram_addr_t offset;
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
	ppc405_sdram_init(env, pic[14], 2, ram_bases, ram_sizes, do_init);
	offset = 0;
	for (i = 0; i < 2; i++)
		offset += ram_sizes[i];

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
