/*
 * Qemu PowerPC 440 board emualtion
 *
 * Copyright 2007 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 *
 */

#include "ppc440.h"

#define KERNEL_LOAD_ADDR 0x400000 /* uboot loader puts kernel at 4MB */

#include "qemu-kvm.h"

/* PPC 440 refrence demo board
 *
 * 440 PowerPC CPU
 */

void bamboo_init(ram_addr_t ram_size, int vga_ram_size,
			const char *boot_device, DisplayState *ds,
			const char *kernel_filename,
			const char *kernel_cmdline,
			const char *initrd_filename,
			const char *cpu_model)
{
	target_phys_addr_t ram_bases[2], ram_sizes[2];
	qemu_irq *pic;
	CPUState *env;
	target_ulong ep;
	int is_linux=1; /* Will assume allways is Linux for now */
	long kernel_size=0;
	target_ulong initrd_base=0;
	target_ulong initrd_size=0;

	printf("%s: START\n", __func__);

	/* Setup Memory */
	if (ram_size) {
		printf("Ram size specified on command line is %i bytes\n",
								(int)ram_size);
		printf("WARNING: RAM is hard coded to 144MB\n");
	}
	else {
		printf("Using defualt ram size of %iMB\n",
						((int)ram_size/1024)/1024);
	}

	/* Each bank can only have memory in configurations of
	 *   16MB, 32MB, 64MB, 128MB, or 256MB
	 */
	ram_bases[0] = 0x0;
	ram_sizes[0] = 0x08000000;
	ram_bases[1] = 0x0;
	ram_sizes[1] = 0x01000000;

	printf("Ram size of domain is %d bytes\n", (int)ram_size);

	/* Setup CPU */
	/* XXX We cheat for now and use 405 */
	env = cpu_ppc_init("405");
	if (!env) {
		fprintf(stderr, "Unable to initilize CPU!\n");
		exit(1);
	}

	/* call init */
	printf("Calling function ppc440_init\n");
	ppc440_init(env, ram_bases, ram_sizes, &pic,1);
	printf("Done calling ppc440_init\n");

	/* Register mem */
	cpu_register_physical_memory(0, ram_size, 0);
	if (kvm_enabled())
	    kvm_cpu_register_physical_memory(0, ram_size, 0);

	/* load kernel with uboot loader */
	printf("%s: load kernel\n", __func__);
	kernel_size = load_uboot(kernel_filename, &ep, &is_linux);
	if (kernel_size < 0) {
		fprintf(stderr, "qemu: could not load kernel '%s'\n",
			kernel_filename);
		exit(1);
	}

	/* load initrd */
	if (initrd_filename) {
		initrd_base = kernel_size + KERNEL_LOAD_ADDR;
		initrd_size = load_image(initrd_filename,
				phys_ram_base + initrd_base);

		if (initrd_size < 0) {
			fprintf(stderr,
				"qemu: could not load initial ram disk '%s'\n",
				initrd_filename);
			exit(1);
		}
	}

	if (kvm_enabled()) {
	    /* XXX insert TLB entries */
	    env->gpr[1] = (16<<20) - 8;
	    env->gpr[4] = initrd_base;
	    env->gpr[5] = initrd_size;

	    env->nip = ep;

	    env->cpu_index = 0;
	    printf("%s: loading kvm registers\n", __func__);
	    kvm_load_registers(env);
	}

	printf("%s: DONE\n", __func__);
}

QEMUMachine bamboo_machine = {
	"bamboo",
	"bamboo",
	bamboo_init,
};
