/*
 * Qemu PowerPC 440 board emualtion
 *
 * Copyright 2007 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 */

#include "config.h"
#include "qemu-common.h"
#include "net.h"
#include "hw.h"
#include "pci.h"
#include "sysemu.h"
#include "ppc440.h"
#include "qemu-kvm.h"
#include "device_tree.h"

#define BINARY_DEVICE_TREE_FILE "bamboo.dtb"

#define bytes_to_mb(a) (a>>20)

void bamboo_init(ram_addr_t ram_size, int vga_ram_size,
			const char *boot_device, DisplayState *ds,
			const char *kernel_filename,
			const char *kernel_cmdline,
			const char *initrd_filename,
			const char *cpu_model)
{
	char *buf=NULL;
	target_phys_addr_t ram_bases[4], ram_sizes[4];
	NICInfo *nd;
	qemu_irq *pic;
	ppc4xx_pci_t *pci;
	CPUState *env;
	uint64_t ep=0;
	uint64_t la=0;
	int is_linux=1; /* Will assume allways is Linux for now */
	target_long kernel_size=0;
	target_ulong initrd_base=0;
	target_long initrd_size=0;
	target_ulong dt_base=0;
	void *fdt;
	int ret;
	int ram_stick_sizes[] = {256<<20, 128<<20, 64<<20,
				32<<20, 16<<20, 8<<20 }; /* in bytes */
	ram_addr_t tmp_ram_size;
	int i=0, k=0;
	uint32_t cpu_freq;
	uint32_t timebase_freq;
	uint32_t mem_reg_property[]={0, 0, ram_size};

	printf("%s: START\n", __func__);

	/* Setup Memory */
	printf("Ram size passed is: %i MB\n",
				bytes_to_mb((int)ram_size));

	tmp_ram_size = ram_size;

	for (i=0; i < (sizeof(ram_sizes)/sizeof(ram_sizes[0])); i++) {
		for (k=0; k < (sizeof(ram_stick_sizes)/sizeof(ram_stick_sizes[0])); k++) {
			if ((tmp_ram_size/ram_stick_sizes[k]) > 0) {
				ram_sizes[i] = ram_stick_sizes[k];
				tmp_ram_size -= ram_stick_sizes[k];
				break;
			}
		}
	}

	if (tmp_ram_size) {
		printf("WARNING: %i MB left over memory is ram\n",
			bytes_to_mb((int)tmp_ram_size));
		ram_size -= tmp_ram_size;
		mem_reg_property[2] = ram_size;
	}

	/* Setup CPU.
	 * XXX Since qemu doesn't implement 440, we just say it's a 405. Since
	 * we don't use qemu's CPU emulation it seems to be working OK. */
	env = cpu_ppc_init("405");
	if (!env) {
		fprintf(stderr, "Unable to initialize CPU!\n");
		exit(1);
	}

	/* call init */
	printf("Calling function ppc440_init\n");
	ppc440ep_init(env, ram_bases, ram_sizes, &pic, &pci, 1);
	printf("Done calling ppc440_init\n");

	/* Register mem */
	cpu_register_physical_memory(0, ram_size, 0);

	/* load kernel with uboot loader */
	printf("%s: load kernel\n", __func__);
	ret = load_uimage(kernel_filename, &ep, &la, &kernel_size, &is_linux);
	if (ret < 0)
		ret = load_elf(kernel_filename, 0, &ep, &la, NULL);

	if (ret < 0) {
		fprintf(stderr, "qemu: could not load kernel '%s'\n",
			kernel_filename);
		exit(1);
	}
	printf("kernel is at guest address: 0x%lx\n", (unsigned long)la);

	/* load initrd */
	if (initrd_filename) {
		initrd_base = kernel_size + la;
		printf("%s: load initrd\n", __func__);
		initrd_size = load_image(initrd_filename,
				phys_ram_base + initrd_base);

		printf("initrd is at guest address: 0x%lx\n",
					(unsigned long) initrd_base);

		if (initrd_size < 0) {
			fprintf(stderr,
				"qemu: could not load initial ram disk '%s'\n",
				initrd_filename);
			exit(1);
		}
	}

#ifdef CONFIG_LIBFDT
	/* get variable for device tree */
	cpu_freq = read_proc_dt_prop_cell("cpus/cpu@0/clock-frequency");
	timebase_freq = read_proc_dt_prop_cell("cpus/cpu@0/timebase-frequency");

	/* load binary device tree into qemu (not guest memory) */
	printf("%s: load device tree file\n", __func__);

	/* get string size */
	ret = asprintf(&buf, "%s/%s", bios_dir,
		BINARY_DEVICE_TREE_FILE);

	if (ret < 0) {
		printf("%s: Unable to malloc string buffer buf\n",
			__func__);
		exit(1);
	}

	/* set base for device tree that will be in guest memory */
	if (initrd_base)
		dt_base = initrd_base + initrd_size;
	else
		dt_base = kernel_size + la;

	fdt = load_device_tree(buf, (unsigned long)(phys_ram_base + dt_base));
	if (fdt == NULL) {
		printf("Loading device tree failed!\n");
		exit(1);
	}

	printf("device tree address is at guest address: 0x%lx\n",
		(unsigned long) dt_base);

	free(buf);

	/* manipulate device tree in memory */
	dt_cell(fdt, "/cpus/cpu@0", "clock-frequency", cpu_freq);
	dt_cell(fdt, "/cpus/cpu@0", "timebase-frequency", timebase_freq);
	dt_cell_multi(fdt, "/memory", "reg", mem_reg_property,
			sizeof(mem_reg_property));
	dt_cell(fdt, "/chosen", "linux,initrd-start", initrd_base);
	dt_cell(fdt, "/chosen", "linux,initrd-end",
				(initrd_base + initrd_size));
	dt_string(fdt, "/chosen", "bootargs", (char *)kernel_cmdline);
#endif

	if (kvm_enabled()) {
		/* XXX insert TLB entries */
		env->gpr[1] = (16<<20) - 8;

#ifdef CONFIG_LIBFDT
		/* location of device tree in register */
		env->gpr[3] = dt_base;
#endif
		env->nip = ep;
	}

	if (pci) {
		int unit_id = 0;

		/* Add virtio block devices. */
		while ((i = drive_get_index(IF_VIRTIO, 0, unit_id)) != -1) {
			virtio_blk_init(pci->bus, 0x1AF4, 0x1001,
				drives_table[i].bdrv);
			unit_id++;
		}

		/* Register network interfaces. */
		for (i = 0; i < nb_nics; i++) {
			nd = &nd_table[i];
			if (!nd->model)
				nd->model = "virtio";
			pci_nic_init(pci->bus, nd, -1);
		}
	}

	printf("%s: DONE\n", __func__);
}

QEMUMachine bamboo_machine = {
	.name = "bamboo",
	.desc = "bamboo",
	.init = bamboo_init,
	.max_cpus = 1,
};
