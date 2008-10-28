/*
 * Qemu PowerPC 440 board emualtion
 *
 * Copyright 2007 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 * 	    Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *
 * This work is licensed under the GNU GPL licence version 2 or later
 *
 */

#ifndef QEMU_PPC440_H
#define QEMU_PPC440_H

#include "hw.h"
#include "ppc.h"
#include "ppc405.h"
#include "pc.h"
#include "qemu-timer.h"
#include "sysemu.h"
#include "exec-all.h"
#include "boards.h"

#define PPC440_MAX_RAM_SLOTS 4

void ppc440ep_init(CPUState *env,
		target_phys_addr_t ram_bases[PPC440_MAX_RAM_SLOTS],
		target_phys_addr_t ram_sizes[PPC440_MAX_RAM_SLOTS],
		int nbanks,
		qemu_irq **picp,
		ppc4xx_pci_t **pcip,
		int do_init);

#endif
