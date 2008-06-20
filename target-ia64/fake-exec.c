/*
 * fake-exec.c for ia64.
 *
 * This is a file for stub functions so that compilation is possible
 * when TCG CPU emulation is disabled during compilation.
 *
 * Copyright 2007 IBM Corporation.
 * Added by & Authors:
 * 	Jerone Young <jyoung5@us.ibm.com>
 *
 * Copyright 2008 Intel Corporation.
 * Added by Xiantao Zhang <xiantao.zhang@intel.com>
 *
 * This work is licensed under the GNU GPL licence version 2 or later.
 *
 */
#include "exec.h"
#include "cpu.h"

int code_copy_enabled = 0;

void cpu_gen_init(void)
{
}

unsigned long code_gen_max_block_size(void)
{
    return 32;
}

int cpu_ia64_gen_code(CPUState *env, TranslationBlock *tb, int *gen_code_size_ptr)
{
    return 0;
}

void tcg_dump_info(FILE *f,
                   int (*cpu_fprintf)(FILE *f, const char *fmt, ...))
{
    return;
}

void flush_icache_range(unsigned long start, unsigned long stop)
{
    while (start < stop) {
	asm volatile ("fc %0" :: "r"(start));
	start += 32;
    }
    asm volatile (";;sync.i;;srlz.i;;");
}

