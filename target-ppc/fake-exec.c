/*
 * fake-exec.c
 *
 * This is a file for stub functions so that compilation is possible
 * when TCG CPU emulation is disabled during compilation.
 *
 * Copyright 2007 IBM Corporation.
 * Added by & Authors:
 * 	Jerone Young <jyoung5@us.ibm.com>
 * This work is licensed under the GNU GPL licence version 2 or later.
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "cpu.h"
#include "exec-all.h"

int code_copy_enabled = 0;

void cpu_dump_state (CPUState *env, FILE *f,
                     int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
                     int flags)
{
}

void ppc_cpu_list (FILE *f, int (*cpu_fprintf)(FILE *f, const char *fmt, ...))
{
}

void cpu_dump_statistics (CPUState *env, FILE*f,
                          int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
                          int flags)
{
}

unsigned long code_gen_max_block_size(void)
{
    return 32;
}

void cpu_gen_init(void)
{
}

int cpu_restore_state(TranslationBlock *tb,
                      CPUState *env, unsigned long searched_pc,
                      void *puc)

{
    return 0;
}

int cpu_ppc_gen_code(CPUState *env, TranslationBlock *tb, int *gen_code_size_ptr)
{
    return 0;
}

const ppc_def_t *cpu_ppc_find_by_name (const unsigned char *name)
{
    return NULL;
}

int cpu_ppc_register_internal (CPUPPCState *env, const ppc_def_t *def)
{
    return 0;
}

void flush_icache_range(unsigned long start, unsigned long stop)
{
}
