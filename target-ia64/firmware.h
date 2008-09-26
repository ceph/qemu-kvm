/*
 * firmwar.h: Firmware build logic head file
 *
 * Copyright (c) 2007, Intel Corporation.
 * Zhang Xiantao <xiantao.zhang@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#ifndef __FIRM_WARE_H
#define  __FIRM_WARE_
#include "cpu.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <zlib.h>

#define GFW_SIZE                (16UL<<20)
#define GFW_START               ((4UL<<30) - GFW_SIZE)

#define HOB_SIGNATURE           0x3436474953424f48        // "HOBSIG64"
#define GFW_HOB_START           ((4UL<<30) - (14UL<<20))    // 4G - 14M
#define GFW_HOB_SIZE            (1UL<<20)                 // 1M
#define HOB_OFFSET              (GFW_HOB_START-GFW_START)

#define Hob_Output(s)           fprintf(stderr, s)

extern int kvm_ia64_build_hob(unsigned long memsize,
                              unsigned long vcpus, uint8_t* fw_start);
extern char *read_image(const char *filename, unsigned long *size);

#endif //__FIRM_WARE_
