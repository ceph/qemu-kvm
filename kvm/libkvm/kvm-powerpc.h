/*
 * This header is for functions & variables that will ONLY be
 * used inside libkvm for powerpc.
 * THESE ARE NOT EXPOSED TO THE USER AND ARE ONLY FOR USE
 * WITHIN LIBKVM.
 *
 * Copyright (C) 2007 IBM
 *
 * Authors:
 *	Jerone Young <jyoung5@us.ibm.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 */

#ifndef KVM_POWERPC_H
#define KVM_POWERPC_H

#include "kvm-common.h"

#define PAGE_SIZE 4096ul
#define PAGE_MASK (~(PAGE_SIZE - 1))

#endif
