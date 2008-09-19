/*
 * signalfd/eventfd compatibility
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "qemu-kvm.h"

#include <sys/syscall.h>

int kvm_eventfd(int *fds)
{
#if defined(SYS_eventfd)
    int ret;

    ret = syscall(SYS_eventfd, 0);
    if (ret >= 0) {
	fds[0] = fds[1] = ret;
	return 0;
    } else if (!(ret == -1 && errno == ENOSYS))
	return ret;
#endif

    return pipe(fds);
}
