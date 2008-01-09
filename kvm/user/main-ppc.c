/*
 * Kernel-based Virtual Machine test driver
 *
 * This test driver provides a simple way of testing kvm, without a full
 * device model.
 *
 * Copyright (C) 2006 Qumranet
 * Copyright IBM Corp. 2008
 *
 * Authors:
 *
 *  Avi Kivity <avi@qumranet.com>
 *  Yaniv Kamay <yaniv@qumranet.com>
 *  Hollis Blanchard <hollisb@us.ibm.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 */

#define _GNU_SOURCE

#include <libkvm.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <inttypes.h>

static int gettid(void)
{
	return syscall(__NR_gettid);
}

kvm_context_t kvm;

#define IPI_SIGNAL (SIGRTMIN + 4)

static int ncpus = 1;
static sem_t init_sem;
static __thread int vcpu;
static sigset_t kernel_sigmask;
static sigset_t ipi_sigmask;
static uint64_t memory_size = 128 * 1024 * 1024;

struct vcpu_info {
	pid_t tid;
};

struct vcpu_info *vcpus;

static int test_debug(void *opaque, int vcpu)
{
	printf("test_debug\n");
	return 0;
}

static int test_halt(void *opaque, int vcpu)
{
	int n;

	sigwait(&ipi_sigmask, &n);
	return 0;
}

static int test_io_window(void *opaque)
{
	return 0;
}

static int test_try_push_interrupts(void *opaque)
{
	return 0;
}

static void test_post_kvm_run(void *opaque, int vcpu)
{
}

static int test_pre_kvm_run(void *opaque, int vcpu)
{
	return 0;
}

static int test_mem_read(void *opaque, uint64_t addr, uint8_t *data, int len)
{
	printf("%s: addr %"PRIx64" len %d\n", __func__, addr, len);
	memset(data, 0, len);
	return 0;
}

static int test_mem_write(void *opaque, uint64_t addr, uint8_t *data, int len)
{
	printf("%s: addr %"PRIx64" len %d data %"PRIx64"\n",
	       __func__, addr, len, *(uint64_t *)data);
	return 0;
}

static int test_dcr_read(kvm_context_t kvm, uint32_t dcrn, uint32_t *data)
{
	printf("%s: dcrn %04X\n", __func__, dcrn);
	*data = 0;
	return 0;
}

static int test_dcr_write(kvm_context_t kvm, uint32_t dcrn, uint32_t data)
{
	printf("%s: dcrn %04X data %04X\n", __func__, dcrn, data);
	return 0;
}

static struct kvm_callbacks test_callbacks = {
	.mmio_read   = test_mem_read,
	.mmio_write  = test_mem_write,
	.debug       = test_debug,
	.halt        = test_halt,
	.io_window = test_io_window,
	.try_push_interrupts = test_try_push_interrupts,
	.post_kvm_run = test_post_kvm_run,
	.pre_kvm_run = test_pre_kvm_run,
	.powerpc_dcr_read = test_dcr_read,
	.powerpc_dcr_write = test_dcr_write,
};

static unsigned long load_file(void *mem, const char *fname, int inval_icache)
{
	int r;
	int fd;
	unsigned long bytes = 0;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

	while ((r = read(fd, mem, 4096)) != -1 && r != 0) {
		mem += r;
		bytes += r;
	}

	if (r == -1) {
		perror("read");
		exit(1);
	}

	return bytes;
}

#define ICACHE_LINE_SIZE 32

void sync_caches(void *mem, unsigned long len)
{
	unsigned long i;

	for (i = 0; i < len; i += ICACHE_LINE_SIZE)
		asm volatile ("dcbst %0, %1" : : "g"(mem), "r"(i));
	asm volatile ("sync");
	for (i = 0; i < len; i += ICACHE_LINE_SIZE)
		asm volatile ("icbi %0, %1" : : "g"(mem), "r"(i));
	asm volatile ("sync; isync");
}

static void init_vcpu(int n, unsigned long entry)
{
	struct kvm_regs regs = {
		.pc = entry,
	};

	kvm_set_regs(kvm, 0, &regs);

	sigemptyset(&ipi_sigmask);
	sigaddset(&ipi_sigmask, IPI_SIGNAL);
	sigprocmask(SIG_UNBLOCK, &ipi_sigmask, NULL);
	sigprocmask(SIG_BLOCK, &ipi_sigmask, &kernel_sigmask);
	vcpus[n].tid = gettid();
	vcpu = n;
	kvm_set_signal_mask(kvm, n, &kernel_sigmask);
	sem_post(&init_sem);
}

static void *do_create_vcpu(void *_n)
{
	int n = (long)_n;

	kvm_create_vcpu(kvm, n);
	init_vcpu(n, 0x0);
	kvm_run(kvm, n);
	return NULL;
}

static void start_vcpu(int n)
{
	pthread_t thread;

	pthread_create(&thread, NULL, do_create_vcpu, (void *)(long)n);
}

static void usage(const char *progname)
{
	fprintf(stderr,
"Usage: %s [OPTIONS] [bootstrap] flatfile\n"
"KVM test harness.\n"
"\n"
"  -s, --smp=NUM          create a VM with NUM virtual CPUs\n"
"  -m, --memory=NUM[GMKB] allocate NUM memory for virtual machine.  A suffix\n"
"                         can be used to change the unit (default: `M')\n"
"  -h, --help             display this help screen and exit\n"
"\n"
"Report bugs to <kvm-devel@lists.sourceforge.net>.\n"
		, progname);
}

static void sig_ignore(int sig)
{
	write(1, "boo\n", 4);
}

int main(int argc, char **argv)
{
	void *vm_mem;
	unsigned long len;
	int i;
	const char *sopts = "s:phm:";
	struct option lopts[] = {
		{ "smp", 1, 0, 's' },
		{ "memory", 1, 0, 'm' },
		{ "help", 0, 0, 'h' },
		{ 0 },
	};
	int opt_ind, ch;
	int nb_args;
	char *endptr;

	while ((ch = getopt_long(argc, argv, sopts, lopts, &opt_ind)) != -1) {
		switch (ch) {
		case 's':
			ncpus = atoi(optarg);
			break;
		case 'm':
			memory_size = strtoull(optarg, &endptr, 0);
			switch (*endptr) {
			case 'G': case 'g':
				memory_size <<= 30;
				break;
			case '\0':
			case 'M': case 'm':
				memory_size <<= 20;
				break;
			case 'K': case 'k':
				memory_size <<= 10;
				break;
			default:
				fprintf(stderr,
					"Unrecongized memory suffix: %c\n",
					*endptr);
				exit(1);
			}
			if (memory_size == 0) {
				fprintf(stderr,
					"Invalid memory size: 0\n");
				exit(1);
			}
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		case '?':
		default:
			fprintf(stderr,
				"Try `%s --help' for more information.\n",
				argv[0]);
			exit(1);
		}
	}

	nb_args = argc - optind;
	if (nb_args < 1 || nb_args > 2) {
		fprintf(stderr,
			"Incorrect number of arguments.\n"
			"Try `%s --help' for more information.\n",
			argv[0]);
		exit(1);
	}

	signal(IPI_SIGNAL, sig_ignore);

	vcpus = calloc(ncpus, sizeof *vcpus);
	if (!vcpus) {
		fprintf(stderr, "calloc failed\n");
		return 1;
	}

	kvm = kvm_init(&test_callbacks, 0);
	if (!kvm) {
		fprintf(stderr, "kvm_init failed\n");
		return 1;
	}
	if (kvm_create(kvm, memory_size, &vm_mem) < 0) {
		kvm_finalize(kvm);
		fprintf(stderr, "kvm_create failed\n");
		return 1;
	}

	vm_mem = kvm_create_phys_mem(kvm, 0, memory_size, 0, 1);

	len = load_file(vm_mem, argv[optind], 1);
	sync_caches(vm_mem, len);

	sem_init(&init_sem, 0, 0);
	init_vcpu(0, 0x0);
	for (i = 1; i < ncpus; ++i)
		start_vcpu(i);
	for (i = 0; i < ncpus; ++i)
		sem_wait(&init_sem);

	kvm_run(kvm, 0);

	return 0;
}
