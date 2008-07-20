/*
 * QEMU VMPort emulation
 *
 * Copyright (C) 2007 Hervé Poussineau
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hw.h"
#include "isa.h"
#include "pc.h"
#include "sysemu.h"
#include "qemu-kvm.h"

#define VMPORT_CMD_GETCPUSPEED 0x01
#define VMPORT_CMD_GETVERSION 0x0a
#define VMPORT_CMD_GETRAMSIZE 0x14
#define VMPORT_CMD_GETBIOSUUID 0x13

#define VMPORT_ENTRIES 0x2c
#define VMPORT_MAGIC   0x564D5868

typedef struct _VMPortState
{
    IOPortReadFunc *func[VMPORT_ENTRIES];
    void *opaque[VMPORT_ENTRIES];
} VMPortState;

static VMPortState port_state;

void vmport_register(unsigned char command, IOPortReadFunc *func, void *opaque)
{
    if (command >= VMPORT_ENTRIES)
        return;

    port_state.func[command] = func;
    port_state.opaque[command] = opaque;
}

static uint32_t vmport_ioport_rw(VMPortState *s, CPUState *env, uint32_t addr)
{
    unsigned char command;
    uint32_t eax;

    eax = env->regs[R_EAX];
    if (eax != VMPORT_MAGIC)
        return eax;

    command = env->regs[R_ECX];
    if (command >= VMPORT_ENTRIES)
        return eax;
    if (!s->func[command])
    {
        printf("vmport: unknown command %x\n", command);
        return eax;
    }

    return s->func[command](s->opaque[command], addr);
}

static uint32_t vmport_ioport_read(void *opaque, uint32_t addr)
{
    VMPortState *s = opaque;
    CPUState *env = cpu_single_env;
    uint32_t ret;

    if (kvm_enabled())
	kvm_save_registers(env);

    ret = vmport_ioport_rw(s, env, addr);

    if (kvm_enabled())
	kvm_load_registers(env);

    return ret;
}

static void vmport_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    VMPortState *s = opaque;
    CPUState *env = cpu_single_env;

    if (kvm_enabled())
	kvm_save_registers(env);

    env->regs[R_EAX] = vmport_ioport_rw(s, env, addr);

    if (kvm_enabled())
	kvm_load_registers(env);
}

static uint32_t vmport_cmd_get_version(void *opaque, uint32_t addr)
{
    CPUState *env = cpu_single_env;
    env->regs[R_EBX] = VMPORT_MAGIC;
    return 6;
}

static uint32_t vmport_cmd_ram_size(void *opaque, uint32_t addr)
{
    CPUState *env = cpu_single_env;
    env->regs[R_EBX] = 0x1177;
    return ram_size;
}

static inline uint32_t uuid2reg(const uint8_t *uuid, uint32_t idx)
{
    int i;
    uint32_t reg = 0;

    for (i = 0; i < 4; i++)
        reg |= ((uint32_t)uuid[(idx*4) + i] << (i*8));

    return reg;
}

static uint32_t vmport_cmd_bios_uuid(void *opaque, uint32_t addr)
{
    CPUState *env = cpu_single_env;
    env->regs[R_EBX] = uuid2reg(qemu_uuid, 1);
    env->regs[R_ECX] = uuid2reg(qemu_uuid, 2);
    env->regs[R_EDX] = uuid2reg(qemu_uuid, 3);
    return uuid2reg(qemu_uuid, 0);
}


/* get_freq () function is taken from conky source code */
#define CPUFREQ_PREFIX "/sys/devices/system/cpu"
#define CPUFREQ_POSTFIX "cpufreq/scaling_cur_freq"

/* return system frequency in MHz (use divisor=1) or GHz (use divisor=1000) */
static double get_freq(int divisor, unsigned int cpu)
{
	FILE *f;
	char frequency[32];
	char s[256];
	double freq = 0;

	if (divisor <= 0)
		return 0;

	snprintf(s, 256, "%s/cpu%d/%s", CPUFREQ_PREFIX, cpu - 1,
			CPUFREQ_POSTFIX);
	f = fopen(s, "r");
	if (f) {
		/* if there's a cpufreq /sys node, read the current frequency from
		 * this node and divide by 1000 to get Mhz. */
		if (fgets(s, sizeof(s), f)) {
			s[strlen(s) - 1] = '\0';
			freq = strtod(s, NULL);
		}
		fclose(f);
		return (freq / 1000) / divisor;
	}

	// open the CPU information file
	f = fopen("/proc/cpuinfo", "r");
	if (!f) {
		perror("Failed to access '/proc/cpuinfo' at get_freq()");
		return 0;
	}

	// read the file
	while (fgets(s, sizeof(s), f) != NULL) {

#if defined(__i386) || defined(__x86_64)
		// and search for the cpu mhz
		if (strncmp(s, "cpu MHz", 7) == 0 && cpu == 0) {
#else
#if defined(__alpha)
		// different on alpha
		if (strncmp(s, "cycle frequency [Hz]", 20) == 0 && cpu == 0) {
#else
		// this is different on ppc for some reason
		if (strncmp(s, "clock", 5) == 0 && cpu == 0) {
#endif // defined(__alpha)
#endif // defined(__i386) || defined(__x86_64)

			// copy just the number
			strcpy(frequency, strchr(s, ':') + 2);
#if defined(__alpha)
			// strip " est.\n"
			frequency[strlen(frequency) - 6] = '\0';
			// kernel reports in Hz
			freq = strtod(frequency, NULL) / 1000000;
#else
			// strip \n
			frequency[strlen(frequency) - 1] = '\0';
			freq = strtod(frequency, NULL);
#endif
			break;
		}
		if (strncmp(s, "processor", 9) == 0) {
			cpu--;
			continue;
		}
	}

	fclose(f);
	return freq / divisor;
}

static uint32_t vmport_cmd_get_cpuspeed(void *opaque, uint32_t addr)
{
	return (int)get_freq(1, 1);
}

void vmport_init(void)
{
    register_ioport_read(0x5658, 1, 4, vmport_ioport_read, &port_state);
    register_ioport_write(0x5658, 1, 4, vmport_ioport_write, &port_state);

    /* Register some generic port commands */
    vmport_register(VMPORT_CMD_GETCPUSPEED, vmport_cmd_get_cpuspeed, NULL);
    vmport_register(VMPORT_CMD_GETVERSION, vmport_cmd_get_version, NULL);
    vmport_register(VMPORT_CMD_GETRAMSIZE, vmport_cmd_ram_size, NULL);
    vmport_register(VMPORT_CMD_GETBIOSUUID, vmport_cmd_bios_uuid, NULL);
}
