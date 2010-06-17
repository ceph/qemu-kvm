/*
 * Copyright (c) 2007, Neocleus Corporation.
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
 *
 *
 *  Assign a PCI device from the host to a guest VM.
 *
 *  Adapted for KVM by Qumranet.
 *
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "qemu-kvm.h"
#include "hw.h"
#include "pc.h"
#include "qemu-error.h"
#include "console.h"
#include "device-assignment.h"
#include "loader.h"
#include "monitor.h"
#include <pci/header.h>

/* From linux/ioport.h */
#define IORESOURCE_IO       0x00000100  /* Resource type */
#define IORESOURCE_MEM      0x00000200
#define IORESOURCE_IRQ      0x00000400
#define IORESOURCE_DMA      0x00000800
#define IORESOURCE_PREFETCH 0x00001000  /* No side effects */

/* #define DEVICE_ASSIGNMENT_DEBUG 1 */

#ifdef DEVICE_ASSIGNMENT_DEBUG
#define DEBUG(fmt, ...)                                       \
    do {                                                      \
      fprintf(stderr, "%s: " fmt, __func__ , __VA_ARGS__);    \
    } while (0)
#else
#define DEBUG(fmt, ...) do { } while(0)
#endif

static void assigned_dev_load_option_rom(AssignedDevice *dev);

static void assigned_dev_unregister_msix_mmio(AssignedDevice *dev);

static uint32_t guest_to_host_ioport(AssignedDevRegion *region, uint32_t addr)
{
    return region->u.r_baseport + (addr - region->e_physbase);
}

static void assigned_dev_ioport_writeb(void *opaque, uint32_t addr,
                                       uint32_t value)
{
    AssignedDevRegion *r_access = opaque;
    uint32_t r_pio = guest_to_host_ioport(r_access, addr);

    DEBUG("r_pio=%08x e_physbase=%08x r_baseport=%08lx value=%08x\n",
	  r_pio, (int)r_access->e_physbase,
	  (unsigned long)r_access->u.r_baseport, value);

    outb(value, r_pio);
}

static void assigned_dev_ioport_writew(void *opaque, uint32_t addr,
                                       uint32_t value)
{
    AssignedDevRegion *r_access = opaque;
    uint32_t r_pio = guest_to_host_ioport(r_access, addr);

    DEBUG("r_pio=%08x e_physbase=%08x r_baseport=%08lx value=%08x\n",
          r_pio, (int)r_access->e_physbase,
	  (unsigned long)r_access->u.r_baseport, value);

    outw(value, r_pio);
}

static void assigned_dev_ioport_writel(void *opaque, uint32_t addr,
                       uint32_t value)
{
    AssignedDevRegion *r_access = opaque;
    uint32_t r_pio = guest_to_host_ioport(r_access, addr);

    DEBUG("r_pio=%08x e_physbase=%08x r_baseport=%08lx value=%08x\n",
	  r_pio, (int)r_access->e_physbase,
          (unsigned long)r_access->u.r_baseport, value);

    outl(value, r_pio);
}

static uint32_t assigned_dev_ioport_readb(void *opaque, uint32_t addr)
{
    AssignedDevRegion *r_access = opaque;
    uint32_t r_pio = guest_to_host_ioport(r_access, addr);
    uint32_t value;

    value = inb(r_pio);

    DEBUG("r_pio=%08x e_physbase=%08x r_=%08lx value=%08x\n",
          r_pio, (int)r_access->e_physbase,
          (unsigned long)r_access->u.r_baseport, value);

    return value;
}

static uint32_t assigned_dev_ioport_readw(void *opaque, uint32_t addr)
{
    AssignedDevRegion *r_access = opaque;
    uint32_t r_pio = guest_to_host_ioport(r_access, addr);
    uint32_t value;

    value = inw(r_pio);

    DEBUG("r_pio=%08x e_physbase=%08x r_baseport=%08lx value=%08x\n",
          r_pio, (int)r_access->e_physbase,
	  (unsigned long)r_access->u.r_baseport, value);

    return value;
}

static uint32_t assigned_dev_ioport_readl(void *opaque, uint32_t addr)
{
    AssignedDevRegion *r_access = opaque;
    uint32_t r_pio = guest_to_host_ioport(r_access, addr);
    uint32_t value;

    value = inl(r_pio);

    DEBUG("r_pio=%08x e_physbase=%08x r_baseport=%08lx value=%08x\n",
          r_pio, (int)r_access->e_physbase,
          (unsigned long)r_access->u.r_baseport, value);

    return value;
}

static uint32_t slow_bar_readb(void *opaque, target_phys_addr_t addr)
{
    AssignedDevRegion *d = opaque;
    uint8_t *in = d->u.r_virtbase + addr;
    uint32_t r;

    r = *in;
    DEBUG("slow_bar_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n", addr, r);

    return r;
}

static uint32_t slow_bar_readw(void *opaque, target_phys_addr_t addr)
{
    AssignedDevRegion *d = opaque;
    uint16_t *in = d->u.r_virtbase + addr;
    uint32_t r;

    r = *in;
    DEBUG("slow_bar_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n", addr, r);

    return r;
}

static uint32_t slow_bar_readl(void *opaque, target_phys_addr_t addr)
{
    AssignedDevRegion *d = opaque;
    uint32_t *in = d->u.r_virtbase + addr;
    uint32_t r;

    r = *in;
    DEBUG("slow_bar_readl addr=0x" TARGET_FMT_plx " val=0x%08x\n", addr, r);

    return r;
}

static void slow_bar_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    AssignedDevRegion *d = opaque;
    uint8_t *out = d->u.r_virtbase + addr;

    DEBUG("slow_bar_writeb addr=0x" TARGET_FMT_plx " val=0x%02x\n", addr, val);
    *out = val;
}

static void slow_bar_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    AssignedDevRegion *d = opaque;
    uint16_t *out = d->u.r_virtbase + addr;

    DEBUG("slow_bar_writew addr=0x" TARGET_FMT_plx " val=0x%04x\n", addr, val);
    *out = val;
}

static void slow_bar_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    AssignedDevRegion *d = opaque;
    uint32_t *out = d->u.r_virtbase + addr;

    DEBUG("slow_bar_writel addr=0x" TARGET_FMT_plx " val=0x%08x\n", addr, val);
    *out = val;
}

static CPUWriteMemoryFunc * const slow_bar_write[] = {
    &slow_bar_writeb,
    &slow_bar_writew,
    &slow_bar_writel
};

static CPUReadMemoryFunc * const slow_bar_read[] = {
    &slow_bar_readb,
    &slow_bar_readw,
    &slow_bar_readl
};

static void assigned_dev_iomem_map_slow(PCIDevice *pci_dev, int region_num,
                                        pcibus_t e_phys, pcibus_t e_size,
                                        int type)
{
    AssignedDevice *r_dev = container_of(pci_dev, AssignedDevice, dev);
    AssignedDevRegion *region = &r_dev->v_addrs[region_num];
    PCIRegion *real_region = &r_dev->real_device.regions[region_num];
    int m;

    DEBUG("%s", "slow map\n");
    if (region_num == PCI_ROM_SLOT)
        m = cpu_register_io_memory(slow_bar_read, NULL, region);
    else
        m = cpu_register_io_memory(slow_bar_read, slow_bar_write, region);
    cpu_register_physical_memory(e_phys, e_size, m);

    /* MSI-X MMIO page */
    if ((e_size > 0) &&
        real_region->base_addr <= r_dev->msix_table_addr &&
        real_region->base_addr + real_region->size >= r_dev->msix_table_addr) {
        int offset = r_dev->msix_table_addr - real_region->base_addr;

        cpu_register_physical_memory(e_phys + offset,
                TARGET_PAGE_SIZE, r_dev->mmio_index);
    }
}

static void assigned_dev_iomem_map(PCIDevice *pci_dev, int region_num,
                                   pcibus_t e_phys, pcibus_t e_size, int type)
{
    AssignedDevice *r_dev = container_of(pci_dev, AssignedDevice, dev);
    AssignedDevRegion *region = &r_dev->v_addrs[region_num];
    PCIRegion *real_region = &r_dev->real_device.regions[region_num];
    int ret = 0, flags = 0;

    DEBUG("e_phys=%08" FMT_PCIBUS " r_virt=%p type=%d len=%08" FMT_PCIBUS " region_num=%d \n",
          e_phys, region->u.r_virtbase, type, e_size, region_num);

    region->e_physbase = e_phys;
    region->e_size = e_size;

    if (e_size > 0) {

        if (region_num == PCI_ROM_SLOT)
            flags |= IO_MEM_ROM;

        cpu_register_physical_memory(e_phys, e_size, region->memory_index | flags);

        /* deal with MSI-X MMIO page */
        if (real_region->base_addr <= r_dev->msix_table_addr &&
                real_region->base_addr + real_region->size >=
                r_dev->msix_table_addr) {
            int offset = r_dev->msix_table_addr - real_region->base_addr;

            cpu_register_physical_memory(e_phys + offset,
                    TARGET_PAGE_SIZE, r_dev->mmio_index);
        }
    }

    if (ret != 0) {
	fprintf(stderr, "%s: Error: create new mapping failed\n", __func__);
	exit(1);
    }
}

static void assigned_dev_ioport_map(PCIDevice *pci_dev, int region_num,
                                    pcibus_t addr, pcibus_t size, int type)
{
    AssignedDevice *r_dev = container_of(pci_dev, AssignedDevice, dev);
    AssignedDevRegion *region = &r_dev->v_addrs[region_num];
    int first_map = (region->e_size == 0);
    CPUState *env;

    region->e_physbase = addr;
    region->e_size = size;

    DEBUG("e_phys=0x%" FMT_PCIBUS " r_baseport=%x type=0x%x len=%" FMT_PCIBUS " region_num=%d \n",
          addr, region->u.r_baseport, type, size, region_num);

    if (first_map) {
	struct ioperm_data *data;

	data = qemu_mallocz(sizeof(struct ioperm_data));
	if (data == NULL) {
	    fprintf(stderr, "%s: Out of memory\n", __func__);
	    exit(1);
	}

	data->start_port = region->u.r_baseport;
	data->num = region->r_size;
	data->turn_on = 1;

	kvm_add_ioperm_data(data);

	for (env = first_cpu; env; env = env->next_cpu)
	    kvm_ioperm(env, data);
    }

    register_ioport_read(addr, size, 1, assigned_dev_ioport_readb,
                         (r_dev->v_addrs + region_num));
    register_ioport_read(addr, size, 2, assigned_dev_ioport_readw,
                         (r_dev->v_addrs + region_num));
    register_ioport_read(addr, size, 4, assigned_dev_ioport_readl,
                         (r_dev->v_addrs + region_num));
    register_ioport_write(addr, size, 1, assigned_dev_ioport_writeb,
                          (r_dev->v_addrs + region_num));
    register_ioport_write(addr, size, 2, assigned_dev_ioport_writew,
                          (r_dev->v_addrs + region_num));
    register_ioport_write(addr, size, 4, assigned_dev_ioport_writel,
                          (r_dev->v_addrs + region_num));
}

static uint32_t assigned_dev_pci_read(PCIDevice *d, int pos, int len)
{
    AssignedDevice *pci_dev = container_of(d, AssignedDevice, dev);
    uint32_t val;
    ssize_t ret;
    int fd = pci_dev->real_device.config_fd;

again:
    ret = pread(fd, &val, len, pos);
    if (ret != len) {
	if ((ret < 0) && (errno == EINTR || errno == EAGAIN))
	    goto again;

	fprintf(stderr, "%s: pread failed, ret = %zd errno = %d\n",
		__func__, ret, errno);

	exit(1);
    }

    return val;
}

static uint8_t assigned_dev_pci_read_byte(PCIDevice *d, int pos)
{
    return (uint8_t)assigned_dev_pci_read(d, pos, 1);
}

static uint16_t assigned_dev_pci_read_word(PCIDevice *d, int pos)
{
    return (uint16_t)assigned_dev_pci_read(d, pos, 2);
}

static uint32_t assigned_dev_pci_read_long(PCIDevice *d, int pos)
{
    return assigned_dev_pci_read(d, pos, 4);
}

static uint8_t pci_find_cap_offset(PCIDevice *d, uint8_t cap)
{
    int id;
    int max_cap = 48;
    int pos = PCI_CAPABILITY_LIST;
    int status;

    status = assigned_dev_pci_read_byte(d, PCI_STATUS);
    if ((status & PCI_STATUS_CAP_LIST) == 0)
        return 0;

    while (max_cap--) {
        pos = assigned_dev_pci_read_byte(d, pos);
        if (pos < 0x40)
            break;

        pos &= ~3;
        id = assigned_dev_pci_read_byte(d, pos + PCI_CAP_LIST_ID);

        if (id == 0xff)
            break;
        if (id == cap)
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

static void assigned_dev_pci_write_config(PCIDevice *d, uint32_t address,
                                          uint32_t val, int len)
{
    int fd;
    ssize_t ret;
    AssignedDevice *pci_dev = container_of(d, AssignedDevice, dev);

    DEBUG("(%x.%x): address=%04x val=0x%08x len=%d\n",
          ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
          (uint16_t) address, val, len);

    if (address == 0x4) {
        pci_default_write_config(d, address, val, len);
        /* Continue to program the card */
    }

    if ((address >= 0x10 && address <= 0x24) || address == 0x30 ||
        address == 0x34 || address == 0x3c || address == 0x3d ||
        pci_access_cap_config(d, address, len)) {
        /* used for update-mappings (BAR emulation) */
        pci_default_write_config(d, address, val, len);
        return;
    }

    DEBUG("NON BAR (%x.%x): address=%04x val=0x%08x len=%d\n",
          ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
          (uint16_t) address, val, len);

    fd = pci_dev->real_device.config_fd;

again:
    ret = pwrite(fd, &val, len, address);
    if (ret != len) {
	if ((ret < 0) && (errno == EINTR || errno == EAGAIN))
	    goto again;

	fprintf(stderr, "%s: pwrite failed, ret = %zd errno = %d\n",
		__func__, ret, errno);

	exit(1);
    }
}

static uint32_t assigned_dev_pci_read_config(PCIDevice *d, uint32_t address,
                                             int len)
{
    uint32_t val = 0;
    int fd;
    ssize_t ret;
    AssignedDevice *pci_dev = container_of(d, AssignedDevice, dev);

    if (address < 0x4 || (pci_dev->need_emulate_cmd && address == 0x4) ||
	(address >= 0x10 && address <= 0x24) || address == 0x30 ||
        address == 0x34 || address == 0x3c || address == 0x3d ||
        pci_access_cap_config(d, address, len)) {
        val = pci_default_read_config(d, address, len);
        DEBUG("(%x.%x): address=%04x val=0x%08x len=%d\n",
              (d->devfn >> 3) & 0x1F, (d->devfn & 0x7), address, val, len);
        return val;
    }

    /* vga specific, remove later */
    if (address == 0xFC)
        goto do_log;

    fd = pci_dev->real_device.config_fd;

again:
    ret = pread(fd, &val, len, address);
    if (ret != len) {
	if ((ret < 0) && (errno == EINTR || errno == EAGAIN))
	    goto again;

	fprintf(stderr, "%s: pread failed, ret = %zd errno = %d\n",
		__func__, ret, errno);

	exit(1);
    }

do_log:
    DEBUG("(%x.%x): address=%04x val=0x%08x len=%d\n",
          (d->devfn >> 3) & 0x1F, (d->devfn & 0x7), address, val, len);

    if (!pci_dev->cap.available) {
        /* kill the special capabilities */
        if (address == 4 && len == 4)
            val &= ~0x100000;
        else if (address == 6)
            val &= ~0x10;
    }

    return val;
}

static int assigned_dev_register_regions(PCIRegion *io_regions,
                                         unsigned long regions_num,
                                         AssignedDevice *pci_dev)
{
    uint32_t i;
    PCIRegion *cur_region = io_regions;

    for (i = 0; i < regions_num; i++, cur_region++) {
        if (!cur_region->valid)
            continue;
        pci_dev->v_addrs[i].num = i;

        /* handle memory io regions */
        if (cur_region->type & IORESOURCE_MEM) {
            int slow_map = 0;
            int t = cur_region->type & IORESOURCE_PREFETCH
                ? PCI_BASE_ADDRESS_MEM_PREFETCH
                : PCI_BASE_ADDRESS_SPACE_MEMORY;

            if (cur_region->size & 0xFFF) {
                if (i != PCI_ROM_SLOT) {
                    fprintf(stderr, "PCI region %d at address 0x%llx "
                            "has size 0x%x, which is not a multiple of 4K. "
                            "You might experience some performance hit "
                            "due to that.\n",
                            i, (unsigned long long)cur_region->base_addr,
                            cur_region->size);
                }
                slow_map = 1;
            }

            /* map physical memory */
            pci_dev->v_addrs[i].e_physbase = cur_region->base_addr;
            if (i == PCI_ROM_SLOT) {
                pci_dev->v_addrs[i].u.r_virtbase =
                    mmap(NULL,
                         cur_region->size,
                         PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE,
                         0, (off_t) 0);

            } else {
                pci_dev->v_addrs[i].u.r_virtbase =
                    mmap(NULL,
                         cur_region->size,
                         PROT_WRITE | PROT_READ, MAP_SHARED,
                         cur_region->resource_fd, (off_t) 0);
            }

            if (pci_dev->v_addrs[i].u.r_virtbase == MAP_FAILED) {
                pci_dev->v_addrs[i].u.r_virtbase = NULL;
                fprintf(stderr, "%s: Error: Couldn't mmap 0x%x!"
                        "\n", __func__,
                        (uint32_t) (cur_region->base_addr));
                return -1;
            }

            if (i == PCI_ROM_SLOT) {
                memset(pci_dev->v_addrs[i].u.r_virtbase, 0,
                       (cur_region->size + 0xFFF) & 0xFFFFF000);
                mprotect(pci_dev->v_addrs[PCI_ROM_SLOT].u.r_virtbase,
                         (cur_region->size + 0xFFF) & 0xFFFFF000, PROT_READ);
            }

            pci_dev->v_addrs[i].r_size = cur_region->size;
            pci_dev->v_addrs[i].e_size = 0;

            /* add offset */
            pci_dev->v_addrs[i].u.r_virtbase +=
                (cur_region->base_addr & 0xFFF);


            if (!slow_map) {
                void *virtbase = pci_dev->v_addrs[i].u.r_virtbase;

                pci_dev->v_addrs[i].memory_index = qemu_ram_map(cur_region->size,
                                                                virtbase);
            } else
                pci_dev->v_addrs[i].memory_index = 0;

            pci_register_bar((PCIDevice *) pci_dev, i,
                             cur_region->size, t,
                             slow_map ? assigned_dev_iomem_map_slow
                                      : assigned_dev_iomem_map);
            continue;
        }
        /* handle port io regions */
        pci_dev->v_addrs[i].e_physbase = cur_region->base_addr;
        pci_dev->v_addrs[i].u.r_baseport = cur_region->base_addr;
        pci_dev->v_addrs[i].r_size = cur_region->size;
        pci_dev->v_addrs[i].e_size = 0;

        pci_register_bar((PCIDevice *) pci_dev, i,
                         cur_region->size, PCI_BASE_ADDRESS_SPACE_IO,
                         assigned_dev_ioport_map);

        /* not relevant for port io */
        pci_dev->v_addrs[i].memory_index = 0;
    }

    /* success */
    return 0;
}

static int get_real_id(const char *devpath, const char *idname, uint16_t *val)
{
    FILE *f;
    char name[128];
    long id;

    snprintf(name, sizeof(name), "%s%s", devpath, idname);
    f = fopen(name, "r");
    if (f == NULL) {
        fprintf(stderr, "%s: %s: %m\n", __func__, name);
        return -1;
    }
    if (fscanf(f, "%li\n", &id) == 1) {
        *val = id;
    } else {
        return -1;
    }
    fclose(f);

    return 0;
}

static int get_real_vendor_id(const char *devpath, uint16_t *val)
{
    return get_real_id(devpath, "vendor", val);
}

static int get_real_device_id(const char *devpath, uint16_t *val)
{
    return get_real_id(devpath, "device", val);
}

static int get_real_device(AssignedDevice *pci_dev, uint16_t r_seg,
                           uint8_t r_bus, uint8_t r_dev, uint8_t r_func)
{
    char dir[128], name[128];
    int fd, r = 0, v;
    FILE *f;
    unsigned long long start, end, size, flags;
    uint16_t id;
    struct stat statbuf;
    PCIRegion *rp;
    PCIDevRegions *dev = &pci_dev->real_device;

    dev->region_number = 0;

    snprintf(dir, sizeof(dir), "/sys/bus/pci/devices/%04x:%02x:%02x.%x/",
	     r_seg, r_bus, r_dev, r_func);

    snprintf(name, sizeof(name), "%sconfig", dir);

    if (pci_dev->configfd_name && *pci_dev->configfd_name) {
        if (qemu_isdigit(pci_dev->configfd_name[0])) {
            dev->config_fd = strtol(pci_dev->configfd_name, NULL, 0);
        } else {
            dev->config_fd = monitor_get_fd(cur_mon, pci_dev->configfd_name);
            if (dev->config_fd < 0) {
                fprintf(stderr, "%s: (%s) unkown\n", __func__,
                        pci_dev->configfd_name);
                return 1;
            }
        }
    } else {
        dev->config_fd = open(name, O_RDWR);

        if (dev->config_fd == -1) {
            fprintf(stderr, "%s: %s: %m\n", __func__, name);
            return 1;
        }
    }
again:
    r = read(dev->config_fd, pci_dev->dev.config,
             pci_config_size(&pci_dev->dev));
    if (r < 0) {
        if (errno == EINTR || errno == EAGAIN)
            goto again;
        fprintf(stderr, "%s: read failed, errno = %d\n", __func__, errno);
    }

    snprintf(name, sizeof(name), "%sresource", dir);

    f = fopen(name, "r");
    if (f == NULL) {
        fprintf(stderr, "%s: %s: %m\n", __func__, name);
        return 1;
    }

    for (r = 0; r < PCI_NUM_REGIONS; r++) {
	if (fscanf(f, "%lli %lli %lli\n", &start, &end, &flags) != 3)
	    break;

        rp = dev->regions + r;
        rp->valid = 0;
        size = end - start + 1;
        flags &= IORESOURCE_IO | IORESOURCE_MEM | IORESOURCE_PREFETCH;
        if (size == 0 || (flags & ~IORESOURCE_PREFETCH) == 0)
            continue;
        if (flags & IORESOURCE_MEM) {
            flags &= ~IORESOURCE_IO;
            if (r != PCI_ROM_SLOT) {
                snprintf(name, sizeof(name), "%sresource%d", dir, r);
                fd = open(name, O_RDWR);
                if (fd == -1)
                    continue;
                rp->resource_fd = fd;
            }
        } else
            flags &= ~IORESOURCE_PREFETCH;

        rp->type = flags;
        rp->valid = 1;
        rp->base_addr = start;
        rp->size = size;
        DEBUG("region %d size %d start 0x%llx type %d resource_fd %d\n",
              r, rp->size, start, rp->type, rp->resource_fd);
    }

    fclose(f);

    /* read and fill vendor ID */
    v = get_real_vendor_id(dir, &id);
    if (v) {
        return 1;
    }
    pci_dev->dev.config[0] = id & 0xff;
    pci_dev->dev.config[1] = (id & 0xff00) >> 8;

    /* read and fill device ID */
    v = get_real_device_id(dir, &id);
    if (v) {
        return 1;
    }
    pci_dev->dev.config[2] = id & 0xff;
    pci_dev->dev.config[3] = (id & 0xff00) >> 8;

    /* dealing with virtual function device */
    snprintf(name, sizeof(name), "%sphysfn/", dir);
    if (!stat(name, &statbuf))
	    pci_dev->need_emulate_cmd = 1;
    else
	    pci_dev->need_emulate_cmd = 0;

    dev->region_number = r;
    return 0;
}

static QLIST_HEAD(, AssignedDevice) devs = QLIST_HEAD_INITIALIZER(devs);

#ifdef KVM_CAP_IRQ_ROUTING
static void free_dev_irq_entries(AssignedDevice *dev)
{
    int i;

    for (i = 0; i < dev->irq_entries_nr; i++)
        kvm_del_routing_entry(kvm_context, &dev->entry[i]);
    free(dev->entry);
    dev->entry = NULL;
    dev->irq_entries_nr = 0;
}
#endif

static void free_assigned_device(AssignedDevice *dev)
{
    if (dev) {
        int i;

        for (i = 0; i < dev->real_device.region_number; i++) {
            PCIRegion *pci_region = &dev->real_device.regions[i];
            AssignedDevRegion *region = &dev->v_addrs[i];

            if (!pci_region->valid)
                continue;

            if (pci_region->type & IORESOURCE_IO) {
                kvm_remove_ioperm_data(region->u.r_baseport, region->r_size);
                continue;
            } else if (pci_region->type & IORESOURCE_MEM) {
                if (region->u.r_virtbase) {
                    int ret = munmap(region->u.r_virtbase,
                                     (pci_region->size + 0xFFF) & 0xFFFFF000);
                    if (ret != 0)
                        fprintf(stderr,
				"Failed to unmap assigned device region: %s\n",
				strerror(errno));
                    close(pci_region->resource_fd);
                }
	    }
        }

        if (dev->cap.available & ASSIGNED_DEVICE_CAP_MSIX)
            assigned_dev_unregister_msix_mmio(dev);

        if (dev->real_device.config_fd) {
            close(dev->real_device.config_fd);
            dev->real_device.config_fd = 0;
        }

#ifdef KVM_CAP_IRQ_ROUTING
        free_dev_irq_entries(dev);
#endif
    }
}

static uint32_t calc_assigned_dev_id(uint16_t seg, uint8_t bus, uint8_t devfn)
{
    return (uint32_t)seg << 16 | (uint32_t)bus << 8 | (uint32_t)devfn;
}

static void assign_failed_examine(AssignedDevice *dev)
{
    char name[PATH_MAX], dir[PATH_MAX], driver[PATH_MAX] = {}, *ns;
    uint16_t vendor_id, device_id;
    int r;

    sprintf(dir, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
            dev->host.seg, dev->host.bus, dev->host.dev, dev->host.func);

    sprintf(name, "%sdriver", dir);

    r = readlink(name, driver, sizeof(driver));
    if ((r <= 0) || r >= sizeof(driver) || !(ns = strrchr(driver, '/'))) {
        goto fail;
    }

    ns++;

    if (get_real_vendor_id(dir, &vendor_id) ||
        get_real_device_id(dir, &device_id)) {
        goto fail;
    }

    fprintf(stderr, "*** The driver '%s' is occupying your device "
                    "%04x:%02x:%02x.%x.\n",
            ns, dev->host.seg, dev->host.bus, dev->host.dev, dev->host.func);
    fprintf(stderr, "***\n");
    fprintf(stderr, "*** You can try the following commands to free it:\n");
    fprintf(stderr, "***\n");
    fprintf(stderr, "*** $ echo \"%04x %04x\" > /sys/bus/pci/drivers/pci-stub/"
                    "new_id\n", vendor_id, device_id);
    fprintf(stderr, "*** $ echo \"%04x:%02x:%02x.%x\" > /sys/bus/pci/drivers/"
                    "%s/unbind\n",
            dev->host.seg, dev->host.bus, dev->host.dev, dev->host.func, ns);
    fprintf(stderr, "*** $ echo \"%04x:%02x:%02x.%x\" > /sys/bus/pci/drivers/"
                    "pci-stub/bind\n",
            dev->host.seg, dev->host.bus, dev->host.dev, dev->host.func);
    fprintf(stderr, "*** $ echo \"%04x %04x\" > /sys/bus/pci/drivers/pci-stub"
                    "/remove_id\n", vendor_id, device_id);
    fprintf(stderr, "***\n");

    return;

fail:
    fprintf(stderr, "Couldn't find out why.\n");
}

static int assign_device(AssignedDevice *dev)
{
    struct kvm_assigned_pci_dev assigned_dev_data;
    int r;

#ifdef KVM_CAP_PCI_SEGMENT
    /* Only pass non-zero PCI segment to capable module */
    if (!kvm_check_extension(kvm_state, KVM_CAP_PCI_SEGMENT) &&
        dev->h_segnr) {
        fprintf(stderr, "Can't assign device inside non-zero PCI segment "
                "as this KVM module doesn't support it.\n");
        return -ENODEV;
    }
#endif

    memset(&assigned_dev_data, 0, sizeof(assigned_dev_data));
    assigned_dev_data.assigned_dev_id  =
	calc_assigned_dev_id(dev->h_segnr, dev->h_busnr, dev->h_devfn);
#ifdef KVM_CAP_PCI_SEGMENT
    assigned_dev_data.segnr = dev->h_segnr;
#endif
    assigned_dev_data.busnr = dev->h_busnr;
    assigned_dev_data.devfn = dev->h_devfn;

#ifdef KVM_CAP_IOMMU
    /* We always enable the IOMMU unless disabled on the command line */
    if (dev->use_iommu) {
        if (!kvm_check_extension(kvm_state, KVM_CAP_IOMMU)) {
            fprintf(stderr, "No IOMMU found.  Unable to assign device \"%s\"\n",
                    dev->dev.qdev.id);
            return -ENODEV;
        }
        assigned_dev_data.flags |= KVM_DEV_ASSIGN_ENABLE_IOMMU;
    }
#else
    dev->use_iommu = 0;
#endif

    r = kvm_assign_pci_device(kvm_context, &assigned_dev_data);
    if (r < 0) {
        fprintf(stderr, "Failed to assign device \"%s\" : %s\n",
                dev->dev.qdev.id, strerror(-r));

        switch (r) {
            case -EBUSY:
                assign_failed_examine(dev);
                break;
            default:
                break;
        }
    }
    return r;
}

static int assign_irq(AssignedDevice *dev)
{
    struct kvm_assigned_irq assigned_irq_data;
    int irq, r = 0;

    /* Interrupt PIN 0 means don't use INTx */
    if (assigned_dev_pci_read_byte(&dev->dev, PCI_INTERRUPT_PIN) == 0)
        return 0;

    irq = pci_map_irq(&dev->dev, dev->intpin);
    irq = piix_get_irq(irq);

#ifdef TARGET_IA64
    irq = ipf_map_irq(&dev->dev, irq);
#endif

    if (dev->girq == irq)
        return r;

    memset(&assigned_irq_data, 0, sizeof(assigned_irq_data));
    assigned_irq_data.assigned_dev_id =
        calc_assigned_dev_id(dev->h_segnr, dev->h_busnr, dev->h_devfn);
    assigned_irq_data.guest_irq = irq;
    assigned_irq_data.host_irq = dev->real_device.irq;
#ifdef KVM_CAP_ASSIGN_DEV_IRQ
    if (dev->irq_requested_type) {
        assigned_irq_data.flags = dev->irq_requested_type;
        r = kvm_deassign_irq(kvm_context, &assigned_irq_data);
        /* -ENXIO means no assigned irq */
        if (r && r != -ENXIO)
            perror("assign_irq: deassign");
    }

    assigned_irq_data.flags = KVM_DEV_IRQ_GUEST_INTX;
    if (dev->cap.available & ASSIGNED_DEVICE_CAP_MSI)
        assigned_irq_data.flags |= KVM_DEV_IRQ_HOST_MSI;
    else
        assigned_irq_data.flags |= KVM_DEV_IRQ_HOST_INTX;
#endif

    r = kvm_assign_irq(kvm_context, &assigned_irq_data);
    if (r < 0) {
        fprintf(stderr, "Failed to assign irq for \"%s\": %s\n",
                dev->dev.qdev.id, strerror(-r));
        fprintf(stderr, "Perhaps you are assigning a device "
                "that shares an IRQ with another device?\n");
        return r;
    }

    dev->girq = irq;
    dev->irq_requested_type = assigned_irq_data.flags;
    return r;
}

static void deassign_device(AssignedDevice *dev)
{
#ifdef KVM_CAP_DEVICE_DEASSIGNMENT
    struct kvm_assigned_pci_dev assigned_dev_data;
    int r;

    memset(&assigned_dev_data, 0, sizeof(assigned_dev_data));
    assigned_dev_data.assigned_dev_id  =
	calc_assigned_dev_id(dev->h_segnr, dev->h_busnr, dev->h_devfn);

    r = kvm_deassign_pci_device(kvm_context, &assigned_dev_data);
    if (r < 0)
	fprintf(stderr, "Failed to deassign device \"%s\" : %s\n",
                dev->dev.qdev.id, strerror(-r));
#endif
}

#if 0
AssignedDevInfo *get_assigned_device(int pcibus, int slot)
{
    AssignedDevice *assigned_dev = NULL;
    AssignedDevInfo *adev = NULL;

    QLIST_FOREACH(adev, &adev_head, next) {
        assigned_dev = adev->assigned_dev;
        if (pci_bus_num(assigned_dev->dev.bus) == pcibus &&
            PCI_SLOT(assigned_dev->dev.devfn) == slot)
            return adev;
    }

    return NULL;
}
#endif

/* The pci config space got updated. Check if irq numbers have changed
 * for our devices
 */
void assigned_dev_update_irqs(void)
{
    AssignedDevice *dev, *next;
    int r;

    dev = QLIST_FIRST(&devs);
    while (dev) {
        next = QLIST_NEXT(dev, next);
        r = assign_irq(dev);
        if (r < 0)
            qdev_unplug(&dev->dev.qdev);
        dev = next;
    }
}

#ifdef KVM_CAP_IRQ_ROUTING

#ifdef KVM_CAP_DEVICE_MSI
static void assigned_dev_update_msi(PCIDevice *pci_dev, unsigned int ctrl_pos)
{
    struct kvm_assigned_irq assigned_irq_data;
    AssignedDevice *assigned_dev = container_of(pci_dev, AssignedDevice, dev);
    uint8_t ctrl_byte = pci_dev->config[ctrl_pos];
    int r;

    memset(&assigned_irq_data, 0, sizeof assigned_irq_data);
    assigned_irq_data.assigned_dev_id  =
        calc_assigned_dev_id(assigned_dev->h_segnr, assigned_dev->h_busnr,
                (uint8_t)assigned_dev->h_devfn);

    /* Some guests gratuitously disable MSI even if they're not using it,
     * try to catch this by only deassigning irqs if the guest is using
     * MSI or intends to start. */
    if ((assigned_dev->irq_requested_type & KVM_DEV_IRQ_GUEST_MSI) ||
        (ctrl_byte & PCI_MSI_FLAGS_ENABLE)) {

        assigned_irq_data.flags = assigned_dev->irq_requested_type;
        free_dev_irq_entries(assigned_dev);
        r = kvm_deassign_irq(kvm_context, &assigned_irq_data);
        /* -ENXIO means no assigned irq */
        if (r && r != -ENXIO)
            perror("assigned_dev_update_msi: deassign irq");

        assigned_irq_data.flags = 0;
    }

    if (ctrl_byte & PCI_MSI_FLAGS_ENABLE) {
        assigned_dev->entry = calloc(1, sizeof(struct kvm_irq_routing_entry));
        if (!assigned_dev->entry) {
            perror("assigned_dev_update_msi: ");
            return;
        }
        assigned_dev->entry->u.msi.address_lo =
                *(uint32_t *)(pci_dev->config + pci_dev->cap.start +
                              PCI_MSI_ADDRESS_LO);
        assigned_dev->entry->u.msi.address_hi = 0;
        assigned_dev->entry->u.msi.data = *(uint16_t *)(pci_dev->config +
                pci_dev->cap.start + PCI_MSI_DATA_32);
        assigned_dev->entry->type = KVM_IRQ_ROUTING_MSI;
        r = kvm_get_irq_route_gsi(kvm_context);
        if (r < 0) {
            perror("assigned_dev_update_msi: kvm_get_irq_route_gsi");
            return;
        }
        assigned_dev->entry->gsi = r;

        kvm_add_routing_entry(kvm_context, assigned_dev->entry);
        if (kvm_commit_irq_routes(kvm_context) < 0) {
            perror("assigned_dev_update_msi: kvm_commit_irq_routes");
            assigned_dev->cap.state &= ~ASSIGNED_DEVICE_MSI_ENABLED;
            return;
        }
	assigned_dev->irq_entries_nr = 1;

        assigned_irq_data.guest_irq = assigned_dev->entry->gsi;
	assigned_irq_data.flags = KVM_DEV_IRQ_HOST_MSI | KVM_DEV_IRQ_GUEST_MSI;
        if (kvm_assign_irq(kvm_context, &assigned_irq_data) < 0)
            perror("assigned_dev_enable_msi: assign irq");

        assigned_dev->irq_requested_type = assigned_irq_data.flags;
    }
}
#endif

#ifdef KVM_CAP_DEVICE_MSIX
static int assigned_dev_update_msix_mmio(PCIDevice *pci_dev)
{
    AssignedDevice *adev = container_of(pci_dev, AssignedDevice, dev);
    uint16_t entries_nr = 0, entries_max_nr;
    int pos = 0, i, r = 0;
    uint32_t msg_addr, msg_upper_addr, msg_data, msg_ctrl;
    struct kvm_assigned_msix_nr msix_nr;
    struct kvm_assigned_msix_entry msix_entry;
    void *va = adev->msix_table_page;

    if (adev->cap.available & ASSIGNED_DEVICE_CAP_MSI)
        pos = pci_dev->cap.start + PCI_CAPABILITY_CONFIG_MSI_LENGTH;
    else
        pos = pci_dev->cap.start;

    entries_max_nr = *(uint16_t *)(pci_dev->config + pos + 2);
    entries_max_nr &= PCI_MSIX_TABSIZE;
    entries_max_nr += 1;

    /* Get the usable entry number for allocating */
    for (i = 0; i < entries_max_nr; i++) {
        memcpy(&msg_ctrl, va + i * 16 + 12, 4);
        memcpy(&msg_data, va + i * 16 + 8, 4);
        /* Ignore unused entry even it's unmasked */
        if (msg_data == 0)
            continue;
        entries_nr ++;
    }

    if (entries_nr == 0) {
        fprintf(stderr, "MSI-X entry number is zero!\n");
        return -EINVAL;
    }
    msix_nr.assigned_dev_id = calc_assigned_dev_id(adev->h_segnr, adev->h_busnr,
                                          (uint8_t)adev->h_devfn);
    msix_nr.entry_nr = entries_nr;
    r = kvm_assign_set_msix_nr(kvm_context, &msix_nr);
    if (r != 0) {
        fprintf(stderr, "fail to set MSI-X entry number for MSIX! %s\n",
			strerror(-r));
        return r;
    }

    free_dev_irq_entries(adev);
    adev->irq_entries_nr = entries_nr;
    adev->entry = calloc(entries_nr, sizeof(struct kvm_irq_routing_entry));
    if (!adev->entry) {
        perror("assigned_dev_update_msix_mmio: ");
        return -errno;
    }

    msix_entry.assigned_dev_id = msix_nr.assigned_dev_id;
    entries_nr = 0;
    for (i = 0; i < entries_max_nr; i++) {
        if (entries_nr >= msix_nr.entry_nr)
            break;
        memcpy(&msg_ctrl, va + i * 16 + 12, 4);
        memcpy(&msg_data, va + i * 16 + 8, 4);
        if (msg_data == 0)
            continue;

        memcpy(&msg_addr, va + i * 16, 4);
        memcpy(&msg_upper_addr, va + i * 16 + 4, 4);

        r = kvm_get_irq_route_gsi(kvm_context);
        if (r < 0)
            return r;

        adev->entry[entries_nr].gsi = r;
        adev->entry[entries_nr].type = KVM_IRQ_ROUTING_MSI;
        adev->entry[entries_nr].flags = 0;
        adev->entry[entries_nr].u.msi.address_lo = msg_addr;
        adev->entry[entries_nr].u.msi.address_hi = msg_upper_addr;
        adev->entry[entries_nr].u.msi.data = msg_data;
        DEBUG("MSI-X data 0x%x, MSI-X addr_lo 0x%x\n!", msg_data, msg_addr);
	kvm_add_routing_entry(kvm_context, &adev->entry[entries_nr]);

        msix_entry.gsi = adev->entry[entries_nr].gsi;
        msix_entry.entry = i;
        r = kvm_assign_set_msix_entry(kvm_context, &msix_entry);
        if (r) {
            fprintf(stderr, "fail to set MSI-X entry! %s\n", strerror(-r));
            break;
        }
        DEBUG("MSI-X entry gsi 0x%x, entry %d\n!",
                msix_entry.gsi, msix_entry.entry);
        entries_nr ++;
    }

    if (r == 0 && kvm_commit_irq_routes(kvm_context) < 0) {
	    perror("assigned_dev_update_msix_mmio: kvm_commit_irq_routes");
	    return -EINVAL;
    }

    return r;
}

static void assigned_dev_update_msix(PCIDevice *pci_dev, unsigned int ctrl_pos)
{
    struct kvm_assigned_irq assigned_irq_data;
    AssignedDevice *assigned_dev = container_of(pci_dev, AssignedDevice, dev);
    uint16_t *ctrl_word = (uint16_t *)(pci_dev->config + ctrl_pos);
    int r;

    memset(&assigned_irq_data, 0, sizeof assigned_irq_data);
    assigned_irq_data.assigned_dev_id  =
            calc_assigned_dev_id(assigned_dev->h_segnr, assigned_dev->h_busnr,
                    (uint8_t)assigned_dev->h_devfn);

    /* Some guests gratuitously disable MSIX even if they're not using it,
     * try to catch this by only deassigning irqs if the guest is using
     * MSIX or intends to start. */
    if ((assigned_dev->irq_requested_type & KVM_DEV_IRQ_GUEST_MSIX) ||
        (*ctrl_word & PCI_MSIX_ENABLE)) {

        assigned_irq_data.flags = assigned_dev->irq_requested_type;
        free_dev_irq_entries(assigned_dev);
        r = kvm_deassign_irq(kvm_context, &assigned_irq_data);
        /* -ENXIO means no assigned irq */
        if (r && r != -ENXIO)
            perror("assigned_dev_update_msix: deassign irq");

        assigned_irq_data.flags = 0;
    }

    if (*ctrl_word & PCI_MSIX_ENABLE) {
        assigned_irq_data.flags = KVM_DEV_IRQ_HOST_MSIX |
                                  KVM_DEV_IRQ_GUEST_MSIX;

        if (assigned_dev_update_msix_mmio(pci_dev) < 0) {
            perror("assigned_dev_update_msix_mmio");
            return;
        }
        if (kvm_assign_irq(kvm_context, &assigned_irq_data) < 0) {
            perror("assigned_dev_enable_msix: assign irq");
            return;
        }
        assigned_dev->irq_requested_type = assigned_irq_data.flags;
    }
}
#endif
#endif

static void assigned_device_pci_cap_write_config(PCIDevice *pci_dev, uint32_t address,
                                                 uint32_t val, int len)
{
    AssignedDevice *assigned_dev = container_of(pci_dev, AssignedDevice, dev);
    unsigned int pos = pci_dev->cap.start, ctrl_pos;

    pci_default_cap_write_config(pci_dev, address, val, len);
#ifdef KVM_CAP_IRQ_ROUTING
#ifdef KVM_CAP_DEVICE_MSI
    if (assigned_dev->cap.available & ASSIGNED_DEVICE_CAP_MSI) {
        ctrl_pos = pos + PCI_MSI_FLAGS;
        if (address <= ctrl_pos && address + len > ctrl_pos)
            assigned_dev_update_msi(pci_dev, ctrl_pos);
        pos += PCI_CAPABILITY_CONFIG_MSI_LENGTH;
    }
#endif
#ifdef KVM_CAP_DEVICE_MSIX
    if (assigned_dev->cap.available & ASSIGNED_DEVICE_CAP_MSIX) {
        ctrl_pos = pos + 3;
        if (address <= ctrl_pos && address + len > ctrl_pos) {
            ctrl_pos--; /* control is word long */
            assigned_dev_update_msix(pci_dev, ctrl_pos);
	}
        pos += PCI_CAPABILITY_CONFIG_MSIX_LENGTH;
    }
#endif
#endif
    return;
}

static int assigned_device_pci_cap_init(PCIDevice *pci_dev)
{
    AssignedDevice *dev = container_of(pci_dev, AssignedDevice, dev);
    PCIRegion *pci_region = dev->real_device.regions;
    int next_cap_pt = 0;

    pci_dev->cap.length = 0;
#ifdef KVM_CAP_IRQ_ROUTING
#ifdef KVM_CAP_DEVICE_MSI
    /* Expose MSI capability
     * MSI capability is the 1st capability in capability config */
    if (pci_find_cap_offset(pci_dev, PCI_CAP_ID_MSI)) {
        dev->cap.available |= ASSIGNED_DEVICE_CAP_MSI;
        memset(&pci_dev->config[pci_dev->cap.start + pci_dev->cap.length],
               0, PCI_CAPABILITY_CONFIG_MSI_LENGTH);
        pci_dev->config[pci_dev->cap.start + pci_dev->cap.length] =
                        PCI_CAP_ID_MSI;
        pci_dev->cap.length += PCI_CAPABILITY_CONFIG_MSI_LENGTH;
        next_cap_pt = 1;
    }
#endif
#ifdef KVM_CAP_DEVICE_MSIX
    /* Expose MSI-X capability */
    if (pci_find_cap_offset(pci_dev, PCI_CAP_ID_MSIX)) {
        int pos, entry_nr, bar_nr;
        uint32_t msix_table_entry;
        dev->cap.available |= ASSIGNED_DEVICE_CAP_MSIX;
        memset(&pci_dev->config[pci_dev->cap.start + pci_dev->cap.length],
               0, PCI_CAPABILITY_CONFIG_MSIX_LENGTH);
        pos = pci_find_cap_offset(pci_dev, PCI_CAP_ID_MSIX);
        entry_nr = assigned_dev_pci_read_word(pci_dev, pos + 2) &
                                                             PCI_MSIX_TABSIZE;
        pci_dev->config[pci_dev->cap.start + pci_dev->cap.length] = 0x11;
        *(uint16_t *)(pci_dev->config + pci_dev->cap.start +
                      pci_dev->cap.length + 2) = entry_nr;
        msix_table_entry = assigned_dev_pci_read_long(pci_dev,
                                                      pos + PCI_MSIX_TABLE);
        *(uint32_t *)(pci_dev->config + pci_dev->cap.start +
                      pci_dev->cap.length + PCI_MSIX_TABLE) = msix_table_entry;
        *(uint32_t *)(pci_dev->config + pci_dev->cap.start +
                      pci_dev->cap.length + PCI_MSIX_PBA) =
                    assigned_dev_pci_read_long(pci_dev, pos + PCI_MSIX_PBA);
        bar_nr = msix_table_entry & PCI_MSIX_BIR;
        msix_table_entry &= ~PCI_MSIX_BIR;
        dev->msix_table_addr = pci_region[bar_nr].base_addr + msix_table_entry;
        if (next_cap_pt != 0) {
            pci_dev->config[pci_dev->cap.start + next_cap_pt] =
                pci_dev->cap.start + pci_dev->cap.length;
            next_cap_pt += PCI_CAPABILITY_CONFIG_MSI_LENGTH;
        } else
            next_cap_pt = 1;
        pci_dev->cap.length += PCI_CAPABILITY_CONFIG_MSIX_LENGTH;
    }
#endif
#endif

    return 0;
}

static uint32_t msix_mmio_readl(void *opaque, target_phys_addr_t addr)
{
    AssignedDevice *adev = opaque;
    unsigned int offset = addr & 0xfff;
    void *page = adev->msix_table_page;
    uint32_t val = 0;

    memcpy(&val, (void *)((char *)page + offset), 4);

    return val;
}

static uint32_t msix_mmio_readb(void *opaque, target_phys_addr_t addr)
{
    return ((msix_mmio_readl(opaque, addr & ~3)) >>
            (8 * (addr & 3))) & 0xff;
}

static uint32_t msix_mmio_readw(void *opaque, target_phys_addr_t addr)
{
    return ((msix_mmio_readl(opaque, addr & ~3)) >>
            (8 * (addr & 3))) & 0xffff;
}

static void msix_mmio_writel(void *opaque,
                             target_phys_addr_t addr, uint32_t val)
{
    AssignedDevice *adev = opaque;
    unsigned int offset = addr & 0xfff;
    void *page = adev->msix_table_page;

    DEBUG("write to MSI-X entry table mmio offset 0x%lx, val 0x%x\n",
		    addr, val);
    memcpy((void *)((char *)page + offset), &val, 4);
}

static void msix_mmio_writew(void *opaque,
                             target_phys_addr_t addr, uint32_t val)
{
    msix_mmio_writel(opaque, addr & ~3,
                     (val & 0xffff) << (8*(addr & 3)));
}

static void msix_mmio_writeb(void *opaque,
                             target_phys_addr_t addr, uint32_t val)
{
    msix_mmio_writel(opaque, addr & ~3,
                     (val & 0xff) << (8*(addr & 3)));
}

static CPUWriteMemoryFunc *msix_mmio_write[] = {
    msix_mmio_writeb,	msix_mmio_writew,	msix_mmio_writel
};

static CPUReadMemoryFunc *msix_mmio_read[] = {
    msix_mmio_readb,	msix_mmio_readw,	msix_mmio_readl
};

static int assigned_dev_register_msix_mmio(AssignedDevice *dev)
{
    dev->msix_table_page = mmap(NULL, 0x1000,
                                PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    if (dev->msix_table_page == MAP_FAILED) {
        fprintf(stderr, "fail allocate msix_table_page! %s\n",
                strerror(errno));
        return -EFAULT;
    }
    memset(dev->msix_table_page, 0, 0x1000);
    dev->mmio_index = cpu_register_io_memory(
                        msix_mmio_read, msix_mmio_write, dev);
    return 0;
}

static void assigned_dev_unregister_msix_mmio(AssignedDevice *dev)
{
    if (!dev->msix_table_page)
        return;

    cpu_unregister_io_memory(dev->mmio_index);
    dev->mmio_index = 0;

    if (munmap(dev->msix_table_page, 0x1000) == -1) {
        fprintf(stderr, "error unmapping msix_table_page! %s\n",
                strerror(errno));
    }
    dev->msix_table_page = NULL;
}

static int assigned_initfn(struct PCIDevice *pci_dev)
{
    AssignedDevice *dev = DO_UPCAST(AssignedDevice, dev, pci_dev);
    uint8_t e_device, e_intx;
    int r;

    if (!dev->host.seg && !dev->host.bus && !dev->host.dev && !dev->host.func) {
        error_report("pci-assign: error: no host device specified");
        goto out;
    }

    if (get_real_device(dev, dev->host.seg, dev->host.bus,
                        dev->host.dev, dev->host.func)) {
        error_report("pci-assign: Error: Couldn't get real device (%s)!",
                     dev->dev.qdev.id);
        goto out;
    }

    /* handle real device's MMIO/PIO BARs */
    if (assigned_dev_register_regions(dev->real_device.regions,
                                      dev->real_device.region_number,
                                      dev))
        goto out;

    /* handle interrupt routing */
    e_device = (dev->dev.devfn >> 3) & 0x1f;
    e_intx = dev->dev.config[0x3d] - 1;
    dev->intpin = e_intx;
    dev->run = 0;
    dev->girq = -1;
    dev->h_segnr = dev->host.seg;
    dev->h_busnr = dev->host.bus;
    dev->h_devfn = PCI_DEVFN(dev->host.dev, dev->host.func);

    if (pci_enable_capability_support(pci_dev, 0, NULL,
                    assigned_device_pci_cap_write_config,
                    assigned_device_pci_cap_init) < 0)
        goto out;

    /* assign device to guest */
    r = assign_device(dev);
    if (r < 0)
        goto out;

    /* assign irq for the device */
    r = assign_irq(dev);
    if (r < 0)
        goto assigned_out;

    /* intercept MSI-X entry page in the MMIO */
    if (dev->cap.available & ASSIGNED_DEVICE_CAP_MSIX)
        if (assigned_dev_register_msix_mmio(dev))
            goto assigned_out;

    assigned_dev_load_option_rom(dev);
    QLIST_INSERT_HEAD(&devs, dev, next);
    return 0;

assigned_out:
    deassign_device(dev);
out:
    free_assigned_device(dev);
    return -1;
}

static int assigned_exitfn(struct PCIDevice *pci_dev)
{
    AssignedDevice *dev = DO_UPCAST(AssignedDevice, dev, pci_dev);

    QLIST_REMOVE(dev, next);
    deassign_device(dev);
    free_assigned_device(dev);
    return 0;
}

static int parse_hostaddr(DeviceState *dev, Property *prop, const char *str)
{
    PCIHostDevice *ptr = qdev_get_prop_ptr(dev, prop);
    int rc;

    rc = pci_parse_host_devaddr(str, &ptr->seg, &ptr->bus, &ptr->dev, &ptr->func);
    if (rc != 0)
        return -1;
    return 0;
}

static int print_hostaddr(DeviceState *dev, Property *prop, char *dest, size_t len)
{
    PCIHostDevice *ptr = qdev_get_prop_ptr(dev, prop);

    return snprintf(dest, len, "%02x:%02x.%x", ptr->bus, ptr->dev, ptr->func);
}

PropertyInfo qdev_prop_hostaddr = {
    .name  = "pci-hostaddr",
    .type  = -1,
    .size  = sizeof(PCIHostDevice),
    .parse = parse_hostaddr,
    .print = print_hostaddr,
};

static PCIDeviceInfo assign_info = {
    .qdev.name    = "pci-assign",
    .qdev.desc    = "pass through host pci devices to the guest",
    .qdev.size    = sizeof(AssignedDevice),
    .init         = assigned_initfn,
    .exit         = assigned_exitfn,
    .config_read  = assigned_dev_pci_read_config,
    .config_write = assigned_dev_pci_write_config,
    .qdev.props   = (Property[]) {
        DEFINE_PROP("host", AssignedDevice, host, qdev_prop_hostaddr, PCIHostDevice),
        DEFINE_PROP_UINT32("iommu", AssignedDevice, use_iommu, 1),
        DEFINE_PROP_STRING("configfd", AssignedDevice, configfd_name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void assign_register_devices(void)
{
    pci_qdev_register(&assign_info);
}

device_init(assign_register_devices)


/*
 * Syntax to assign device:
 *
 * -pcidevice host=bus:dev.func[,dma=none][,name=Foo]
 *
 * Example:
 * -pcidevice host=00:13.0,dma=pvdma
 *
 * dma can currently only be 'none' to disable iommu support.
 */
QemuOpts *add_assigned_device(const char *arg)
{
    QemuOpts *opts = NULL;
    char host[64], id[64], dma[8];
    int r;

    r = get_param_value(host, sizeof(host), "host", arg);
    if (!r)
         goto bad;
    r = get_param_value(id, sizeof(id), "id", arg);
    if (!r)
        r = get_param_value(id, sizeof(id), "name", arg);
    if (!r)
        r = get_param_value(id, sizeof(id), "host", arg);

    opts = qemu_opts_create(&qemu_device_opts, id, 0);
    if (!opts)
        goto bad;
    qemu_opt_set(opts, "driver", "pci-assign");
    qemu_opt_set(opts, "host", host);

#ifdef KVM_CAP_IOMMU
    r = get_param_value(dma, sizeof(dma), "dma", arg);
    if (r && !strncmp(dma, "none", 4))
        qemu_opt_set(opts, "iommu", "0");
#endif
    qemu_opts_print(opts, NULL);
    return opts;

bad:
    fprintf(stderr, "pcidevice argument parse error; "
            "please check the help text for usage\n");
    if (opts)
        qemu_opts_del(opts);
    return NULL;
}

void add_assigned_devices(PCIBus *bus, const char **devices, int n_devices)
{
    QemuOpts *opts;
    int i;

    for (i = 0; i < n_devices; i++) {
        opts = add_assigned_device(devices[i]);
        if (opts == NULL) {
            fprintf(stderr, "Could not add assigned device %s\n", devices[i]);
            exit(1);
        }
        /* generic code will call qdev_device_add() for the device */
    }
}

/*
 * Scan the assigned devices for the devices that have an option ROM, and then
 * load the corresponding ROM data to RAM. If an error occurs while loading an
 * option ROM, we just ignore that option ROM and continue with the next one.
 */
static void assigned_dev_load_option_rom(AssignedDevice *dev)
{
    int size, len, ret;
    void *buf;
    FILE *fp;
    uint8_t i = 1;
    char rom_file[64];

    snprintf(rom_file, sizeof(rom_file),
             "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/rom",
             dev->host.seg, dev->host.bus, dev->host.dev, dev->host.func);

    if (access(rom_file, F_OK))
        return;

    /* Write something to the ROM file to enable it */
    fp = fopen(rom_file, "wb");
    if (fp == NULL)
        return;
    len = fwrite(&i, 1, 1, fp);
    fclose(fp);
    if (len != 1)
        return;

    /* The file has to be closed and reopened, otherwise it won't work */
    fp = fopen(rom_file, "rb");
    if (fp == NULL)
        return;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = malloc(size);
    if (buf == NULL) {
        fclose(fp);
        return;
    }

    ret = fread(buf, size, 1, fp);
    if (!feof(fp) || ferror(fp) || ret != 1) {
        free(buf);
        fclose(fp);
        return;
    }
    fclose(fp);

    /* Copy ROM contents into the space backing the ROM BAR */
    if (dev->v_addrs[PCI_ROM_SLOT].r_size >= size &&
        dev->v_addrs[PCI_ROM_SLOT].u.r_virtbase) {
        mprotect(dev->v_addrs[PCI_ROM_SLOT].u.r_virtbase,
                 size, PROT_READ | PROT_WRITE);
        memcpy(dev->v_addrs[PCI_ROM_SLOT].u.r_virtbase,
               buf, size);
        mprotect(dev->v_addrs[PCI_ROM_SLOT].u.r_virtbase,
                 size, PROT_READ);
    }

    free(buf);
}
