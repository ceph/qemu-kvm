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
#include <sys/io.h>
#include "qemu-kvm.h"
#include "hw.h"
#include "pc.h"
#include "sysemu.h"
#include "console.h"
#include "device-assignment.h"

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

static void assigned_dev_iomem_map(PCIDevice *pci_dev, int region_num,
                                   uint32_t e_phys, uint32_t e_size, int type)
{
    AssignedDevice *r_dev = (AssignedDevice *) pci_dev;
    AssignedDevRegion *region = &r_dev->v_addrs[region_num];
    uint32_t old_ephys = region->e_physbase;
    uint32_t old_esize = region->e_size;
    int first_map = (region->e_size == 0);
    int ret = 0;

    DEBUG("e_phys=%08x r_virt=%p type=%d len=%08x region_num=%d \n",
          e_phys, region->u.r_virtbase, type, e_size, region_num);

    region->e_physbase = e_phys;
    region->e_size = e_size;

    if (!first_map) {
        int slot = get_slot(old_ephys);
        if (slot != -1)
	    kvm_destroy_phys_mem(kvm_context, old_ephys,
                                 TARGET_PAGE_ALIGN(old_esize));
    }

    if (e_size > 0)
	ret = kvm_register_phys_mem(kvm_context, e_phys,
                                    region->u.r_virtbase,
                                    TARGET_PAGE_ALIGN(e_size), 0);

    if (ret != 0) {
	fprintf(stderr, "%s: Error: create new mapping failed\n", __func__);
	exit(1);
    }
}

static void assigned_dev_ioport_map(PCIDevice *pci_dev, int region_num,
                                    uint32_t addr, uint32_t size, int type)
{
    AssignedDevice *r_dev = (AssignedDevice *) pci_dev;
    AssignedDevRegion *region = &r_dev->v_addrs[region_num];
    int first_map = (region->e_size == 0);
    CPUState *env;

    region->e_physbase = addr;
    region->e_size = size;

    DEBUG("e_phys=0x%x r_baseport=%x type=0x%x len=%d region_num=%d \n",
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

static void assigned_dev_pci_write_config(PCIDevice *d, uint32_t address,
                                          uint32_t val, int len)
{
    int fd;
    ssize_t ret;

    DEBUG("(%x.%x): address=%04x val=0x%08x len=%d\n",
          ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
          (uint16_t) address, val, len);

    if (address == 0x4) {
        pci_default_write_config(d, address, val, len);
        /* Continue to program the card */
    }

    if ((address >= 0x10 && address <= 0x24) || address == 0x34 ||
        address == 0x3c || address == 0x3d) {
        /* used for update-mappings (BAR emulation) */
        pci_default_write_config(d, address, val, len);
        return;
    }

    DEBUG("NON BAR (%x.%x): address=%04x val=0x%08x len=%d\n",
          ((d->devfn >> 3) & 0x1F), (d->devfn & 0x7),
          (uint16_t) address, val, len);

    fd = ((AssignedDevice *)d)->real_device.config_fd;

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

    if ((address >= 0x10 && address <= 0x24) || address == 0x34 ||
        address == 0x3c || address == 0x3d) {
        val = pci_default_read_config(d, address, len);
        DEBUG("(%x.%x): address=%04x val=0x%08x len=%d\n",
              (d->devfn >> 3) & 0x1F, (d->devfn & 0x7), address, val, len);
        return val;
    }

    /* vga specific, remove later */
    if (address == 0xFC)
        goto do_log;

    fd = ((AssignedDevice *)d)->real_device.config_fd;

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

    /* kill the special capabilities */
    if (address == 4 && len == 4)
        val &= ~0x100000;
    else if (address == 6)
        val &= ~0x10;

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
            int t = cur_region->type & IORESOURCE_PREFETCH
                ? PCI_ADDRESS_SPACE_MEM_PREFETCH
                : PCI_ADDRESS_SPACE_MEM;

            /* map physical memory */
            pci_dev->v_addrs[i].e_physbase = cur_region->base_addr;
            pci_dev->v_addrs[i].u.r_virtbase =
                mmap(NULL,
                     (cur_region->size + 0xFFF) & 0xFFFFF000,
                     PROT_WRITE | PROT_READ, MAP_SHARED,
                     cur_region->resource_fd, (off_t) 0);

            if (pci_dev->v_addrs[i].u.r_virtbase == MAP_FAILED) {
                pci_dev->v_addrs[i].u.r_virtbase = NULL;
                fprintf(stderr, "%s: Error: Couldn't mmap 0x%x!"
                        "\n", __func__,
                        (uint32_t) (cur_region->base_addr));
                return -1;
            }
            pci_dev->v_addrs[i].r_size = cur_region->size;
            pci_dev->v_addrs[i].e_size = 0;

            /* add offset */
            pci_dev->v_addrs[i].u.r_virtbase +=
                (cur_region->base_addr & 0xFFF);

            pci_register_io_region((PCIDevice *) pci_dev, i,
                                   cur_region->size, t,
                                   assigned_dev_iomem_map);
            continue;
        }
        /* handle port io regions */
        pci_dev->v_addrs[i].e_physbase = cur_region->base_addr;
        pci_dev->v_addrs[i].u.r_baseport = cur_region->base_addr;
        pci_dev->v_addrs[i].r_size = cur_region->size;
        pci_dev->v_addrs[i].e_size = 0;

        pci_register_io_region((PCIDevice *) pci_dev, i,
                               cur_region->size, PCI_ADDRESS_SPACE_IO,
                               assigned_dev_ioport_map);

        /* not relevant for port io */
        pci_dev->v_addrs[i].memory_index = 0;
    }

    /* success */
    return 0;
}

static int get_real_device(AssignedDevice *pci_dev, uint8_t r_bus,
                           uint8_t r_dev, uint8_t r_func)
{
    char dir[128], name[128];
    int fd, r = 0;
    FILE *f;
    unsigned long long start, end, size, flags;
    PCIRegion *rp;
    PCIDevRegions *dev = &pci_dev->real_device;

    dev->region_number = 0;

    snprintf(dir, sizeof(dir), "/sys/bus/pci/devices/0000:%02x:%02x.%x/",
	     r_bus, r_dev, r_func);

    snprintf(name, sizeof(name), "%sconfig", dir);

    fd = open(name, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "%s: %s: %m\n", __func__, name);
        return 1;
    }
    dev->config_fd = fd;
again:
    r = read(fd, pci_dev->dev.config, sizeof(pci_dev->dev.config));
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

    for (r = 0; r < MAX_IO_REGIONS; r++) {
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
	    snprintf(name, sizeof(name), "%sresource%d", dir, r);
            fd = open(name, O_RDWR);
            if (fd == -1)
                continue;       /* probably ROM */
            rp->resource_fd = fd;
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

    dev->region_number = r;
    return 0;
}

static LIST_HEAD(, AssignedDevInfo) adev_head;

void free_assigned_device(AssignedDevInfo *adev)
{
    AssignedDevice *dev = adev->assigned_dev;

    if (dev) {
        int i;

        for (i = 0; i < dev->real_device.region_number; i++) {
            PCIRegion *pci_region = &dev->real_device.regions[i];
            AssignedDevRegion *region = &dev->v_addrs[i];

            if (!pci_region->valid || !(pci_region->type & IORESOURCE_MEM))
                continue;

            if (region->u.r_virtbase) {
                int ret = munmap(region->u.r_virtbase,
                                 (pci_region->size + 0xFFF) & 0xFFFFF000);
                if (ret != 0)
                    fprintf(stderr,
                            "Failed to unmap assigned device region: %s\n",
                            strerror(errno));
            }
        }

        if (dev->real_device.config_fd) {
            close(dev->real_device.config_fd);
            dev->real_device.config_fd = 0;
        }

        pci_unregister_device(&dev->dev);
        adev->assigned_dev = dev = NULL;
    }

    LIST_REMOVE(adev, next);
    qemu_free(adev);
}

static uint32_t calc_assigned_dev_id(uint8_t bus, uint8_t devfn)
{
    return (uint32_t)bus << 8 | (uint32_t)devfn;
}

/* The pci config space got updated. Check if irq numbers have changed
 * for our devices
 */
void assigned_dev_update_irq(PCIDevice *d)
{
    AssignedDevInfo *adev;

    adev = LIST_FIRST(&adev_head);
    while (adev) {
        AssignedDevInfo *next = LIST_NEXT(adev, next);
        AssignedDevice *assigned_dev = adev->assigned_dev;
        int irq, r;

        irq = pci_map_irq(&assigned_dev->dev, assigned_dev->intpin);
        irq = piix_get_irq(irq);

#ifdef TARGET_IA64
	irq = ipf_map_irq(d, irq);
#endif

        if (irq != assigned_dev->girq) {
            struct kvm_assigned_irq assigned_irq_data;

            memset(&assigned_irq_data, 0, sizeof(assigned_irq_data));
            assigned_irq_data.assigned_dev_id  =
                calc_assigned_dev_id(assigned_dev->h_busnr,
                                     (uint8_t) assigned_dev->h_devfn);
            assigned_irq_data.guest_irq = irq;
            assigned_irq_data.host_irq = assigned_dev->real_device.irq;
            r = kvm_assign_irq(kvm_context, &assigned_irq_data);
            if (r < 0) {
                fprintf(stderr, "Failed to assign irq for \"%s\": %s\n",
                        adev->name, strerror(-r));
                fprintf(stderr, "Perhaps you are assigning a device "
                        "that shares an IRQ with another device?\n");
                LIST_REMOVE(adev, next);
                free_assigned_device(adev);
                adev = next;
                continue;
            }
            assigned_dev->girq = irq;
        }

        adev = next;
    }
}

struct PCIDevice *init_assigned_device(AssignedDevInfo *adev, PCIBus *bus)
{
    int r;
    AssignedDevice *dev;
    uint8_t e_device, e_intx;
    struct kvm_assigned_pci_dev assigned_dev_data;

    DEBUG("Registering real physical device %s (bus=%x dev=%x func=%x)\n",
          adev->name, adev->bus, adev->dev, adev->func);

    dev = (AssignedDevice *)
        pci_register_device(bus, adev->name, sizeof(AssignedDevice),
                            -1, assigned_dev_pci_read_config,
                            assigned_dev_pci_write_config);
    if (NULL == dev) {
        fprintf(stderr, "%s: Error: Couldn't register real device %s\n",
                __func__, adev->name);
        return NULL;
    }

    adev->assigned_dev = dev;

    if (get_real_device(dev, adev->bus, adev->dev, adev->func)) {
        fprintf(stderr, "%s: Error: Couldn't get real device (%s)!\n",
                __func__, adev->name);
        return NULL;
    }

    /* handle real device's MMIO/PIO BARs */
    if (assigned_dev_register_regions(dev->real_device.regions,
                                      dev->real_device.region_number,
                                      dev))
        return NULL;

    /* handle interrupt routing */
    e_device = (dev->dev.devfn >> 3) & 0x1f;
    e_intx = dev->dev.config[0x3d] - 1;
    dev->intpin = e_intx;
    dev->run = 0;
    dev->girq = 0;
    dev->h_busnr = adev->bus;
    dev->h_devfn = PCI_DEVFN(adev->dev, adev->func);

    memset(&assigned_dev_data, 0, sizeof(assigned_dev_data));
    assigned_dev_data.assigned_dev_id  =
	calc_assigned_dev_id(dev->h_busnr, (uint32_t)dev->h_devfn);
    assigned_dev_data.busnr = dev->h_busnr;
    assigned_dev_data.devfn = dev->h_devfn;

#ifdef KVM_CAP_IOMMU
    /* We always enable the IOMMU if present
     * (or when not disabled on the command line)
     */
    r = kvm_check_extension(kvm_context, KVM_CAP_IOMMU);
    if (r && !adev->disable_iommu)
	assigned_dev_data.flags |= KVM_DEV_ASSIGN_ENABLE_IOMMU;
#endif

    r = kvm_assign_pci_device(kvm_context, &assigned_dev_data);
    if (r < 0) {
	fprintf(stderr, "Failed to assign device \"%s\" : %s\n",
                adev->name, strerror(-r));
	return NULL;
    }

    return &dev->dev;
}

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
AssignedDevInfo *add_assigned_device(const char *arg)
{
    char *cp, *cp1;
    char device[8];
    char dma[6];
    int r;
    AssignedDevInfo *adev;

    adev = qemu_mallocz(sizeof(AssignedDevInfo));
    if (adev == NULL) {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        return NULL;
    }
    r = get_param_value(device, sizeof(device), "host", arg);
    r = get_param_value(adev->name, sizeof(adev->name), "name", arg);
    if (!r)
	snprintf(adev->name, sizeof(adev->name), "%s", device);

#ifdef KVM_CAP_IOMMU
    r = get_param_value(dma, sizeof(dma), "dma", arg);
    if (r && !strncmp(dma, "none", 4))
        adev->disable_iommu = 1;
#endif
    cp = device;
    adev->bus = strtoul(cp, &cp1, 16);
    if (*cp1 != ':')
        goto bad;
    cp = cp1 + 1;

    adev->dev = strtoul(cp, &cp1, 16);
    if (*cp1 != '.')
        goto bad;
    cp = cp1 + 1;

    adev->func = strtoul(cp, &cp1, 16);

    LIST_INSERT_HEAD(&adev_head, adev, next);
    return adev;
bad:
    fprintf(stderr, "pcidevice argument parse error; "
            "please check the help text for usage\n");
    qemu_free(adev);
    return NULL;
}

void add_assigned_devices(PCIBus *bus, const char **devices, int n_devices)
{
    int i;

    for (i = 0; i < n_devices; i++) {
        struct AssignedDevInfo *adev;

        adev = add_assigned_device(devices[i]);
        if (!adev) {
            fprintf(stderr, "Could not add assigned device %s\n", devices[i]);
            continue;
            exit(1);
        }

        if (!init_assigned_device(adev, bus)) {
            fprintf(stderr, "Failed to initialize assigned device %s\n",
                    devices[i]);
            exit(1);
        }
    }
}
