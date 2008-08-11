/*
 * Virtio Support
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <inttypes.h>
#include <err.h>

#include "virtio.h"
#include "sysemu.h"

/* from Linux's linux/virtio_pci.h */

/* A 32-bit r/o bitmask of the features supported by the host */
#define VIRTIO_PCI_HOST_FEATURES	0

/* A 32-bit r/w bitmask of features activated by the guest */
#define VIRTIO_PCI_GUEST_FEATURES	4

/* A 32-bit r/w PFN for the currently selected queue */
#define VIRTIO_PCI_QUEUE_PFN		8

/* A 16-bit r/o queue size for the currently selected queue */
#define VIRTIO_PCI_QUEUE_NUM		12

/* A 16-bit r/w queue selector */
#define VIRTIO_PCI_QUEUE_SEL		14

/* A 16-bit r/w queue notifier */
#define VIRTIO_PCI_QUEUE_NOTIFY		16

/* An 8-bit device status register.  */
#define VIRTIO_PCI_STATUS		18

/* An 8-bit r/o interrupt status register.  Reading the value will return the
 * current contents of the ISR and will also clear it.  This is effectively
 * a read-and-acknowledge. */
#define VIRTIO_PCI_ISR			19

#define VIRTIO_PCI_CONFIG		20

/* Virtio ABI version, if we increment this, we break the guest driver. */
#define VIRTIO_PCI_ABI_VERSION		0

/* QEMU doesn't strictly need write barriers since everything runs in
 * lock-step.  We'll leave the calls to wmb() in though to make it obvious for
 * KVM or if kqemu gets SMP support.
 */
#define wmb() do { } while (0)

/* virt queue functions */

static void *virtio_map_gpa(target_phys_addr_t addr, size_t size)
{
    ram_addr_t off;
    target_phys_addr_t addr1;

    off = cpu_get_physical_page_desc(addr);
    if ((off & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
	fprintf(stderr, "virtio DMA to IO ram\n");
	exit(1);
    }

    off = (off & TARGET_PAGE_MASK) | (addr & ~TARGET_PAGE_MASK);

    for (addr1 = addr + TARGET_PAGE_SIZE;
	 addr1 < TARGET_PAGE_ALIGN(addr + size);
	 addr1 += TARGET_PAGE_SIZE) {
	ram_addr_t off1;

	off1 = cpu_get_physical_page_desc(addr1);
	if ((off1 & ~TARGET_PAGE_MASK) != IO_MEM_RAM) {
	    fprintf(stderr, "virtio DMA to IO ram\n");
	    exit(1);
	}

	off1 = (off1 & TARGET_PAGE_MASK) | (addr1 & ~TARGET_PAGE_MASK);

	if (off1 != (off + (addr1 - addr))) {
	    fprintf(stderr, "discontigous virtio memory\n");
	    exit(1);
	}
    }

    return phys_ram_base + off;
}

static size_t virtqueue_size(int num)
{
    return TARGET_PAGE_ALIGN((sizeof(VRingDesc) * num) +
			     (sizeof(VRingAvail) + sizeof(uint16_t) * num)) +
	(sizeof(VRingUsed) + sizeof(VRingUsedElem) * num);
}

static void virtqueue_init(VirtQueue *vq, void *p)
{
    vq->vring.desc = p;
    vq->vring.avail = p + vq->vring.num * sizeof(VRingDesc);
    vq->vring.used = (void *)TARGET_PAGE_ALIGN((unsigned long)&vq->vring.avail->ring[vq->vring.num]);
}

static unsigned virtqueue_next_desc(VirtQueue *vq, unsigned int i)
{
    unsigned int next;

    /* If this descriptor says it doesn't chain, we're done. */
    if (!(vq->vring.desc[i].flags & VRING_DESC_F_NEXT))
	return vq->vring.num;

    /* Check they're not leading us off end of descriptors. */
    next = vq->vring.desc[i].next;
    /* Make sure compiler knows to grab that: we don't want it changing! */
    wmb();

    if (next >= vq->vring.num)
	errx(1, "Desc next is %u", next);

    return next;
}

void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
		    unsigned int len)
{
    VRingUsedElem *used;

    /* Get a pointer to the next entry in the used ring. */
    used = &vq->vring.used->ring[vq->vring.used->idx % vq->vring.num];
    used->id = elem->index;
    used->len = len;
    /* Make sure buffer is written before we update index. */
    wmb();
    vq->vring.used->idx++;
    vq->inuse--;
}

int virtqueue_pop(VirtQueue *vq, VirtQueueElement *elem)
{
    unsigned int i, head;
    unsigned int position;

    /* Check it isn't doing very strange things with descriptor numbers. */
    if ((uint16_t)(vq->vring.avail->idx - vq->last_avail_idx) > vq->vring.num)
	errx(1, "Guest moved used index from %u to %u",
	     vq->last_avail_idx, vq->vring.avail->idx);

    /* If there's nothing new since last we looked, return invalid. */
    if (vq->vring.avail->idx == vq->last_avail_idx)
	return 0;

    /* Grab the next descriptor number they're advertising, and increment
     * the index we've seen. */
    head = vq->vring.avail->ring[vq->last_avail_idx++ % vq->vring.num];

    /* If their number is silly, that's a fatal mistake. */
    if (head >= vq->vring.num)
	errx(1, "Guest says index %u is available", head);

    /* When we start there are none of either input nor output. */
    position = elem->out_num = elem->in_num = 0;

    i = head;
    do {
	struct iovec *sg;

	if (vq->vring.desc[i].flags & VRING_DESC_F_WRITE)
	    sg = &elem->in_sg[elem->in_num++];
	else
	    sg = &elem->out_sg[elem->out_num++];

	/* Grab the first descriptor, and check it's OK. */
	sg->iov_len = vq->vring.desc[i].len;
	sg->iov_base = virtio_map_gpa(vq->vring.desc[i].addr, sg->iov_len);
	if (sg->iov_base == NULL)
	    errx(1, "Invalid mapping\n");

	/* If we've got too many, that implies a descriptor loop. */
	if ((elem->in_num + elem->out_num) > vq->vring.num)
	    errx(1, "Looped descriptor");
    } while ((i = virtqueue_next_desc(vq, i)) != vq->vring.num);

    elem->index = head;

    vq->inuse++;

    return elem->in_num + elem->out_num;
}

/* virtio device */

static VirtIODevice *to_virtio_device(PCIDevice *pci_dev)
{
    return (VirtIODevice *)pci_dev;
}

static void virtio_update_irq(VirtIODevice *vdev)
{
    qemu_set_irq(vdev->pci_dev.irq[0], vdev->isr & 1);
}

void virtio_reset(void *opaque)
{
    VirtIODevice *vdev = opaque;
    int i;

    if (vdev->reset)
        vdev->reset(vdev);

    vdev->features = 0;
    vdev->queue_sel = 0;
    vdev->status = 0;
    vdev->isr = 0;
    virtio_update_irq(vdev);

    for(i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++) {
        vdev->vq[i].vring.desc = NULL;
        vdev->vq[i].vring.avail = NULL;
        vdev->vq[i].vring.used = NULL;
        vdev->vq[i].last_avail_idx = 0;
        vdev->vq[i].pfn = 0;
    }
}

static void virtio_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    VirtIODevice *vdev = to_virtio_device(opaque);
    ram_addr_t pa;

    addr -= vdev->addr;

    switch (addr) {
    case VIRTIO_PCI_GUEST_FEATURES:
	if (vdev->set_features)
	    vdev->set_features(vdev, val);
	vdev->features = val;
	break;
    case VIRTIO_PCI_QUEUE_PFN:
	pa = (ram_addr_t)val << TARGET_PAGE_BITS;
	vdev->vq[vdev->queue_sel].pfn = val;
	if (pa == 0) {
            virtio_reset(vdev);
	} else {
	    size_t size = virtqueue_size(vdev->vq[vdev->queue_sel].vring.num);
	    virtqueue_init(&vdev->vq[vdev->queue_sel],
			   virtio_map_gpa(pa, size));
	}
	break;
    case VIRTIO_PCI_QUEUE_SEL:
	if (val < VIRTIO_PCI_QUEUE_MAX)
	    vdev->queue_sel = val;
	break;
    case VIRTIO_PCI_QUEUE_NOTIFY:
	if (val < VIRTIO_PCI_QUEUE_MAX && vdev->vq[val].vring.desc)
	    vdev->vq[val].handle_output(vdev, &vdev->vq[val]);
	break;
    case VIRTIO_PCI_STATUS:
	vdev->status = val & 0xFF;
	if (vdev->status == 0)
	    virtio_reset(vdev);
	break;
    }
}

static uint32_t virtio_ioport_read(void *opaque, uint32_t addr)
{
    VirtIODevice *vdev = to_virtio_device(opaque);
    uint32_t ret = 0xFFFFFFFF;

    addr -= vdev->addr;

    switch (addr) {
    case VIRTIO_PCI_HOST_FEATURES:
	ret = vdev->get_features(vdev);
	ret |= (1 << VIRTIO_F_NOTIFY_ON_EMPTY);
	break;
    case VIRTIO_PCI_GUEST_FEATURES:
	ret = vdev->features;
	break;
    case VIRTIO_PCI_QUEUE_PFN:
	ret = vdev->vq[vdev->queue_sel].pfn;
	break;
    case VIRTIO_PCI_QUEUE_NUM:
	ret = vdev->vq[vdev->queue_sel].vring.num;
	break;
    case VIRTIO_PCI_QUEUE_SEL:
	ret = vdev->queue_sel;
	break;
    case VIRTIO_PCI_STATUS:
	ret = vdev->status;
	break;
    case VIRTIO_PCI_ISR:
	/* reading from the ISR also clears it. */
	ret = vdev->isr;
	vdev->isr = 0;
	virtio_update_irq(vdev);
	break;
    default:
	break;
    }

    return ret;
}

static uint32_t virtio_config_readb(void *opaque, uint32_t addr)
{
    VirtIODevice *vdev = opaque;
    uint8_t val;

    addr -= vdev->addr + VIRTIO_PCI_CONFIG;
    if (addr > (vdev->config_len - sizeof(val)))
	return (uint32_t)-1;

    memcpy(&val, vdev->config + addr, sizeof(val));
    return val;
}

static uint32_t virtio_config_readw(void *opaque, uint32_t addr)
{
    VirtIODevice *vdev = opaque;
    uint16_t val;

    addr -= vdev->addr + VIRTIO_PCI_CONFIG;
    if (addr > (vdev->config_len - sizeof(val)))
	return (uint32_t)-1;

    memcpy(&val, vdev->config + addr, sizeof(val));
    return val;
}

static uint32_t virtio_config_readl(void *opaque, uint32_t addr)
{
    VirtIODevice *vdev = opaque;
    uint32_t val;

    addr -= vdev->addr + VIRTIO_PCI_CONFIG;
    if (addr > (vdev->config_len - sizeof(val)))
	return (uint32_t)-1;

    memcpy(&val, vdev->config + addr, sizeof(val));
    return val;
}

static void virtio_config_writeb(void *opaque, uint32_t addr, uint32_t data)
{
    VirtIODevice *vdev = opaque;
    uint8_t val = data;

    addr -= vdev->addr + VIRTIO_PCI_CONFIG;
    if (addr > (vdev->config_len - sizeof(val)))
	return;

    memcpy(vdev->config + addr, &val, sizeof(val));
}

static void virtio_config_writew(void *opaque, uint32_t addr, uint32_t data)
{
    VirtIODevice *vdev = opaque;
    uint16_t val = data;

    addr -= vdev->addr + VIRTIO_PCI_CONFIG;
    if (addr > (vdev->config_len - sizeof(val)))
	return;

    memcpy(vdev->config + addr, &val, sizeof(val));
}

static void virtio_config_writel(void *opaque, uint32_t addr, uint32_t data)
{
    VirtIODevice *vdev = opaque;
    uint32_t val = data;

    addr -= vdev->addr + VIRTIO_PCI_CONFIG;
    if (addr > (vdev->config_len - sizeof(val)))
	return;

    memcpy(vdev->config + addr, &val, sizeof(val));
}

static void virtio_map(PCIDevice *pci_dev, int region_num,
		       uint32_t addr, uint32_t size, int type)
{
    VirtIODevice *vdev = to_virtio_device(pci_dev);
    int i;

    vdev->addr = addr;
    for (i = 0; i < 3; i++) {
	register_ioport_write(addr, 20, 1 << i, virtio_ioport_write, vdev);
	register_ioport_read(addr, 20, 1 << i, virtio_ioport_read, vdev);
    }

    if (vdev->config_len) {
	register_ioport_write(addr + 20, vdev->config_len, 1,
			      virtio_config_writeb, vdev);
	register_ioport_write(addr + 20, vdev->config_len, 2,
			      virtio_config_writew, vdev);
	register_ioport_write(addr + 20, vdev->config_len, 4,
			      virtio_config_writel, vdev);
	register_ioport_read(addr + 20, vdev->config_len, 1,
			     virtio_config_readb, vdev);
	register_ioport_read(addr + 20, vdev->config_len, 2,
			     virtio_config_readw, vdev);
	register_ioport_read(addr + 20, vdev->config_len, 4,
			     virtio_config_readl, vdev);

	vdev->update_config(vdev, vdev->config);
    }
}

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
			    void (*handle_output)(VirtIODevice *, VirtQueue *))
{
    int i;

    for (i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++) {
	if (vdev->vq[i].vring.num == 0)
	    break;
    }

    if (i == VIRTIO_PCI_QUEUE_MAX || queue_size > VIRTQUEUE_MAX_SIZE)
	abort();

    vdev->vq[i].vring.num = queue_size;
    vdev->vq[i].handle_output = handle_output;

    return &vdev->vq[i];
}

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    /* Always notify when queue is empty */
    if ((vq->inuse || vq->vring.avail->idx != vq->last_avail_idx) &&
	(vq->vring.avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
	return;

    vdev->isr = 1;
    virtio_update_irq(vdev);
}

void virtio_save(VirtIODevice *vdev, QEMUFile *f)
{
    int i;

    pci_device_save(&vdev->pci_dev, f);

    qemu_put_be32s(f, &vdev->addr);
    qemu_put_8s(f, &vdev->status);
    qemu_put_8s(f, &vdev->isr);
    qemu_put_be16s(f, &vdev->queue_sel);
    qemu_put_be32s(f, &vdev->features);
    qemu_put_be32(f, vdev->config_len);
    qemu_put_buffer(f, vdev->config, vdev->config_len);

    for (i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++) {
	if (vdev->vq[i].vring.num == 0)
	    break;
    }

    qemu_put_be32(f, i);

    for (i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++) {
	if (vdev->vq[i].vring.num == 0)
	    break;

	qemu_put_be32(f, vdev->vq[i].vring.num);
	qemu_put_be32s(f, &vdev->vq[i].pfn);
	qemu_put_be16s(f, &vdev->vq[i].last_avail_idx);
    }
}

void virtio_load(VirtIODevice *vdev, QEMUFile *f)
{
    int num, i;

    pci_device_load(&vdev->pci_dev, f);

    qemu_get_be32s(f, &vdev->addr);
    qemu_get_8s(f, &vdev->status);
    qemu_get_8s(f, &vdev->isr);
    qemu_get_be16s(f, &vdev->queue_sel);
    qemu_get_be32s(f, &vdev->features);
    vdev->config_len = qemu_get_be32(f);
    qemu_get_buffer(f, vdev->config, vdev->config_len);

    num = qemu_get_be32(f);

    for (i = 0; i < num; i++) {
	vdev->vq[i].vring.num = qemu_get_be32(f);
	qemu_get_be32s(f, &vdev->vq[i].pfn);
	qemu_get_be16s(f, &vdev->vq[i].last_avail_idx);

	if (vdev->vq[i].pfn) {
	    size_t size;
	    target_phys_addr_t pa;

	    pa = (ram_addr_t)vdev->vq[i].pfn << TARGET_PAGE_BITS;
	    size = virtqueue_size(vdev->vq[i].vring.num);
	    virtqueue_init(&vdev->vq[i], virtio_map_gpa(pa, size));
	}
    }

    virtio_update_irq(vdev);
}

VirtIODevice *virtio_init_pci(PCIBus *bus, const char *name,
			      uint16_t vendor, uint16_t device,
			      uint16_t subvendor, uint16_t subdevice,
			      uint8_t class_code, uint8_t subclass_code,
			      uint8_t pif, size_t config_size,
			      size_t struct_size)
{
    VirtIODevice *vdev;
    PCIDevice *pci_dev;
    uint8_t *config;
    uint32_t size;

    pci_dev = pci_register_device(bus, name, struct_size,
				  -1, NULL, NULL);
    if (!pci_dev)
	return NULL;

    vdev = to_virtio_device(pci_dev);

    vdev->status = 0;
    vdev->isr = 0;
    vdev->queue_sel = 0;
    memset(vdev->vq, 0, sizeof(vdev->vq));

    config = pci_dev->config;
    config[0x00] = vendor & 0xFF;
    config[0x01] = (vendor >> 8) & 0xFF;
    config[0x02] = device & 0xFF;
    config[0x03] = (device >> 8) & 0xFF;

    config[0x08] = VIRTIO_PCI_ABI_VERSION;

    config[0x09] = pif;
    config[0x0a] = subclass_code;
    config[0x0b] = class_code;
    config[0x0e] = 0x00;

    config[0x2c] = subvendor & 0xFF;
    config[0x2d] = (subvendor >> 8) & 0xFF;
    config[0x2e] = subdevice & 0xFF;
    config[0x2f] = (subdevice >> 8) & 0xFF;

    config[0x3d] = 1;

    vdev->name = name;
    vdev->config_len = config_size;
    if (vdev->config_len)
	vdev->config = qemu_mallocz(config_size);
    else
	vdev->config = NULL;

    size = 20 + config_size;
    if (size & (size-1))
        size = 1 << fls(size);

    pci_register_io_region(pci_dev, 0, size, PCI_ADDRESS_SPACE_IO,
			   virtio_map);
    qemu_register_reset(virtio_reset, vdev);

    return vdev;
}
