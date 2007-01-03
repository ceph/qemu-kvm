/*
 * QEMU-KVM Hypercall emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2006 Qumranet
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
#include "vl.h"

int use_hypercall_dev = 0;
static CharDriverState *vmchannel_hd;

typedef struct HypercallState {
    int irq;
    PCIDevice *pci_dev;
} HypercallState;

static void hp_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    //printf("hp_ioport_write, val=0x%x\n", val);
    qemu_chr_write(vmchannel_hd, (const uint8_t*)&val, 1);
}

static uint32_t hp_ioport_read(void *opaque, uint32_t addr)
{
    //printf("hp_ioport_read\n");
    return 0;
}

/***********************************************************/
/* PCI Hypercall definitions */

typedef struct PCIHypercallState {
    PCIDevice dev;
    HypercallState hp;
} PCIHypercallState;

static void hp_map(PCIDevice *pci_dev, int region_num, 
                       uint32_t addr, uint32_t size, int type)
{
    PCIHypercallState *d = (PCIHypercallState *)pci_dev;
    HypercallState *s = &d->hp;

    register_ioport_write(addr, 16, 1, hp_ioport_write, s);
    register_ioport_read(addr, 16, 1, hp_ioport_read, s);

}

void pci_hypercall_init(PCIBus *bus)
{
    PCIHypercallState *d;
    HypercallState *s;
    uint8_t *pci_conf;

    // If the vmchannel wasn't initialized, we don't want the Hypercall device in the guest
    if (use_hypercall_dev == 0) {
        return;
    }

    d = (PCIHypercallState *)pci_register_device(bus,
                                                 "Hypercall", sizeof(PCIHypercallState),
                                                 -1,
                                                 NULL, NULL);

    pci_conf = d->dev.config;
    pci_conf[0x00] = 0x02; // Qumranet vendor ID 0x5002
    pci_conf[0x01] = 0x50;
    pci_conf[0x02] = 0x58; // Qumranet DeviceID 0x2258
    pci_conf[0x03] = 0x22;

    pci_conf[0x09] = 0x00; // ProgIf
    pci_conf[0x0a] = 0x00; // SubClass
    pci_conf[0x0b] = 0x05; // BaseClass

    pci_conf[0x0e] = 0x00; // header_type
    pci_conf[0x3d] = 1; // interrupt pin 0

    pci_register_io_region(&d->dev, 0, 0x100,
                           PCI_ADDRESS_SPACE_IO, hp_map);
    s = &d->hp;
    s->irq = 16; /* PCI interrupt */
    s->pci_dev = (PCIDevice *)d;
}


static int vmchannel_can_read(void *opaque)
{
    return 128;
}

static void vmchannel_read(void *opaque, const uint8_t *buf, int size)
{
    int i;

    //printf("vmchannel_read buf:%p, size:%d\n", buf, size);

    for(i = 0; i < size; i++) {
        readline_handle_byte(buf[i]);
    }
}

void vmchannel_init(CharDriverState *hd)
{
    vmchannel_hd = hd;

    use_hypercall_dev = 1;
    qemu_chr_add_read_handler(vmchannel_hd, vmchannel_can_read, vmchannel_read, NULL);
    //vmchannel_start_input();
}
