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
#include "hypercall.h"
#include <stddef.h>

int use_hypercall_dev = 0;
static CharDriverState *vmchannel_hd;

typedef struct HypercallState {
    uint32_t hcr;
    uint32_t hsr;
    uint32_t txsize;
    uint32_t txbuff;
    uint32_t rxsize;
    uint8_t  RxBuff[HP_MEM_SIZE];
    uint8_t  txbufferaccu[HP_MEM_SIZE];
    int      txbufferaccu_offset;
    int      irq;
    PCIDevice *pci_dev;
} HypercallState;

HypercallState *pHypercallState = NULL;


//#define HYPERCALL_DEBUG 1

static void hp_reset(HypercallState *s)
{
    s->hcr = 0;
    s->hsr = 0;
    s->txsize = 0;
    s->txbuff = 0;
    s->rxsize= 0;
    s->txbufferaccu_offset = 0;
}

static void hypercall_update_irq(HypercallState *s);


static void hp_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    HypercallState *s = opaque;

#ifdef HYPERCALL_DEBUG
    printf("%s: addr=0x%x, val=0x%x\n", __FUNCTION__, addr, val);
#endif
    addr &= 0xff;

    switch(addr)
    {
        case HCR_REGISTER:
        {
            s->hcr = val;
	    if (s->hcr & HCR_DI)
                hypercall_update_irq(s);
            if (val & HCR_GRS){
                hp_reset(s);
            }
            break;
        }

        case HP_TXSIZE:
        {
            // handle the case when the we are being called when txsize is not 0
            if (s->txsize != 0) {
                printf("txsize is being set, but txsize is not 0!!!\n");
            }
            if (val > HP_MEM_SIZE) {
                printf("txsize is larger than allowed by hw!!!\n");
            }
            s->txsize = val;
            s->txbufferaccu_offset = 0;
            break;
        }

        case HP_TXBUFF:
        {
            if (s->txsize == 0) {
                printf("error with txbuff!!!\n");
                break;
            }

            s->txbufferaccu[s->txbufferaccu_offset] = val;
            s->txbufferaccu_offset++;
            if (s->txbufferaccu_offset >= s->txsize) {
                qemu_chr_write(vmchannel_hd, s->txbufferaccu, s->txsize);
                s->txbufferaccu_offset = 0;
                s->txsize = 0;
            }
            break;
        }
        default:
        {
            printf("hp_ioport_write to unhandled address!!!\n");
        }
    }
}

static uint32_t hp_ioport_read(void *opaque, uint32_t addr)
{
    HypercallState *s = opaque;
    int ret;

#ifdef HYPERCALL_DEBUG
    printf("%s: addr=0x%x\n", __FUNCTION__, addr);
#endif
    addr &= 0xff;

    if (addr >= offsetof(HypercallState, RxBuff) )
    {
        int RxBuffOffset = addr - (offsetof(HypercallState, RxBuff));
        ret = s->RxBuff[RxBuffOffset];
        return ret;
    }

    switch (addr)
    {
    case HSR_REGISTER:
        ret = s->hsr;
        if (ret & HSR_VDR) {
            s->hsr &= ~HSR_VDR;
        }
        break;
    case HP_RXSIZE:
        ret = s->rxsize;
        break;

    default:
        ret = 0x00;
        break;
    }

    return ret;
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

    register_ioport_write(addr, 0x100, 1, hp_ioport_write, s);
    register_ioport_read(addr, 0x100, 1, hp_ioport_read, s);

}


static void hypercall_update_irq(HypercallState *s)
{
    /* PCI irq */
    pci_set_irq(s->pci_dev, 0, !(s->hcr & HCR_DI));
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
    pHypercallState = s;
    s->irq = 16; /* PCI interrupt */
    s->pci_dev = (PCIDevice *)d;

    hp_reset(s);
}


static int vmchannel_can_read(void *opaque)
{
    return 128;
}

static void vmchannel_event(void *opaque, int event)
{
    PCIHypercallState *s = opaque;
#ifdef HYPERCALL_DEBUG
    printf("%s got event %d\n", __FUNCTION__, event);
#endif
    return;
}

// input from vmchannel outside caller
static void vmchannel_read(void *opaque, const uint8_t *buf, int size)
{
    int i;

#ifdef HYPERCALL_DEBUG    
    printf("vmchannel_read buf:%s, size:%d\n", buf, size);
#endif

    // if the hypercall device is in interrupts disabled state, don't accept the data
    if (pHypercallState->hcr & HCR_DI) {
        return;
    }

    for(i = 0; i < size; i++) {
        pHypercallState->RxBuff[i] = buf[i];
    }
    pHypercallState->rxsize = size;
    pHypercallState->hsr = HSR_VDR;
    hypercall_update_irq(pHypercallState);
}

void vmchannel_init(CharDriverState *hd)
{
    vmchannel_hd = hd;

#ifdef HYPERCALL_DEBUG
    printf("vmchannel_init\n");
#endif
    use_hypercall_dev = 1;
    qemu_chr_add_handlers(vmchannel_hd, vmchannel_can_read, vmchannel_read,
			  vmchannel_event, &pHypercallState);
}
