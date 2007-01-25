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
#include <stddef.h>

#define HP_CMD          0x00  // The command register  WR
#define HP_ISRSTATUS    0x04  // Interrupt status reg RD 
#define HP_TXSIZE       0x08
#define HP_TXBUFF       0x0c
#define HP_RXSIZE       0x10
#define HP_RXBUFF       0x14

// HP_CMD register commands
#define HP_CMD_DI		1 // disable interrupts
#define HP_CMD_EI		2 // enable interrupts
#define HP_CMD_RESET	4 // enable interrupts


/* Bits in HP_ISR - Interrupt status register */
#define HPISR_RX	0x01  // Data is ready to be read

int use_hypercall_dev = 0;
static CharDriverState *vmchannel_hd;

#define HP_MEM_SIZE    0x50

typedef struct HypercallState {
    uint32_t cmd;
    uint32_t isr;
    uint32_t txsize;
    uint32_t txbuff;
    uint32_t rxsize;
    uint8_t  RxBuff[HP_MEM_SIZE];
    uint8_t  *txbufferaccu;
    int      txbufferaccu_offset;
    int      irq;
    PCIDevice *pci_dev;
} HypercallState;

HypercallState *pHypercallState = NULL;

static void hp_reset(HypercallState *s)
{
    s->cmd = 0;
    s->isr = 0;
    s->txsize = 0;
    s->txbuff = 0;
    s->rxsize= 0;
    if (s->txbufferaccu) {
        free(txbufferaccu)
        s->txbufferaccu = 0;
    }
    s->txbufferaccu_offset = 0;
}

static void hp_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    HypercallState *s = opaque;

    //printf("hp_ioport_write,addr=0x%x, val=0x%x\n",addr, val);

    addr &= 0xff;

    switch(addr)
    {
        case HP_CMD:
        {
            s->cmd = val;
            if (val == HP_CMD_RESET){
                hp_reset(s);
                return;
            }
            break;
        }

        case HP_TXSIZE:
        {
            // handle the case when the we are being called when txsize is not 0
            if (s->txsize != 0) {
                printf("txsize is being set, but txsize is not 0!!!\n");
            }
            s->txsize = val;
            s->txbufferaccu = malloc(val);
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
                printf("tranmit txbuf, Len:0x%x\n", s->txbufferaccu_offset);
                qemu_chr_write(vmchannel_hd, s->txbufferaccu, s->txsize);
                s->txbufferaccu_offset = 0;
                free(s->txbufferaccu);
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

    if (addr != 0xc204) {
        //printf("hp_ioport_read addr:0x%x\n",addr);
    }

    addr &= 0xff;

    if (addr >= offsetof(HypercallState, RxBuff) )
    {
        int RxBuffOffset = addr - (offsetof(HypercallState, RxBuff));
        ret = s->RxBuff[RxBuffOffset];
        return ret;
    }

    switch (addr)
    {
    case HP_ISRSTATUS:
        if (s->isr != 0){
            printf("hp_ioport_read s->isr=0x%x\n", s->isr);
        }
        ret = s->isr;
        if (ret & HPISR_RX) {
            s->isr &= ~HPISR_RX;
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
    printf("hypercall_update_irq\n");

    if (s->cmd &= HP_CMD_DI) {
        return;
    }
	/* PCI irq */
	pci_set_irq(s->pci_dev, 0, 1);
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

// input from vmchannel outside caller
static void vmchannel_read(void *opaque, const uint8_t *buf, int size)
{
    int i;
    
    printf("vmchannel_read buf:%p, size:%d\n", buf, size);
    for(i = 0; i < size; i++) {
        printf("%x,", buf[i]);
    }
    printf("\n");

    // if the hypercall device is in interrupts disabled state, don't accept the data
    if (pHypercallState->cmd &= HP_CMD_DI) {
        return;
    }

    for(i = 0; i < size; i++) {
        //printf("buf[i%d]=%x\n",i, buf[i]);
        pHypercallState->RxBuff[i] = buf[i];
    }
    pHypercallState->rxsize = size;
    pHypercallState->isr = HPISR_RX;
    hypercall_update_irq(pHypercallState);
}

void vmchannel_init(CharDriverState *hd)
{
    vmchannel_hd = hd;

    //printf("vmchannel_init\n");
    use_hypercall_dev = 1;
    qemu_chr_add_read_handler(vmchannel_hd, vmchannel_can_read, vmchannel_read, &pHypercallState);

}
