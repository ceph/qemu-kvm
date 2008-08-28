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

#ifndef _QEMU_VIRTIO_H
#define _QEMU_VIRTIO_H

#include <sys/uio.h>
#include "hw.h"
#include "pci.h"

/* from Linux's linux/virtio_config.h */

/* Status byte for guest to report progress, and synchronize features. */
/* We have seen device and processed generic fields (VIRTIO_CONFIG_F_VIRTIO) */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE	1
/* We have found a driver for the device. */
#define VIRTIO_CONFIG_S_DRIVER		2
/* Driver has used its parts of the config, and is happy */
#define VIRTIO_CONFIG_S_DRIVER_OK	4
/* We've given up on this device. */
#define VIRTIO_CONFIG_S_FAILED		0x80

/* We notify when the ring is completely used, even if the guest is supressing
 * callbacks */
#define VIRTIO_F_NOTIFY_ON_EMPTY        24

/* from Linux's linux/virtio_ring.h */

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2

/* This means don't notify other side when buffer added. */
#define VRING_USED_F_NO_NOTIFY	1
/* This means don't interrupt guest when buffer consumed. */
#define VRING_AVAIL_F_NO_INTERRUPT	1

typedef struct VirtQueue VirtQueue;
typedef struct VirtIODevice VirtIODevice;

typedef struct VRingDesc
{
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} VRingDesc;

typedef struct VRingAvail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[0];
} VRingAvail;

typedef struct VRingUsedElem
{
    uint32_t id;
    uint32_t len;
} VRingUsedElem;

typedef struct VRingUsed
{
    uint16_t flags;
    uint16_t idx;
    VRingUsedElem ring[0];
} VRingUsed;

typedef struct VRing
{
    unsigned int num;
    VRingDesc *desc;
    VRingAvail *avail;
    VRingUsed *used;
} VRing;

struct VirtQueue
{
    VRing vring;
    uint32_t pfn;
    uint16_t last_avail_idx;
    int inuse;
    void (*handle_output)(VirtIODevice *vdev, VirtQueue *vq);
};

#define VIRTQUEUE_MAX_SIZE 1024

typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int out_num;
    unsigned int in_num;
    struct iovec in_sg[VIRTQUEUE_MAX_SIZE];
    struct iovec out_sg[VIRTQUEUE_MAX_SIZE];
} VirtQueueElement;

#define VIRTIO_PCI_QUEUE_MAX	16

struct VirtIODevice
{
    PCIDevice pci_dev;
    const char *name;
    uint32_t addr;
    uint8_t status;
    uint8_t isr;
    uint16_t queue_sel;
    uint32_t features;
    size_t config_len;
    void *config;
    uint32_t (*get_features)(VirtIODevice *vdev);
    void (*set_features)(VirtIODevice *vdev, uint32_t val);
    void (*get_config)(VirtIODevice *vdev, uint8_t *config);
    void (*set_config)(VirtIODevice *vdev, const uint8_t *config);
    void (*reset)(VirtIODevice *vdev);
    VirtQueue vq[VIRTIO_PCI_QUEUE_MAX];
};

VirtIODevice *virtio_init_pci(PCIBus *bus, const char *name,
			      uint16_t vendor, uint16_t device,
			      uint16_t subvendor, uint16_t subdevice,
			      uint8_t class_code, uint8_t subclass_code,
			      uint8_t pif, size_t config_size,
			      size_t struct_size);

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
			    void (*handle_output)(VirtIODevice *,
						  VirtQueue *));

void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
		    unsigned int len);

int virtqueue_pop(VirtQueue *vq, VirtQueueElement *elem);

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq);

void virtio_save(VirtIODevice *vdev, QEMUFile *f);

void virtio_load(VirtIODevice *vdev, QEMUFile *f);

void virtio_notify_config(VirtIODevice *vdev);

#endif
