/*
 * Virtio Network Device
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

#include "virtio.h"
#include "net.h"
#include "pc.h"

/* from Linux's virtio_net.h */

/* The ID for virtio_net */
#define VIRTIO_ID_NET	1

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_NO_CSUM	0
#define VIRTIO_NET_F_TSO4	1
#define VIRTIO_NET_F_UFO	2
#define VIRTIO_NET_F_TSO4_ECN	3
#define VIRTIO_NET_F_TSO6	4
#define VIRTIO_NET_F_MAC	5

/* The config defining mac address (6 bytes) */
struct virtio_net_config
{
    uint8_t mac[6];
} __attribute__((packed));

/* This is the first element of the scatter-gather list.  If you don't
 * specify GSO or CSUM features, you can simply ignore the header. */
struct virtio_net_hdr
{
#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1	// Use csum_start, csum_offset
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE		0	// Not a GSO frame
#define VIRTIO_NET_HDR_GSO_TCPV4	1	// GSO frame, IPv4 TCP (TSO)
/* FIXME: Do we need this?  If they said they can handle ECN, do they care? */
#define VIRTIO_NET_HDR_GSO_TCPV4_ECN	2	// GSO frame, IPv4 TCP w/ ECN
#define VIRTIO_NET_HDR_GSO_UDP		3	// GSO frame, IPv4 UDP (UFO)
#define VIRTIO_NET_HDR_GSO_TCPV6	4	// GSO frame, IPv6 TCP
    uint8_t gso_type;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
};

typedef struct VirtIONet
{
    VirtIODevice vdev;
    uint8_t mac[6];
    VirtQueue *rx_vq;
    VirtQueue *tx_vq;
    VLANClientState *vc;
    int can_receive;
} VirtIONet;

static VirtIONet *to_virtio_net(VirtIODevice *vdev)
{
    return (VirtIONet *)vdev;
}

static void virtio_net_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIONet *n = to_virtio_net(vdev);
    struct virtio_net_config netcfg;

    memcpy(netcfg.mac, n->mac, 6);
    memcpy(config, &netcfg, sizeof(netcfg));
}

static uint32_t virtio_net_get_features(VirtIODevice *vdev)
{
    return (1 << VIRTIO_NET_F_MAC);
}

/* RX */

static void virtio_net_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIONet *n = to_virtio_net(vdev);
    n->can_receive = 1;
}

static int virtio_net_can_receive(void *opaque)
{
    VirtIONet *n = opaque;

    return (n->vdev.status & VIRTIO_CONFIG_S_DRIVER_OK) && n->can_receive;
}

static void virtio_net_receive(void *opaque, const uint8_t *buf, int size)
{
    VirtIONet *n = opaque;
    VirtQueueElement elem;
    struct virtio_net_hdr *hdr;
    int offset, i;

    /* FIXME: the drivers really need to set their status better */
    if (n->rx_vq->vring.avail == NULL) {
	n->can_receive = 0;
	return;
    }

    if (virtqueue_pop(n->rx_vq, &elem) == 0) {
	/* wait until the guest adds some rx bufs */
	n->can_receive = 0;
	return;
    }

    hdr = (void *)elem.in_sg[0].iov_base;
    hdr->flags = 0;
    hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;

    /* copy in packet.  ugh */
    offset = 0;
    i = 1;
    while (offset < size && i < elem.in_num) {
	int len = MIN(elem.in_sg[i].iov_len, size - offset);
	memcpy(elem.in_sg[i].iov_base, buf + offset, len);
	offset += len;
	i++;
    }

    /* signal other side */
    virtqueue_push(n->rx_vq, &elem, sizeof(*hdr) + offset);
    virtio_notify(&n->vdev, n->rx_vq);
}

/* TX */
static void virtio_net_handle_tx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIONet *n = to_virtio_net(vdev);
    VirtQueueElement elem;

    if (!(n->vdev.status & VIRTIO_CONFIG_S_DRIVER_OK))
        return;

    while (virtqueue_pop(vq, &elem)) {
	int i;
	size_t len = 0;

	/* ignore the header for now */
	for (i = 1; i < elem.out_num; i++) {
	    qemu_send_packet(n->vc, elem.out_sg[i].iov_base,
			     elem.out_sg[i].iov_len);
	    len += elem.out_sg[i].iov_len;
	}

	virtqueue_push(vq, &elem, sizeof(struct virtio_net_hdr) + len);
	virtio_notify(&n->vdev, vq);
    }
}

void *virtio_net_init(PCIBus *bus, NICInfo *nd, int devfn)
{
    VirtIONet *n;

    n = (VirtIONet *)virtio_init_pci(bus, "virtio-net", 6900, 0x1000,
				     0, VIRTIO_ID_NET,
				     0x02, 0x00, 0x00,
				     6, sizeof(VirtIONet));

    n->vdev.update_config = virtio_net_update_config;
    n->vdev.get_features = virtio_net_get_features;
    n->rx_vq = virtio_add_queue(&n->vdev, 512, virtio_net_handle_rx);
    n->tx_vq = virtio_add_queue(&n->vdev, 128, virtio_net_handle_tx);
    n->can_receive = 0;
    memcpy(n->mac, nd->macaddr, 6);
    n->vc = qemu_new_vlan_client(nd->vlan, virtio_net_receive,
				 virtio_net_can_receive, n);

    return &n->vdev;
}
