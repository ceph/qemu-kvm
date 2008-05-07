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
#include "qemu-timer.h"

/* from Linux's virtio_net.h */

/* The ID for virtio_net */
#define VIRTIO_ID_NET	1

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_NO_CSUM	0
#define VIRTIO_NET_F_MAC	5
#define VIRTIO_NET_F_GS0	6

#define TX_TIMER_INTERVAL (1000 / 500)

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
#define VIRTIO_NET_HDR_GSO_ECN		0x80	// TCP has ECN set
    uint8_t gso_type;
    uint16_t hdr_len;
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
    int tap_fd;
    struct VirtIONet *next;
    int do_notify;
    QEMUTimer *tx_timer;
    int tx_timer_active;
} VirtIONet;

static VirtIONet *VirtIONetHead = NULL;

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

/* -net user receive function */
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

    if (elem.in_num < 1 || elem.in_sg[0].iov_len != sizeof(*hdr)) {
	fprintf(stderr, "virtio-net header not in first element\n");
	exit(1);
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

/* -net tap receive handler */
void virtio_net_poll(void)
{
    VirtIONet *vnet;
    int len;
    fd_set rfds;
    struct timeval tv;
    int max_fd = -1;
    VirtQueueElement elem;
    struct virtio_net_hdr *hdr;
    int did_notify;

    FD_ZERO(&rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    while (1) {

        // Prepare the set of device to select from
        for (vnet = VirtIONetHead; vnet; vnet = vnet->next) {

            if (vnet->tap_fd == -1)
                continue;

            vnet->do_notify = 0;
            //first check if the driver is ok
            if (!virtio_net_can_receive(vnet))
                continue;

            /* FIXME: the drivers really need to set their status better */
            if (vnet->rx_vq->vring.avail == NULL) {
                vnet->can_receive = 0;
                continue;
            }

            FD_SET(vnet->tap_fd, &rfds);
            if (max_fd < vnet->tap_fd) max_fd = vnet->tap_fd;
        }

        if (select(max_fd + 1, &rfds, NULL, NULL, &tv) <= 0)
            break;

        // Now check who has data pending in the tap
        for (vnet = VirtIONetHead; vnet; vnet = vnet->next) {

            if (!FD_ISSET(vnet->tap_fd, &rfds))
                continue;

            if (virtqueue_pop(vnet->rx_vq, &elem) == 0) {
                vnet->can_receive = 0;
                continue;
            }

	    if (elem.in_num < 1 || elem.in_sg[0].iov_len != sizeof(*hdr)) {
		fprintf(stderr, "virtio-net header not in first element\n");
		exit(1);
	    }

            hdr = (void *)elem.in_sg[0].iov_base;
            hdr->flags = 0;
            hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
again:
            len = readv(vnet->tap_fd, &elem.in_sg[1], elem.in_num - 1);
            if (len == -1) {
                if (errno == EINTR || errno == EAGAIN)
                    goto again;
                else
                    fprintf(stderr, "reading network error %d", len);
            }
            virtqueue_push(vnet->rx_vq, &elem, sizeof(*hdr) + len);
            vnet->do_notify = 1;
        }

        /* signal other side */
        did_notify = 0;
        for (vnet = VirtIONetHead; vnet; vnet = vnet->next)
            if (vnet->do_notify) {
                virtio_notify(&vnet->vdev, vnet->rx_vq);
                did_notify++;
            }
        if (!did_notify)
            break;
     }

}

/* TX */
static void virtio_net_flush_tx(VirtIONet *n, VirtQueue *vq)
{
    VirtQueueElement elem;
    int count = 0;

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

	count++;

	virtqueue_push(vq, &elem, sizeof(struct virtio_net_hdr) + len);
	virtio_notify(&n->vdev, vq);
    }
}

static void virtio_net_handle_tx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIONet *n = to_virtio_net(vdev);

    if (n->tx_timer_active &&
	(vq->vring.avail->idx - vq->last_avail_idx) == 64) {
	vq->vring.used->flags &= ~VRING_USED_F_NO_NOTIFY;
	qemu_del_timer(n->tx_timer);
	n->tx_timer_active = 0;
	virtio_net_flush_tx(n, vq);
    } else {
	qemu_mod_timer(n->tx_timer,
		       qemu_get_clock(vm_clock) + TX_TIMER_INTERVAL);
	n->tx_timer_active = 1;
	vq->vring.used->flags |= VRING_USED_F_NO_NOTIFY;
    }
}

static void virtio_net_tx_timer(void *opaque)
{
    VirtIONet *n = opaque;

    n->tx_timer_active = 0;

    /* Just in case the driver is not ready on more */
    if (!(n->vdev.status & VIRTIO_CONFIG_S_DRIVER_OK))
        return;

    n->tx_vq->vring.used->flags &= ~VRING_USED_F_NO_NOTIFY;
    virtio_net_flush_tx(n, n->tx_vq);
}

PCIDevice *virtio_net_init(PCIBus *bus, NICInfo *nd, int devfn)
{
    VirtIONet *n;

    n = (VirtIONet *)virtio_init_pci(bus, "virtio-net", 6900, 0x1000,
				     0, VIRTIO_ID_NET,
				     0x02, 0x00, 0x00,
				     6, sizeof(VirtIONet));
    if (!n)
	return NULL;

    n->vdev.update_config = virtio_net_update_config;
    n->vdev.get_features = virtio_net_get_features;
    n->rx_vq = virtio_add_queue(&n->vdev, 512, virtio_net_handle_rx);
    n->tx_vq = virtio_add_queue(&n->vdev, 128, virtio_net_handle_tx);
    n->can_receive = 0;
    memcpy(n->mac, nd->macaddr, 6);
    n->vc = qemu_new_vlan_client(nd->vlan, virtio_net_receive,
                                 virtio_net_can_receive, n);
    n->tap_fd = hack_around_tap(n->vc->vlan->first_client);
    if (n->tap_fd != -1) {
        n->next = VirtIONetHead;
        //push the device on top of the list
        VirtIONetHead = n;
    }

    n->tx_timer = qemu_new_timer(vm_clock, virtio_net_tx_timer, n);
    n->tx_timer_active = 0;

    return (PCIDevice *)n;
}
