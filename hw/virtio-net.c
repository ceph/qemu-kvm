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
#include "qemu-timer.h"
#include "virtio-net.h"
#include "qemu-kvm.h"

typedef struct VirtIONet
{
    VirtIODevice vdev;
    uint8_t mac[6];
    VirtQueue *rx_vq;
    VirtQueue *tx_vq;
    VLANClientState *vc;
    QEMUTimer *tx_timer;
    int tx_timer_active;
    int mergeable_rx_bufs;
} VirtIONet;

/* TODO
 * - we could suppress RX interrupt if we were so inclined.
 */

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
    VirtIONet *n = to_virtio_net(vdev);
    VLANClientState *host = n->vc->vlan->first_client;
    uint32_t features = (1 << VIRTIO_NET_F_MAC);

    if (tap_has_vnet_hdr(host)) {
        tap_using_vnet_hdr(host, 1);
        features |= (1 << VIRTIO_NET_F_CSUM);
        features |= (1 << VIRTIO_NET_F_GUEST_CSUM);
        features |= (1 << VIRTIO_NET_F_GUEST_TSO4);
        features |= (1 << VIRTIO_NET_F_GUEST_TSO6);
        features |= (1 << VIRTIO_NET_F_GUEST_ECN);
        features |= (1 << VIRTIO_NET_F_HOST_TSO4);
        features |= (1 << VIRTIO_NET_F_HOST_TSO6);
        features |= (1 << VIRTIO_NET_F_HOST_ECN);
        features |= (1 << VIRTIO_NET_F_MRG_RXBUF);
        /* Kernel can't actually handle UFO in software currently. */
    }

    return features;
}

static void virtio_net_set_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIONet *n = to_virtio_net(vdev);
    VLANClientState *host = n->vc->vlan->first_client;

    n->mergeable_rx_bufs = !!(features & (1 << VIRTIO_NET_F_MRG_RXBUF));

    if (!tap_has_vnet_hdr(host) || !host->set_offload)
        return;

    host->set_offload(host,
                      (features >> VIRTIO_NET_F_GUEST_CSUM) & 1,
                      (features >> VIRTIO_NET_F_GUEST_TSO4) & 1,
                      (features >> VIRTIO_NET_F_GUEST_TSO6) & 1,
                      (features >> VIRTIO_NET_F_GUEST_ECN)  & 1);
}

/* RX */

static void virtio_net_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    /* We now have RX buffers, signal to the IO thread to break out of the
       select to re-poll the tap file descriptor */
    if (kvm_enabled())
        qemu_kvm_notify_work();
}

static int virtio_net_can_receive(void *opaque)
{
    VirtIONet *n = opaque;

    if (!virtio_queue_ready(n->rx_vq) ||
        !(n->vdev.status & VIRTIO_CONFIG_S_DRIVER_OK))
        return 0;

    if (virtio_queue_empty(n->rx_vq) ||
        (n->mergeable_rx_bufs &&
         !virtqueue_avail_bytes(n->rx_vq, VIRTIO_NET_MAX_BUFSIZE, 0))) {
        virtio_queue_set_notification(n->rx_vq, 1);
        return 0;
    }

    virtio_queue_set_notification(n->rx_vq, 0);
    return 1;
}

/* dhclient uses AF_PACKET but doesn't pass auxdata to the kernel so
 * it never finds out that the packets don't have valid checksums.  This
 * causes dhclient to get upset.  Fedora's carried a patch for ages to
 * fix this with Xen but it hasn't appeared in an upstream release of
 * dhclient yet.
 *
 * To avoid breaking existing guests, we catch udp packets and add
 * checksums.  This is terrible but it's better than hacking the guest
 * kernels.
 *
 * N.B. if we introduce a zero-copy API, this operation is no longer free so
 * we should provide a mechanism to disable it to avoid polluting the host
 * cache.
 */
static void work_around_broken_dhclient(struct virtio_net_hdr *hdr,
                                        const uint8_t *buf, size_t size)
{
    if ((hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) && /* missing csum */
        (size > 27 && size < 1500) && /* normal sized MTU */
        (buf[12] == 0x08 && buf[13] == 0x00) && /* ethertype == IPv4 */
        (buf[23] == 17) && /* ip.protocol == UDP */
        (buf[34] == 0 && buf[35] == 67)) { /* udp.srcport == bootps */
        /* FIXME this cast is evil */
        net_checksum_calculate((uint8_t *)buf, size);
        hdr->flags &= ~VIRTIO_NET_HDR_F_NEEDS_CSUM;
    }
}

static int iov_fill(struct iovec *iov, int iovcnt, const void *buf, int count)
{
    int offset, i;

    offset = i = 0;
    while (offset < count && i < iovcnt) {
        int len = MIN(iov[i].iov_len, count - offset);
        memcpy(iov[i].iov_base, buf + offset, len);
        offset += len;
        i++;
    }

    return offset;
}

static int receive_header(VirtIONet *n, struct iovec *iov, int iovcnt,
                          const void *buf, int size, int hdr_len)
{
    struct virtio_net_hdr *hdr = iov[0].iov_base;
    int offset;

    hdr->flags = 0;
    hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;

    if (tap_has_vnet_hdr(n->vc->vlan->first_client)) {
        memcpy(hdr, buf, sizeof(*hdr));
        offset = sizeof(*hdr);
        work_around_broken_dhclient(hdr, buf + offset, size - offset);
    }

    /* We only ever receive a struct virtio_net_hdr from the tapfd,
     * but we may be passing along a larger header to the guest.
     */
    iov[0].iov_base += hdr_len;
    iov[0].iov_len  -= hdr_len;

    return offset;
}

static void virtio_net_receive(void *opaque, const uint8_t *buf, int size)
{
    VirtIONet *n = opaque;
    struct virtio_net_hdr_mrg_rxbuf *mhdr = NULL;
    int hdr_len, offset, i;

    /* hdr_len refers to the header we supply to the guest */
    hdr_len = n->mergeable_rx_bufs ?
        sizeof(struct virtio_net_hdr_mrg_rxbuf) : sizeof(struct virtio_net_hdr);

    offset = i = 0;

    while (offset < size) {
        VirtQueueElement elem;
        int len, total;
        struct iovec sg[VIRTQUEUE_MAX_SIZE];

        len = total = 0;

        if ((i != 0 && !n->mergeable_rx_bufs) ||
            virtqueue_pop(n->rx_vq, &elem) == 0) {
            if (i == 0)
                return;
            fprintf(stderr, "virtio-net truncating packet\n");
            exit(1);
        }

        if (elem.in_num < 1) {
            fprintf(stderr, "virtio-net receive queue contains no in buffers\n");
            exit(1);
        }

        if (!n->mergeable_rx_bufs && elem.in_sg[0].iov_len != hdr_len) {
            fprintf(stderr, "virtio-net header not in first element\n");
            exit(1);
        }

        memcpy(&sg, &elem.in_sg[0], sizeof(sg[0]) * elem.in_num);

        if (i == 0) {
            if (n->mergeable_rx_bufs)
                mhdr = (struct virtio_net_hdr_mrg_rxbuf *)sg[0].iov_base;

            offset += receive_header(n, sg, elem.in_num,
                                     buf + offset, size - offset, hdr_len);
            total += hdr_len;
        }

        /* copy in packet.  ugh */
        len = iov_fill(sg, elem.in_num,
                       buf + offset, size - offset);
        total += len;

        /* signal other side */
        virtqueue_fill(n->rx_vq, &elem, total, i++);

        offset += len;
    }

    if (mhdr)
        mhdr->num_buffers = i;

    virtqueue_flush(n->rx_vq, i);
    virtio_notify(&n->vdev, n->rx_vq);
}

/* TX */
static void virtio_net_flush_tx(VirtIONet *n, VirtQueue *vq)
{
    VirtQueueElement elem;
    int has_vnet_hdr = tap_has_vnet_hdr(n->vc->vlan->first_client);

    if (!(n->vdev.status & VIRTIO_CONFIG_S_DRIVER_OK))
        return;

    while (virtqueue_pop(vq, &elem)) {
        ssize_t len = 0;
        unsigned int out_num = elem.out_num;
        struct iovec *out_sg = &elem.out_sg[0];
        unsigned hdr_len;

        /* hdr_len refers to the header received from the guest */
        hdr_len = n->mergeable_rx_bufs ?
            sizeof(struct virtio_net_hdr_mrg_rxbuf) :
            sizeof(struct virtio_net_hdr);

        if (out_num < 1 || out_sg->iov_len != hdr_len) {
            fprintf(stderr, "virtio-net header not in first element\n");
            exit(1);
        }

        /* ignore the header if GSO is not supported */
        if (!has_vnet_hdr) {
            out_num--;
            out_sg++;
            len += hdr_len;
        } else if (n->mergeable_rx_bufs) {
            /* tapfd expects a struct virtio_net_hdr */
            hdr_len -= sizeof(struct virtio_net_hdr);
            out_sg->iov_len -= hdr_len;
            len += hdr_len;
        }

        len += qemu_sendv_packet(n->vc, out_sg, out_num);

        virtqueue_push(vq, &elem, len);
        virtio_notify(&n->vdev, vq);
    }
}

static void virtio_net_handle_tx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIONet *n = to_virtio_net(vdev);

    if (n->tx_timer_active) {
        virtio_queue_set_notification(vq, 1);
        qemu_del_timer(n->tx_timer);
        n->tx_timer_active = 0;
        virtio_net_flush_tx(n, vq);
    } else {
        qemu_mod_timer(n->tx_timer,
                       qemu_get_clock(vm_clock) + TX_TIMER_INTERVAL);
        n->tx_timer_active = 1;
        virtio_queue_set_notification(vq, 0);
    }
}

static void virtio_net_tx_timer(void *opaque)
{
    VirtIONet *n = opaque;

    n->tx_timer_active = 0;

    /* Just in case the driver is not ready on more */
    if (!(n->vdev.status & VIRTIO_CONFIG_S_DRIVER_OK))
        return;

    virtio_queue_set_notification(n->tx_vq, 1);
    virtio_net_flush_tx(n, n->tx_vq);
}

static void virtio_net_save(QEMUFile *f, void *opaque)
{
    VirtIONet *n = opaque;

    virtio_save(&n->vdev, f);

    qemu_put_buffer(f, n->mac, 6);
    qemu_put_be32(f, n->tx_timer_active);
}

static int virtio_net_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIONet *n = opaque;

    if (version_id != 1)
        return -EINVAL;

    virtio_load(&n->vdev, f);

    qemu_get_buffer(f, n->mac, 6);
    n->tx_timer_active = qemu_get_be32(f);

    if (n->tx_timer_active) {
        qemu_mod_timer(n->tx_timer,
                       qemu_get_clock(vm_clock) + TX_TIMER_INTERVAL);
    }

    return 0;
}

PCIDevice *virtio_net_init(PCIBus *bus, NICInfo *nd, int devfn)
{
    VirtIONet *n;
    static int virtio_net_id;

    n = (VirtIONet *)virtio_init_pci(bus, "virtio-net", 6900, 0x1000,
                                     0, VIRTIO_ID_NET,
                                     0x02, 0x00, 0x00,
                                     6, sizeof(VirtIONet));
    if (!n)
        return NULL;

    n->vdev.get_config = virtio_net_update_config;
    n->vdev.get_features = virtio_net_get_features;
    n->vdev.set_features = virtio_net_set_features;
    n->rx_vq = virtio_add_queue(&n->vdev, 256, virtio_net_handle_rx);
    n->tx_vq = virtio_add_queue(&n->vdev, 256, virtio_net_handle_tx);
    memcpy(n->mac, nd->macaddr, 6);
    n->vc = qemu_new_vlan_client(nd->vlan, virtio_net_receive,
                                 virtio_net_can_receive, n);

    n->tx_timer = qemu_new_timer(vm_clock, virtio_net_tx_timer, n);
    n->tx_timer_active = 0;
    n->mergeable_rx_bufs = 0;

    register_savevm("virtio-net", virtio_net_id++, 1,
                    virtio_net_save, virtio_net_load, n);

    return (PCIDevice *)n;
}
