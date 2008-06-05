/*
 * Virtio Block Device
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
#include "block.h"
#include "block_int.h"
#include "pc.h"

/* from Linux's linux/virtio_blk.h */

/* The ID for virtio_block */
#define VIRTIO_ID_BLOCK	2

/* Feature bits */
#define VIRTIO_BLK_F_BARRIER	0	/* Does host support barriers? */
#define VIRTIO_BLK_F_SIZE_MAX	1	/* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX	2	/* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY	4	/* Indicates support of legacy geometry */

struct virtio_blk_config
{
    uint64_t capacity;
    uint32_t size_max;
    uint32_t seg_max;
    uint16_t cylinders;
    uint8_t heads;
    uint8_t sectors;
} __attribute__((packed));

/* These two define direction. */
#define VIRTIO_BLK_T_IN		0
#define VIRTIO_BLK_T_OUT	1

/* This bit says it's a scsi command, not an actual read or write. */
#define VIRTIO_BLK_T_SCSI_CMD	2

/* Barrier before this op. */
#define VIRTIO_BLK_T_BARRIER	0x80000000

/* This is the first element of the read scatter-gather list. */
struct virtio_blk_outhdr
{
    /* VIRTIO_BLK_T* */
    uint32_t type;
    /* io priority. */
    uint32_t ioprio;
    /* Sector (ie. 512 byte offset) */
    uint64_t sector;
};

#define VIRTIO_BLK_S_OK		0
#define VIRTIO_BLK_S_IOERR	1
#define VIRTIO_BLK_S_UNSUPP	2

/* This is the first element of the write scatter-gather list */
struct virtio_blk_inhdr
{
    unsigned char status;
};

typedef struct VirtIOBlock
{
    VirtIODevice vdev;
    BlockDriverState *bs;
} VirtIOBlock;

static VirtIOBlock *to_virtio_blk(VirtIODevice *vdev)
{
    return (VirtIOBlock *)vdev;
}

typedef struct VirtIOBlockReq
{
    VirtIODevice *vdev;
    VirtQueue *vq;
    struct iovec in_sg_status;
    unsigned int pending;
    unsigned int len;
    unsigned int elem_idx;
    int status;
} VirtIOBlockReq;

static void virtio_blk_rw_complete(void *opaque, int ret)
{
    VirtIOBlockReq *req = opaque;
    struct virtio_blk_inhdr *in;
    VirtQueueElement elem;

    req->status |= ret;
    if (--req->pending > 0)
        return;

    elem.index = req->elem_idx;
    in = (void *)req->in_sg_status.iov_base;

    in->status = req->status ? VIRTIO_BLK_S_IOERR : VIRTIO_BLK_S_OK;
    virtqueue_push(req->vq, &elem, req->len);
    virtio_notify(req->vdev, req->vq);
    qemu_free(req);
}

static void virtio_blk_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOBlock *s = to_virtio_blk(vdev);
    VirtQueueElement elem;
    VirtIOBlockReq *req;
    unsigned int count;

    while ((count = virtqueue_pop(vq, &elem)) != 0) {
	struct virtio_blk_inhdr *in;
	struct virtio_blk_outhdr *out;
	off_t off;
	int i;

	if (elem.out_num < 1 || elem.in_num < 1) {
	    fprintf(stderr, "virtio-blk missing headers\n");
	    exit(1);
	}

	if (elem.out_sg[0].iov_len != sizeof(*out) ||
	    elem.in_sg[elem.in_num - 1].iov_len != sizeof(*in)) {
	    fprintf(stderr, "virtio-blk header not in correct element\n");
	    exit(1);
	}

	/*
	 * FIXME: limit the number of in-flight requests
	 */
	req = qemu_malloc(sizeof(VirtIOBlockReq));
	if (!req)
	    return;
	memset(req, 0, sizeof(*req));
	memcpy(&req->in_sg_status, &elem.in_sg[elem.in_num - 1],
	       sizeof(req->in_sg_status));
	req->vdev = vdev;
	req->vq = vq;
	req->elem_idx = elem.index;

	out = (void *)elem.out_sg[0].iov_base;
	in = (void *)elem.in_sg[elem.in_num - 1].iov_base;
	off = out->sector;

	if (out->type & VIRTIO_BLK_T_SCSI_CMD) {
	    unsigned int len = sizeof(*in);

	    in->status = VIRTIO_BLK_S_UNSUPP;
	    virtqueue_push(vq, &elem, len);
	    virtio_notify(vdev, vq);
	    qemu_free(req);
	} else if (out->type & VIRTIO_BLK_T_OUT) {
	    req->pending = elem.out_num - 1;

	    for (i = 1; i < elem.out_num; i++) {
		req->len += elem.out_sg[i].iov_len;
		bdrv_aio_write(s->bs, off,
			   elem.out_sg[i].iov_base,
			   elem.out_sg[i].iov_len / 512,
			   virtio_blk_rw_complete,
			   req);
		off += elem.out_sg[i].iov_len / 512;
	    }
	} else {
	    req->pending = elem.in_num - 1;

	    for (i = 0; i < elem.in_num - 1; i++) {
		req->len += elem.in_sg[i].iov_len;
		bdrv_aio_read(s->bs, off,
			  elem.in_sg[i].iov_base,
			  elem.in_sg[i].iov_len / 512,
			  virtio_blk_rw_complete,
			  req);
		off += elem.in_sg[i].iov_len / 512;
	    }
	}
    }
    /*
     * FIXME: Want to check for completions before returning to guest mode,
     * so cached reads and writes are reported as quickly as possible. But
     * that should be done in the generic block layer.
     */
}

static void virtio_blk_reset(VirtIODevice *vdev)
{
    VirtIOBlock *s = to_virtio_blk(vdev);

    /*
     * This should cancel pending requests, but can't do nicely until there
     * are per-device request lists.
     */
    qemu_aio_flush();
}

static void virtio_blk_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOBlock *s = to_virtio_blk(vdev);
    struct virtio_blk_config blkcfg;
    int64_t capacity;
    int cylinders, heads, secs;

    bdrv_get_geometry(s->bs, &capacity);
    bdrv_get_geometry_hint(s->bs, &cylinders, &heads, &secs);
    blkcfg.capacity = cpu_to_le64(capacity);
    blkcfg.seg_max = cpu_to_le32(128 - 2);
    blkcfg.cylinders = cpu_to_le16(cylinders);
    blkcfg.heads = heads;
    blkcfg.sectors = secs;
    memcpy(config, &blkcfg, sizeof(blkcfg));
}

static uint32_t virtio_blk_get_features(VirtIODevice *vdev)
{
    return (1 << VIRTIO_BLK_F_SEG_MAX | 1 << VIRTIO_BLK_F_GEOMETRY);
}

static void virtio_blk_save(QEMUFile *f, void *opaque)
{
    VirtIOBlock *s = opaque;
    virtio_save(&s->vdev, f);
}

static int virtio_blk_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIOBlock *s = opaque;

    if (version_id != 1)
	return -EINVAL;

    virtio_load(&s->vdev, f);

    return 0;
}

void *virtio_blk_init(PCIBus *bus, uint16_t vendor, uint16_t device,
		      BlockDriverState *bs)
{
    VirtIOBlock *s;
    int cylinders, heads, secs;
    static int virtio_blk_id;

    s = (VirtIOBlock *)virtio_init_pci(bus, "virtio-blk", vendor, device,
				       0, VIRTIO_ID_BLOCK,
				       0x01, 0x80, 0x00,
				       sizeof(struct virtio_blk_config), sizeof(VirtIOBlock));
    if (!s)
	return NULL;

    s->vdev.update_config = virtio_blk_update_config;
    s->vdev.get_features = virtio_blk_get_features;
    s->vdev.reset = virtio_blk_reset;
    s->bs = bs;
    bs->devfn = s->vdev.pci_dev.devfn;
    bdrv_guess_geometry(s->bs, &cylinders, &heads, &secs);
    bdrv_set_geometry_hint(s->bs, cylinders, heads, secs);

    virtio_add_queue(&s->vdev, 128, virtio_blk_handle_output);

    register_savevm("virtio-blk", virtio_blk_id++, 1,
		    virtio_blk_save, virtio_blk_load, s);

    return s;
}
