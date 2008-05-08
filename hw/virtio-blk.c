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

static void virtio_blk_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOBlock *s = to_virtio_blk(vdev);
    VirtQueueElement elem;
    unsigned int count;

    while ((count = virtqueue_pop(vq, &elem)) != 0) {
	struct virtio_blk_inhdr *in;
	struct virtio_blk_outhdr *out;
	unsigned int wlen;
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

	out = (void *)elem.out_sg[0].iov_base;
	in = (void *)elem.in_sg[elem.in_num - 1].iov_base;
	off = out->sector;

	if (out->type & VIRTIO_BLK_T_SCSI_CMD) {
	    wlen = sizeof(*in);
	    in->status = VIRTIO_BLK_S_UNSUPP;
	} else if (out->type & VIRTIO_BLK_T_OUT) {
	    wlen = sizeof(*in);

	    for (i = 1; i < elem.out_num; i++) {
		bdrv_write(s->bs, off,
			   elem.out_sg[i].iov_base,
			   elem.out_sg[i].iov_len / 512);
		off += elem.out_sg[i].iov_len / 512;
	    }

	    in->status = VIRTIO_BLK_S_OK;
	} else {
	    wlen = sizeof(*in);

	    for (i = 0; i < elem.in_num - 1; i++) {
		bdrv_read(s->bs, off,
			  elem.in_sg[i].iov_base,
			  elem.in_sg[i].iov_len / 512);
		off += elem.in_sg[i].iov_len / 512;
		wlen += elem.in_sg[i].iov_len;
	    }

	    in->status = VIRTIO_BLK_S_OK;
	}

	virtqueue_push(vq, &elem, wlen);
	virtio_notify(vdev, vq);
    }
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
    s->bs = bs;
    bs->devfn = s->vdev.pci_dev.devfn;
    bdrv_guess_geometry(s->bs, &cylinders, &heads, &secs);
    bdrv_set_geometry_hint(s->bs, cylinders, heads, secs);

    virtio_add_queue(&s->vdev, 128, virtio_blk_handle_output);

    register_savevm("virtio-blk", virtio_blk_id++, 1,
		    virtio_blk_save, virtio_blk_load, s);

    return s;
}
