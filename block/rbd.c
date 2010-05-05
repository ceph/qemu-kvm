/*
 * QEMU Block driver for RADOS (Ceph)
 *
 * Copyright (C) 2010 Christian Brunner <chb@muc.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include <sys/types.h>
#include <stdbool.h>

#include <qemu-common.h>

#include "rbd_types.h"
#include "rados.h"
#include "module.h"
#include "block_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <rados/librados.h>

#include <signal.h>

/*
 * When specifying the image filename use:
 *
 * rbd:poolname/devicename
 *
 * poolname must be the name of an existing rados pool
 *
 * devicename is the basename for all objects used to
 * emulate the raw device.
 *
 * Metadata information (image size, ...) is stored in an 
 * object with the name "devicename.rbd".
 *
 * The raw device is split into 4MB sized objects by default.
 * The sequencenumber is encoded in a 12 byte long hex-string,
 * and is attached to the devicename, separated by a dot.
 * e.g. "devicename.1234567890ab"
 *
 */

#define OBJ_MAX_SIZE (1UL << OBJ_DEFAULT_OBJ_ORDER)

typedef struct RBDAIOCB {
        BlockDriverAIOCB common;
        QEMUBH *bh;
        int ret;
        QEMUIOVector *qiov;
        char *bounce;
        int write;
        int64_t sector_num;
        int aiocnt;
	int rccomplete;
} RBDAIOCB;

typedef struct RADOSCB {
        int rcbid;
        RBDAIOCB *acb;
        int done;
        int64_t segsize;
        char *buf;
} RADOSCB;

typedef struct RBDRVRBDState {
	rados_pool_t pool;
	char name[RBD_MAX_OBJ_NAME_SIZE];
	int name_len;
	uint64_t size;
	uint64_t objsize;
} RBDRVRBDState;
	
typedef struct rbd_obj_header_ondisk RbdHeader1;

static int rbd_parsename(const char *filename, char *pool, char *name) {
	const char *rbdname;
	char *p, *n;
	int l;

	if(!strstart(filename, "rbd:", &rbdname)) {
		return -EINVAL;
	}
		
	pstrcpy(pool, 2*RBD_MAX_SEG_NAME_SIZE, rbdname);
	p = strchr(pool, '/');
	if (p == NULL) {
		return -EINVAL;
	}

	*p = '\0';
	n = ++p;

	l = strlen(n);

	if (l > RBD_MAX_OBJ_NAME_SIZE) {
		fprintf(stderr, "object name to long\n");
		return -EINVAL;
	} else if (l <= 0) {
		fprintf(stderr, "object name to short\n");
		return -EINVAL;
	}

	strcpy(name, n);

	return l;
}

static int create_tmap_op(uint8_t op, const char *name, char **tmap_desc)
{
	uint32_t len = strlen(name);
	uint32_t total_len = 1 + (sizeof(uint32_t) + len) + sizeof(uint32_t); /* encoding op + name + empty buffer */
	char *desc;

	desc = malloc(total_len);
	if (!desc)
		return -ENOMEM;

	*tmap_desc = desc;

	*desc = op;
	desc++;
	memcpy(desc, &len, sizeof(len));
	desc += sizeof(len);
	memcpy(desc, name, len);
	desc += len;
	len = 0;
	memcpy(desc, &len, sizeof(len));
	desc += sizeof(len);

	return desc - *tmap_desc;
}

static void free_tmap_op(char *tmap_desc)
{
	free(tmap_desc);
}

static int rbd_register_image(rados_pool_t pool, const char *name)
{
	char *tmap_desc;
	const char *dir = RBD_DIRECTORY;
	int ret;

	ret = create_tmap_op(CEPH_OSD_TMAP_SET, name, &tmap_desc);
	if (ret < 0)
		return ret;

	ret = rados_tmap_update(pool, dir, tmap_desc, ret);
	free_tmap_op(tmap_desc);

	return ret;
}

static int rbd_create(const char *filename, QEMUOptionParameter *options) {
	int64_t bytes = 0;
	int64_t objsize;
	uint8_t obj_order = RBD_DEFAULT_OBJ_ORDER;
	char pool[RBD_MAX_SEG_NAME_SIZE];
	char n[RBD_MAX_SEG_NAME_SIZE];
	char name[RBD_MAX_SEG_NAME_SIZE];
	RbdHeader1 header;
	rados_pool_t p;
	int name_len;
	int ret;

	if ((name_len = rbd_parsename(filename, pool, name)) < 0) {
		return -EINVAL;
	}

	snprintf(n, RBD_MAX_SEG_NAME_SIZE, "%s%s", name, RBD_SUFFIX);

	/* Read out options */
	while (options && options->name) {
		if (!strcmp(options->name, BLOCK_OPT_SIZE)) {
			bytes = options->value.n;
		} else if (!strcmp(options->name, BLOCK_OPT_CLUSTER_SIZE)) {
			if (options->value.n) {
				objsize = options->value.n;
				if (!objsize || ((objsize - 1) & objsize)) { /* not a power of 2? */
					fprintf(stderr, "obj size needs to be power of 2\n");
					return -EINVAL;	
				}
				if (objsize < 4096) {
					fprintf(stderr, "obj size too small\n");
					return -EINVAL;
				}

				for (obj_order=0; obj_order<64; obj_order++) {
					if (objsize == 1)
						break;
					objsize >>= 1;
				}
			}
		}
		options++;
	}

	memset(&header, 0, sizeof(header));
	pstrcpy(header.text, sizeof(header.text), rbd_text);
	pstrcpy(header.signature, sizeof(header.signature), rbd_signature);
	pstrcpy(header.version, sizeof(header.version), rbd_version);
	header.image_size = bytes;
	cpu_to_le64s((uint64_t *)&header.image_size);
	header.obj_order = obj_order;
	header.crypt_type = RBD_CRYPT_NONE;
	header.comp_type = RBD_COMP_NONE;
	header.snap_seq = 0;
	header.snap_count = 0;
	cpu_to_le32s(&header.snap_count);

        if (rados_initialize(0, NULL) < 0) {
                fprintf(stderr, "error initializing\n");
		return -EIO;
        }

	if (rados_open_pool(pool, &p)) {
                fprintf(stderr, "error opening pool %s\n", pool);
		return -EIO;
	}

	ret = rados_write(p, n, 0, (const char *) &header, sizeof(header));
	if (ret < 0)
		goto done;

	ret = rbd_register_image(p, name);
done:
	rados_close_pool(p);
	rados_deinitialize();

	return ret;
}

static int rbd_open(BlockDriverState *bs, const char *filename, int flags) {
	RBDRVRBDState *s = bs->opaque;
	char pool[RBD_MAX_SEG_NAME_SIZE];
	char n[RBD_MAX_SEG_NAME_SIZE];
	char hbuf[4096];

	if ((s->name_len = rbd_parsename(filename, pool, s->name)) < 0) {
		return -EINVAL;
	}
	snprintf(n, RBD_MAX_SEG_NAME_SIZE, "%s%s", s->name, RBD_SUFFIX);
	
        if (rados_initialize(0, NULL) < 0) {
                fprintf(stderr, "error initializing\n");
		return -EIO;
        }

	if (rados_open_pool(pool, &s->pool)) {
                fprintf(stderr, "error opening pool %s\n", pool);
		return -EIO;
	}

	if (rados_read(s->pool, n, 0, hbuf, 4096) < 0) {
                fprintf(stderr, "error reading header from %s\n", s->name);
		return -EIO;
	}
	if (!strncmp(hbuf+64, rbd_signature, 4)) {
		if(!strncmp(hbuf+68, rbd_version, 8)) {
			RbdHeader1 *header;

			header = (RbdHeader1 *) hbuf;
			le64_to_cpus((uint64_t *)&header->image_size);
			s->size = header->image_size;
			s->objsize = 1 << header->obj_order;
		} else {
                	fprintf(stderr, "Unknown image version %s\n", hbuf+68);
			return -EIO;
		}
	} else {
                fprintf(stderr, "Invalid header signature %s\n", hbuf+64);
		return -EIO;
	}

	return 0;
}

static void rbd_close(BlockDriverState *bs) {
	RBDRVRBDState *s = bs->opaque;

	rados_close_pool(s->pool);
	rados_deinitialize();
}

static int rbd_write(BlockDriverState *bs, int64_t sector_num, 
		const uint8_t *buf, int nb_sectors) {
	RBDRVRBDState *s = bs->opaque;
	char n[RBD_MAX_SEG_NAME_SIZE];

	int64_t segnr, segoffs, segsize;
	int64_t off, size;

	off = sector_num * 512;
	size = nb_sectors * 512;
	segnr = (int64_t) (off / s->objsize);
	segoffs = (int64_t) (off % s->objsize);
	segsize  = (int64_t) (s->objsize - segoffs);

	while (size > 0) {
		if (size < segsize) {
			segsize = size;
		}

		snprintf(n, RBD_MAX_SEG_NAME_SIZE, "%s.%012llx", s->name, (long long unsigned int) segnr);

		if (rados_write(s->pool, n, segoffs, (const char *) buf, segsize) < 0) {
			return -errno;
		}

		buf += segsize;
		size -= segsize;
		segoffs = 0;
		segsize = s->objsize;
		segnr++;
	}

	return(0);
}

static int rbd_read(BlockDriverState *bs, int64_t sector_num, 
		uint8_t *buf, int nb_sectors) {
	RBDRVRBDState *s = bs->opaque;
	char n[RBD_MAX_SEG_NAME_SIZE];

	int64_t segnr, segoffs, segsize, r;
	int64_t off, size;

	off = sector_num * 512;
	size = nb_sectors * 512;
	segnr = (int64_t) (off / s->objsize);
	segoffs = (int64_t) (off % s->objsize);
	segsize  = (int64_t) (s->objsize - segoffs);

	while (size > 0) {
		if (size < segsize) {
			segsize = size;
		}

		snprintf(n, RBD_MAX_SEG_NAME_SIZE, "%s.%012llx", s->name, (long long unsigned int) segnr);

		r = rados_read(s->pool, n, segoffs, (char *) buf, segsize);
		if (r < 0) {
			memset(buf, 0, segsize);
		} else if (r < segsize) {
			memset(buf+r, 0, segsize-r);
		}

		buf += segsize;
		size -= segsize;
		segoffs = 0;
		segsize = s->objsize;
		segnr++;
	}

	return(0);
}

static void rbd_aio_cancel(BlockDriverAIOCB *blockacb)
{
    RBDAIOCB *acb = (RBDAIOCB *)blockacb;
    qemu_bh_delete(acb->bh);
    acb->bh = NULL;
    qemu_aio_release(acb);
}

static AIOPool rbd_aio_pool = 
{
    .aiocb_size         = sizeof(RBDAIOCB),
    .cancel             = rbd_aio_cancel,
};

static void rbd_finish_aiocb(rados_completion_t c, RADOSCB *rcb) 
{
    RBDAIOCB *acb = rcb->acb;
    int64_t r;
    int i;

    if (rados_aio_is_complete(c)) {
        acb->aiocnt--;
        r = rados_aio_get_return_value(c);
        rados_aio_set_callback(c, NULL, NULL);
        rados_aio_release(c);
        if (acb->write) {
            acb->ret += r;
        } else {
            if (r < 0) {
                memset(rcb->buf, 0, rcb->segsize);
                acb->ret += rcb->segsize;
            } else if (r < rcb->segsize) {
                memset(rcb->buf+r, 0, rcb->segsize-r);
                acb->ret += rcb->segsize;
            } else {
                acb->ret += r;
            }
        }
        qemu_free(rcb);
        i=0;
        while ((acb->aiocnt == 0) && !acb->rccomplete && i<5) {
	    usleep(100);
            i++;
        }
        if ((acb->aiocnt == 0) && acb->rccomplete && acb->bh) {
            qemu_bh_schedule(acb->bh);
	}
    }
}
            
static void rbd_aio_bh_cb(void *opaque) 
{
    RBDAIOCB *acb = opaque;

    if (!acb->write) {
        qemu_iovec_from_buffer(acb->qiov, acb->bounce, acb->qiov->size);
    }
    qemu_vfree(acb->bounce);
    acb->common.cb(acb->common.opaque, acb->ret);
    qemu_bh_delete(acb->bh);
    acb->bh = NULL;
    qemu_aio_release(acb);
}

static BlockDriverAIOCB *rbd_aio_rw_vector(BlockDriverState *bs,
                                           int64_t sector_num,
                                           QEMUIOVector *qiov,
                                           int nb_sectors,
                                           BlockDriverCompletionFunc *cb,
                                           void *opaque,
                                           int write)
{
    RBDAIOCB *acb;
    RADOSCB *rcb;
    rados_completion_t c;
    char n[RBD_MAX_SEG_NAME_SIZE];
    int64_t segnr, segoffs, segsize;
    int64_t off, size;
    char *buf;

    RBDRVRBDState *s = bs->opaque;

    acb = qemu_aio_get(&rbd_aio_pool, bs, cb, opaque);
    acb->write = write;
    acb->qiov = qiov;
    acb->bounce = qemu_blockalign(bs, qiov->size);
    acb->aiocnt=0;
    acb->ret=0;
    acb->rccomplete=0;

    if (!acb->bh) {
        acb->bh = qemu_bh_new(rbd_aio_bh_cb, acb);
    }

    if (write) {
        qemu_iovec_to_buffer(acb->qiov, acb->bounce);
    }

    buf = acb->bounce;

    off = sector_num * 512;
    size = nb_sectors * 512;
    segnr = (int64_t) (off / s->objsize);
    segoffs = (int64_t) (off % s->objsize);
    segsize  = (int64_t) (s->objsize - segoffs);

    while (size > 0) {
        if (size < segsize) {
            segsize = size;
        }

        snprintf(n, RBD_MAX_SEG_NAME_SIZE, "%s.%012llx", s->name, (long long unsigned int) segnr);

        rcb = qemu_malloc(sizeof(RADOSCB));
        rcb->done = 0;
        rcb->acb = acb;
        rcb->segsize = segsize;
        rcb->buf = buf;

        acb->aiocnt++;

        rados_aio_create_completion((rados_callback_t) rbd_finish_aiocb, rcb, &c);
        if (write) {
            rados_aio_write(s->pool, n, segoffs, buf , segsize, c);
	} else {
            rados_aio_read(s->pool, n, segoffs, buf , segsize, c);
	}

        buf += segsize;
        size -= segsize;
        segoffs = 0;
        segsize = s->objsize;
        segnr++;
    }

    acb->rccomplete=1;

    return &acb->common;
}


static BlockDriverAIOCB *rbd_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return rbd_aio_rw_vector(bs, sector_num, qiov, nb_sectors, cb, opaque, 0);
}

static BlockDriverAIOCB *rbd_aio_writev(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return rbd_aio_rw_vector(bs, sector_num, qiov, nb_sectors, cb, opaque, 1);
}


static int rbd_getinfo(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    RBDRVRBDState *s = bs->opaque;
    bdi->cluster_size = s->objsize;
    return 0;
}

static int64_t rbd_getlength(BlockDriverState *bs) {
	RBDRVRBDState *s = bs->opaque;

	return s->size;
}


static QEMUOptionParameter rbd_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {
        .name = BLOCK_OPT_CLUSTER_SIZE,
        .type = OPT_SIZE,
        .help = "RBD object size"
    },
    { NULL }
};

static BlockDriver bdrv_rbd = {
	.format_name	= "rbd",
	.instance_size	= sizeof(RBDRVRBDState),
	.bdrv_open	= rbd_open,
	.bdrv_read 	= rbd_read,
	.bdrv_write	= rbd_write,
	.bdrv_close	= rbd_close,
	.bdrv_create	= rbd_create,
	.bdrv_get_info	= rbd_getinfo,
	.create_options = rbd_create_options,
	.bdrv_getlength	= rbd_getlength,
	.protocol_name	= "rbd",

	.bdrv_aio_readv = rbd_aio_readv,
	.bdrv_aio_writev= rbd_aio_writev,
};

static void bdrv_rbd_init(void) {
	bdrv_register(&bdrv_rbd);
}

block_init(bdrv_rbd_init);

