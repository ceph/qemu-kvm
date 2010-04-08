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

//#include "rbd.h"
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

#define OBJ_DEFAULT_ORDER 22	// 22 Bit = 4MB (as default)
#define OBJ_MAX_SIZE (1UL << OBJ_DEFAULT_ORDER)

#define MAX_NAME 128 		// Maximum size of the poolname plus objectname
#define MAX_SNAPS 4096		// Maximum number of snapshots (unsupported at
				// the moment)

typedef struct RBDRVRBDState {
	rados_pool_t pool;
	char name[MAX_NAME];
	int name_len;
	uint64_t size;
	uint64_t objsize;
} RBDRVRBDState;
	
#define RBD_TEXT "<<< Rados Block Device Image >>>\n"
#define RBD_SIGNATURE "RBD"
#define RBD_VERSION1 "001.000"

#define COMP_NONE 0
#define CRYPT_NONE 0

typedef struct {
	char text[64];
	char signature[4];
	char version[8];
	uint64_t imagesize;
	uint8_t objorder;
	uint8_t crypt_type;
	uint8_t comp_type;			// unsupported at the moment
	uint64_t snap_seq;			// unsupported at the moment
	uint16_t snap_count;			// unsupported at the moment
	uint64_t snap_id[MAX_SNAPS];	// unsupported at the moment
} __attribute__((packed)) RbdHeader1;

static int rbd_parsename(const char *filename, char *pool, char *name) {
	const char *rbdname;
	char *p, *n;
	int l;

	if(!strstart(filename, "rbd:", &rbdname)) {
		return -EINVAL;
	}
		
	pstrcpy(pool, MAX_NAME, rbdname);
	p = strchr(pool, '/');
	if (p == NULL) {
		return -EINVAL;
	}

	*p = '\0';
	n = ++p;

	l = strlen(n);

	if (l > MAX_NAME-14) {
		fprintf(stderr, "object name to long\n");
		return -EINVAL;
	} else if (l <= 0) {
		fprintf(stderr, "object name to short\n");
		return -EINVAL;
	}

	strcpy(name, n);

	return l;
}

static int rbd_create(const char *filename, QEMUOptionParameter *options) {
	int64_t bytes = 0;
	int64_t objsize;
	uint8_t objorder = OBJ_DEFAULT_ORDER;
	char pool[MAX_NAME];
	char n[MAX_NAME];
	char name[MAX_NAME];
	RbdHeader1 header;
	rados_pool_t p;
	int name_len;

	if ((name_len = rbd_parsename(filename, pool, name)) < 0) {
		return -EINVAL;
	}

	snprintf(n, MAX_NAME, "%s.rbd", name);

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

				for (objorder=0; objorder<64; objorder++) {
					if (objsize == 1)
						break;
					objsize >>= 1;
				}
			}
		}
		options++;
	}

	memset(&header, 0, sizeof(header));
	pstrcpy(header.text, sizeof(header.text), RBD_TEXT);
	pstrcpy(header.signature, sizeof(header.signature), RBD_SIGNATURE);
	pstrcpy(header.version, sizeof(header.version), RBD_VERSION1);
	header.imagesize = bytes;
	cpu_to_le64s(&header.imagesize);
	header.objorder = objorder;
	header.crypt_type = CRYPT_NONE;
	header.comp_type = COMP_NONE;
	header.snap_seq = 0;
	header.snap_count = 0;
	cpu_to_le16s(&header.snap_count);

        if (rados_initialize(0, NULL) < 0) {
                fprintf(stderr, "error initializing\n");
		return -EIO;
        }

	if (rados_open_pool(pool, &p)) {
                fprintf(stderr, "error opening pool %s\n", pool);
		return -EIO;
	}

	if (rados_write(p, n, 0, (const char *) &header, sizeof(header)) < 0) {
		return -errno;
	}

	rados_close_pool(p);
	rados_deinitialize();

	return 0;
}

static int rbd_open(BlockDriverState *bs, const char *filename, int flags) {
	RBDRVRBDState *s = bs->opaque;
	char pool[MAX_NAME];
	char n[MAX_NAME];
	char hbuf[4096];

	if ((s->name_len = rbd_parsename(filename, pool, s->name)) < 0) {
		return -EINVAL;
	}
	snprintf(n, MAX_NAME, "%s.rbd", s->name);
	
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
	if (!strncmp(hbuf+64, RBD_SIGNATURE, 4)) {
		if(!strncmp(hbuf+68, RBD_VERSION1, 8)) {
			RbdHeader1 *header;

			header = (RbdHeader1 *) hbuf;
			le64_to_cpus(&header->imagesize);
			s->size = header->imagesize;
			s->objsize = 1 << header->objorder;
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
	char n[MAX_NAME];

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

		snprintf(n, MAX_NAME, "%s.%012llx", s->name, (long long unsigned int) segnr);

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
	char n[MAX_NAME];

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

		snprintf(n, MAX_NAME, "%s.%012llx", s->name, (long long unsigned int) segnr);

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
};

static void bdrv_rbd_init(void) {
	bdrv_register(&bdrv_rbd);
}

block_init(bdrv_rbd_init);


