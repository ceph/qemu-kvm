/*
 * Functions to help device tree manipulation using libfdt.
 * It also provides functions to read entries from device tree proc
 * interface.
 *
 * Copyright 2008 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "config.h"
#include "ppc440.h"

#ifdef CONFIG_LIBFDT
#include "libfdt.h"
#endif

#define DT_PROC_INTERFACE_PATH "/proc/device-tree"

/* FUNCTIONS FOR READING FROM DEVICE TREE OF HOST IN /PROC */

/* This function reads device-tree property files that are of
 * a single cell size
 */
uint32_t read_proc_dt_prop_cell(const char *path_in_device_tree)
{
	char *buf = NULL;
	int i;
	uint32_t num;
	FILE *stream;

	i = asprintf(&buf, "%s/%s", DT_PROC_INTERFACE_PATH,
		path_in_device_tree);

	if (i < 0) {
		printf("%s: Unable to malloc string buffer buf\n",
			__func__);
		exit(1);
	}

	stream = fopen(buf, "rb");

	if (stream == NULL) {
		printf("%s: Unable to open '%s'\n", __func__, buf);
		exit(1);
	}

	fread(&num, sizeof(num), 1, stream);
	fclose(stream);
	free(buf);

	return num;
}

/* FUNCTIONS FOR LOADING & MANIPULATION OF DEVICE TREE IN GUEST */

#ifdef CONFIG_LIBFDT
/* support functions */
static int get_offset_of_node(void *fdt, const char *node_path)
{
	int node_offset;
	node_offset = fdt_path_offset(fdt, node_path);
	if (node_offset < 0) {
		printf("Unable to find node in device tree '%s'\n",
			node_path);
		exit(1);
	}
	return node_offset;
}

/* public functions */
void *load_device_tree(const char *filename_path, unsigned long load_addr)
{
	int dt_file_size;
	int dt_file_load_size;
	int new_dt_size;
	int ret;
	void *dt_file = NULL;
	void *fdt;

	dt_file_size = get_image_size(filename_path);
	if (dt_file_size < 0) {
		printf("Unable to get size of device tree file '%s'\n",
			filename_path);
		goto fail;
	}

	/* First allocate space in qemu for device tree */
	dt_file = qemu_malloc(dt_file_size);
	if (dt_file == NULL) {
		printf("Unable to allocate memory in qemu for device tree\n");
		goto fail;
	}
	memset(dt_file, 0, dt_file_size);

	dt_file_load_size = load_image(filename_path, dt_file);


	/* XXX Second we place new copy of 2x size in guest memory
	 *  This give us enough room for manipulation.
	 */
	new_dt_size = dt_file_size * 2;

	fdt = (void *)load_addr;

	ret = fdt_open_into(dt_file, fdt, new_dt_size);
	if (ret) {
		printf("Unable to copy device tree in memory\n");
		goto fail;
	}

	/* Check sanity of device tree */
	if (fdt_check_header(fdt)) {
		printf ("Device tree file loaded into memory is invalid: %s\n",
			filename_path);
		goto fail;
	}
	/* free qemu memory with old device tree */
	qemu_free(dt_file);
	return fdt;

fail:
	if (dt_file)
		qemu_free(dt_file);
	return NULL;
}

void dump_device_tree_to_file(void *fdt, const char *filename)
{
	int fd;
	fd = open(filename, O_RDWR|O_CREAT, O_RDWR);
	if (fd < 0) {
		printf("Failed to open file %s\n Cannot dum device-tree\n",
			filename);
		return;
	}

	write(fd, fdt, fdt_totalsize(fdt));
	close(fd);
}

void dt_cell(void *fdt, const char *node_path, const char *property,
		uint32_t val)
{
	int offset;
	int ret;
	offset = get_offset_of_node(fdt, node_path);
	ret = fdt_setprop_cell(fdt, offset, property, val);
	if (ret < 0) {
		printf("Unable to set device tree property '%s'\n",
			property);
		exit(1);
	}
}

/* This function is to manipulate a cell with multiple values */
void dt_cell_multi(void *fdt, const char *node_path, const char *property,
			uint32_t *val_array, int size)
{
	int offset;
	int ret;
	offset = get_offset_of_node(fdt, node_path);
	ret = fdt_setprop(fdt, offset, property, val_array, size);
	if (ret < 0) {
		printf("Unable to set device tree property '%s'\n",
			property);
		exit(1);
	}
}

void dt_string(void *fdt, const char *node_path, const char *property,
		char *string)
{
	int offset;
	int ret;
	offset = get_offset_of_node(fdt, node_path);
	ret = fdt_setprop_string(fdt, offset, property, string);
	if (ret < 0) {
		printf("Unable to set device tree property '%s'\n",
			property);
		exit(1);
	}
}
#endif
