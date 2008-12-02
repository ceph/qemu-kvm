/*
 * Header with function prototypes to help device tree manipulation using
 * libfdt. It also provides functions to read entries from device tree proc
 * interface.
 *
 * Copyright 2008 IBM Corporation.
 * Authors: Jerone Young <jyoung5@us.ibm.com>
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 */

/* device-tree proc support functions */
uint32_t read_proc_dt_prop_cell(const char *path_in_device_tree);

#ifdef CONFIG_LIBFDT
/* device tree functions */
void *load_device_tree(const char *filename_path, target_ulong load_addr);
void dump_device_tree_to_file(void *fdt, const char *filename);
void dt_cell(void *fdt, const char *node_path, const char *property,
		uint32_t val);
void dt_cell_multi(void *fdt, const char *node_path, const char *property,
		uint32_t *val_array, int size);
void dt_string(void *fdt, const char *node_path, const char *property,
		char *string);
#endif
