#ifndef DOVEADM_PRINT_PRIVATE_H
#define DOVEADM_PRINT_PRIVATE_H

#include "doveadm-print.h"

struct doveadm_print_header {
	const char *key;
	const char *title;
	enum doveadm_print_header_flags flags;
};

struct doveadm_print_vfuncs {
	const char *name;

	void (*init)(void);
	void (*deinit)(void);

	void (*header)(const struct doveadm_print_header *hdr);
	void (*print)(const char *value);
	void (*print_stream)(const unsigned char *value, size_t size);
	void (*flush)(void);
};

extern struct doveadm_print_vfuncs doveadm_print_flow_vfuncs;
extern struct doveadm_print_vfuncs doveadm_print_tab_vfuncs;
extern struct doveadm_print_vfuncs doveadm_print_table_vfuncs;
extern struct doveadm_print_vfuncs doveadm_print_pager_vfuncs;

#endif
