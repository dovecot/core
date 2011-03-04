/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "doveadm-print-private.h"

#include <stdio.h>

struct doveadm_print_tab_context {
	unsigned int header_idx, header_count;

	unsigned int header_written:1;
};

static struct doveadm_print_tab_context ctx;

static void
doveadm_print_tab_header(const struct doveadm_print_header *hdr)
{
	if (ctx.header_count++ > 0)
		printf("\t");
	printf("%s", hdr->title);
}

static void doveadm_print_tab_print(const char *value)
{
	if (!ctx.header_written) {
		printf("\n");
		ctx.header_written = TRUE;
	}
	if (ctx.header_idx > 0)
		printf("\t");
	printf("%s", value);

	if (++ctx.header_idx == ctx.header_count) {
		ctx.header_idx = 0;
		printf("\n");
	}
}

static void
doveadm_print_tab_print_stream(const unsigned char *value, size_t size)
{
	if (size == 0) {
		doveadm_print_tab_print("");
		return;
	}
	if (!ctx.header_written) {
		printf("\n");
		ctx.header_written = TRUE;
	}
	if (ctx.header_idx > 0)
		printf("\t");
	printf("%.*s", (int)size, value);
}

static void doveadm_print_tab_flush(void)
{
	if (!ctx.header_written) {
		printf("\n");
		ctx.header_written = TRUE;
	}
}

struct doveadm_print_vfuncs doveadm_print_tab_vfuncs = {
	"tab",

	NULL,
	NULL,
	doveadm_print_tab_header,
	doveadm_print_tab_print,
	doveadm_print_tab_print_stream,
	doveadm_print_tab_flush
};
