/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "doveadm-print-private.h"

struct doveadm_print_tab_context {
	unsigned int header_idx, header_count;

	bool header_written:1;
};

static struct doveadm_print_tab_context ctx;

static void doveadm_print_tab_flush_header(void)
{
	if (!ctx.header_written) {
		if (!doveadm_print_hide_titles)
			o_stream_nsend(doveadm_print_ostream, "\n", 1);
		ctx.header_written = TRUE;
	}
}

static void
doveadm_print_tab_header(const struct doveadm_print_header *hdr)
{
	ctx.header_count++;
	if (!doveadm_print_hide_titles) {
		if (ctx.header_count > 1)
			o_stream_nsend(doveadm_print_ostream, "\t", 1);
		o_stream_nsend_str(doveadm_print_ostream, hdr->title);
	}
}

static void doveadm_print_tab_print(const char *value)
{
	doveadm_print_tab_flush_header();
	if (ctx.header_idx > 0)
		o_stream_nsend(doveadm_print_ostream, "\t", 1);
	o_stream_nsend_str(doveadm_print_ostream, value);

	if (++ctx.header_idx == ctx.header_count) {
		ctx.header_idx = 0;
		o_stream_nsend(doveadm_print_ostream, "\n", 1);
	}
}

static void
doveadm_print_tab_print_stream(const unsigned char *value, size_t size)
{
	if (size == 0) {
		doveadm_print_tab_print("");
		return;
	}
	doveadm_print_tab_flush_header();
	if (ctx.header_idx > 0)
		o_stream_nsend(doveadm_print_ostream, "\t", 1);
	o_stream_nsend(doveadm_print_ostream, value, size);
}

static void doveadm_print_tab_flush(void)
{
	doveadm_print_tab_flush_header();
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
