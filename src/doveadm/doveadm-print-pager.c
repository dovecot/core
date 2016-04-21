/* Copyright (c) 2010-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "doveadm-print-private.h"

struct doveadm_print_pager_header {
	const char *title;
};

struct doveadm_print_pager_context {
	pool_t pool;
	ARRAY(struct doveadm_print_pager_header) headers;
	unsigned int header_idx;

	unsigned int streaming:1;
	unsigned int first_page:1;
};

static struct doveadm_print_pager_context *ctx;

static void
doveadm_print_pager_header(const struct doveadm_print_header *hdr)
{
	struct doveadm_print_pager_header *fhdr;

	fhdr = array_append_space(&ctx->headers);
	fhdr->title = p_strdup(ctx->pool, hdr->title);
}

static void pager_next_hdr(void)
{
	if (++ctx->header_idx == array_count(&ctx->headers)) {
		ctx->header_idx = 0;
	}
}

static void doveadm_print_pager_print(const char *value)
{
	const struct doveadm_print_pager_header *hdr =
		array_idx(&ctx->headers, ctx->header_idx);

	if (ctx->header_idx == 0 && !ctx->first_page) {
		o_stream_nsend(doveadm_print_ostream, "\f\n", 2);
	}
	ctx->first_page = FALSE;
	o_stream_nsend_str(doveadm_print_ostream, hdr->title);
	o_stream_nsend(doveadm_print_ostream, ": ", 2);
	o_stream_nsend_str(doveadm_print_ostream, value);
	o_stream_nsend(doveadm_print_ostream, "\n", 1);
	pager_next_hdr();
}

static void
doveadm_print_pager_print_stream(const unsigned char *value, size_t size)
{
	const struct doveadm_print_pager_header *hdr =
		array_idx(&ctx->headers, ctx->header_idx);

	if (!ctx->streaming) {
		ctx->streaming = TRUE;
		o_stream_nsend_str(doveadm_print_ostream, hdr->title);
		o_stream_nsend(doveadm_print_ostream, ":\n", 2);
	}
	o_stream_nsend(doveadm_print_ostream, value, size);
	if (size == 0) {
		pager_next_hdr();
		ctx->streaming = FALSE;
	}
}

static void doveadm_print_pager_init(void)
{
	pool_t pool;

	pool = pool_alloconly_create("doveadm print pager", 1024);
	ctx = p_new(pool, struct doveadm_print_pager_context, 1);
	ctx->pool = pool;
	ctx->first_page = TRUE;
	p_array_init(&ctx->headers, pool, 16);
}

static void doveadm_print_pager_flush(void)
{
	if (ctx->header_idx != 0) {
		o_stream_nsend(doveadm_print_ostream, "\n", 1);
		ctx->header_idx = 0;
	}
}

static void doveadm_print_pager_deinit(void)
{
	pool_unref(&ctx->pool);
	ctx = NULL;
}

struct doveadm_print_vfuncs doveadm_print_pager_vfuncs = {
	"pager",

	doveadm_print_pager_init,
	doveadm_print_pager_deinit,
	doveadm_print_pager_header,
	doveadm_print_pager_print,
	doveadm_print_pager_print_stream,
	doveadm_print_pager_flush
};
