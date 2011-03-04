/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "doveadm-print-private.h"

#include <stdio.h>

struct doveadm_print_pager_header {
	const char *title;
};

struct doveadm_print_pager_context {
	pool_t pool;
	ARRAY_DEFINE(headers, struct doveadm_print_pager_header);
	unsigned int header_idx;

	unsigned int streaming:1;
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
		printf("\f\n");
	}
}

static void doveadm_print_pager_print(const char *value)
{
	const struct doveadm_print_pager_header *hdr =
		array_idx(&ctx->headers, ctx->header_idx);

	printf("%s: %s\n", hdr->title, value);
	pager_next_hdr();
}

static void
doveadm_print_pager_print_stream(const unsigned char *value, size_t size)
{
	const struct doveadm_print_pager_header *hdr =
		array_idx(&ctx->headers, ctx->header_idx);

	if (!ctx->streaming) {
		ctx->streaming = TRUE;
		printf("%s:\n", hdr->title);
	}
	printf("%.*s", (int)size, value);
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
	p_array_init(&ctx->headers, pool, 16);
}

static void doveadm_print_pager_flush(void)
{
	if (ctx->header_idx != 0) {
		printf("\n");
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
