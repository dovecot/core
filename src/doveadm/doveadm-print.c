/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "doveadm-print-private.h"

struct doveadm_print_header_context {
	const char *key;
	char *sticky_value;
	bool sticky;
};

struct doveadm_print_context {
	pool_t pool;
	ARRAY(struct doveadm_print_header_context) headers;
	const struct doveadm_print_vfuncs *v;

	unsigned int header_idx;
	bool print_stream_open;
};

bool doveadm_print_hide_titles = FALSE;
struct ostream *doveadm_print_ostream = NULL;

static struct doveadm_print_context *ctx;

bool doveadm_print_is_initialized(void)
{
	return ctx != NULL;
}

void doveadm_print_header(const char *key, const char *title,
			  enum doveadm_print_header_flags flags)
{
	struct doveadm_print_header hdr;
	struct doveadm_print_header_context *hdr_ctx;

	i_assert(title != NULL);

	i_zero(&hdr);
	hdr.key = key;
	hdr.title = title;
	hdr.flags = flags;
	ctx->v->header(&hdr);

	hdr_ctx = array_append_space(&ctx->headers);
	hdr_ctx->key = p_strdup(ctx->pool, key);
	hdr_ctx->sticky = (flags & DOVEADM_PRINT_HEADER_FLAG_STICKY) != 0;
}

void doveadm_print_header_simple(const char *key_title)
{
	doveadm_print_header(key_title, key_title, 0);
}

unsigned int doveadm_print_get_headers_count(void)
{
	return array_count(&ctx->headers);
}

static void doveadm_print_sticky_headers(void)
{
	const struct doveadm_print_header_context *headers;
	unsigned int count;

	headers = array_get(&ctx->headers, &count);
	i_assert(count > 0);
	for (;;) {
		if (ctx->header_idx == count)
			ctx->header_idx = 0;
		else if (headers[ctx->header_idx].sticky) {
			ctx->v->print(headers[ctx->header_idx].sticky_value);
			ctx->header_idx++;
		} else {
			break;
		}
	}
}

void doveadm_print(const char *value)
{
	i_assert(!ctx->print_stream_open);

	doveadm_print_sticky_headers();
	ctx->v->print(value);
	ctx->header_idx++;
}

void doveadm_print_num(uintmax_t value)
{
	T_BEGIN {
		doveadm_print(dec2str(value));
	} T_END;
}

void doveadm_print_stream(const void *value, size_t size)
{
	if (!ctx->print_stream_open) {
		doveadm_print_sticky_headers();
		ctx->print_stream_open = TRUE;
	}
	ctx->v->print_stream(value, size);
	if (size == 0) {
		ctx->header_idx++;
		ctx->print_stream_open = FALSE;
	}
}

int doveadm_print_istream(struct istream *input)
{
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		doveadm_print_stream(data, size);
		i_stream_skip(input, size);
	}
	i_assert(ret == -1);
	doveadm_print_stream("", 0);
	if (input->stream_errno != 0) {
		i_error("read(%s) failed: %s", i_stream_get_name(input),
			i_stream_get_error(input));
		return -1;
	}
	return 0;
}

void doveadm_print_sticky(const char *key, const char *value)
{
	struct doveadm_print_header_context *hdr;

	if (ctx == NULL) {
		/* command doesn't really print anything */
		return;
	}

	array_foreach_modifiable(&ctx->headers, hdr) {
		if (strcmp(hdr->key, key) == 0) {
			i_free(hdr->sticky_value);
			hdr->sticky_value = i_strdup(value);
			return;
		}
	}
	i_unreached();
}

void doveadm_print_flush(void)
{
	if (ctx != NULL && ctx->v->flush != NULL)
		ctx->v->flush();
	o_stream_uncork(doveadm_print_ostream);
	o_stream_cork(doveadm_print_ostream);
}

void doveadm_print_unstick_headers(void)
{
	struct doveadm_print_header_context *hdr;

	if (ctx != NULL) {
		array_foreach_modifiable(&ctx->headers, hdr)
			hdr->sticky = FALSE;
	}
}

void doveadm_print_init(const char *name)
{
	pool_t pool;
	unsigned int i;

	if (ctx != NULL) {
		/* already forced the type */
		return;
	}

	pool = pool_alloconly_create("doveadm print", 1024);
	ctx = p_new(pool, struct doveadm_print_context, 1);
	ctx->pool = pool;
	p_array_init(&ctx->headers, pool, 16);

	for (i = 0; doveadm_print_vfuncs_all[i] != NULL; i++) {
		if (strcmp(doveadm_print_vfuncs_all[i]->name, name) == 0) {
			ctx->v = doveadm_print_vfuncs_all[i];
			break;
		}
	}
	if (ctx->v == NULL)
		i_fatal("Unknown print formatter: %s", name);
	if (ctx->v->init != NULL)
		ctx->v->init();
}

void doveadm_print_deinit(void)
{
	struct doveadm_print_header_context *hdr;

	if (ctx == NULL)
		return;

	if (ctx->v->flush != NULL && doveadm_print_ostream != NULL) {
		ctx->v->flush();
		o_stream_uncork(doveadm_print_ostream);
	}
	if (ctx->v->deinit != NULL)
		ctx->v->deinit();
	array_foreach_modifiable(&ctx->headers, hdr)
		i_free(hdr->sticky_value);
	pool_unref(&ctx->pool);
	ctx = NULL;
}
