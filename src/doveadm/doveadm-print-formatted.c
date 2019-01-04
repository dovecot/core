/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ostream.h"
#include "doveadm.h"
#include "doveadm-server.h"
#include "doveadm-print.h"
#include "doveadm-print-private.h"
#include "client-connection.h"
#include "var-expand.h"

struct doveadm_print_formatted_context {
	pool_t pool;
	const char *format;
	ARRAY(struct var_expand_table) headers;
	string_t *buf;
	string_t *vbuf;
	unsigned int idx;
};

static struct doveadm_print_formatted_context ctx;

void doveadm_print_formatted_set_format(const char *format)
{
        ctx.format = format;
}

static void doveadm_print_formatted_init(void)
{
	i_zero(&ctx);
	ctx.pool = pool_alloconly_create("doveadm formatted print", 1024);
	ctx.buf = str_new(ctx.pool, 256);
	p_array_init(&ctx.headers, ctx.pool, 8);
	ctx.idx = 0;
}

static void
doveadm_print_formatted_header(const struct doveadm_print_header *hdr)
{
	struct var_expand_table entry;
	i_zero(&entry);
	entry.key = '\0';
	entry.long_key = p_strdup(ctx.pool, hdr->key);
	entry.value = NULL;
	array_push_back(&ctx.headers, &entry);
}


static void doveadm_print_formatted_flush(void)
{
	o_stream_nsend(doveadm_print_ostream, str_data(ctx.buf), str_len(ctx.buf));
	str_truncate(ctx.buf, 0);
}

static void doveadm_print_formatted_print(const char *value)
{
	if (ctx.format == NULL) {
		i_fatal("formatted formatter cannot be used without a format.");
	}
	const char *error;
	struct var_expand_table *entry = array_idx_modifiable(&ctx.headers, ctx.idx++);
	entry->value = value;

	if (ctx.idx >= array_count(&ctx.headers)) {
		if (var_expand(ctx.buf, ctx.format, array_first(&ctx.headers), &error) <= 0) {
			i_error("Failed to expand print format '%s': %s",
				ctx.format, error);
		}
		doveadm_print_formatted_flush();
		ctx.idx = 0;
	}

}

static void doveadm_print_formatted_deinit(void)
{
	pool_unref(&ctx.pool);
}

struct doveadm_print_vfuncs doveadm_print_formatted_vfuncs = {
	"formatted",

	doveadm_print_formatted_init,
	doveadm_print_formatted_deinit,
	doveadm_print_formatted_header,
	doveadm_print_formatted_print,
	NULL,
	doveadm_print_formatted_flush
};

