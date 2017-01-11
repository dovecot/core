/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "json-parser.h"
#include "client-connection.h"
#include "doveadm-server.h"
#include "doveadm-print.h"
#include "doveadm-print-private.h"

struct doveadm_print_json_context {
	unsigned int header_idx, header_count;
	bool first_row;
	bool in_stream;
	bool flushed;
	ARRAY(struct doveadm_print_header) headers;
	pool_t pool;
	string_t *str;
};

static struct doveadm_print_json_context ctx;

static void doveadm_print_json_flush_internal(void);

static void doveadm_print_json_init(void)
{
	i_zero(&ctx);
	ctx.pool = pool_alloconly_create("doveadm json print", 1024);
	ctx.str = str_new(ctx.pool, 256);
	p_array_init(&ctx.headers, ctx.pool, 1);
	ctx.first_row = TRUE;
	ctx.in_stream = FALSE;
}

static void
doveadm_print_json_header(const struct doveadm_print_header *hdr)
{
	struct doveadm_print_header *lhdr;
	lhdr = array_append_space(&ctx.headers);
	lhdr->key = p_strdup(ctx.pool, hdr->key);
	lhdr->flags = hdr->flags;
	ctx.header_count++;
}

static void
doveadm_print_json_value_header(const struct doveadm_print_header *hdr)
{
	// get header name
	if (ctx.header_idx == 0) {
		if (ctx.first_row == TRUE) {
			ctx.first_row = FALSE;
			str_append_c(ctx.str, '[');
		} else {
			str_append_c(ctx.str, ',');
		}
		str_append_c(ctx.str, '{');
	} else {
		str_append_c(ctx.str, ',');
	}

	str_append_c(ctx.str, '"');
	json_append_escaped(ctx.str, hdr->key);
	str_append_c(ctx.str, '"');
	str_append_c(ctx.str, ':');
}

static void
doveadm_print_json_value_footer(void) {
	if (++ctx.header_idx == ctx.header_count) {
		ctx.header_idx = 0;
		str_append_c(ctx.str, '}');
		doveadm_print_json_flush_internal();
	}
}

static void doveadm_print_json_print(const char *value)
{
	const struct doveadm_print_header *hdr = array_idx(&ctx.headers, ctx.header_idx);

	doveadm_print_json_value_header(hdr);

	if (value == NULL) {
		str_append(ctx.str, "null");
	} else if ((hdr->flags & DOVEADM_PRINT_HEADER_FLAG_NUMBER) != 0) {
		i_assert(str_is_float(value, '\0'));
		str_append(ctx.str, value);
	} else {
		str_append_c(ctx.str, '"');
		json_append_escaped(ctx.str, value);
		str_append_c(ctx.str, '"');
	}

	doveadm_print_json_value_footer();
}

static void
doveadm_print_json_print_stream(const unsigned char *value, size_t size)
{
	if (!ctx.in_stream) {
		const struct doveadm_print_header *hdr =
			array_idx(&ctx.headers, ctx.header_idx);
		doveadm_print_json_value_header(hdr);
		i_assert((hdr->flags & DOVEADM_PRINT_HEADER_FLAG_NUMBER) == 0);
		str_append_c(ctx.str, '"');
		ctx.in_stream = TRUE;
	}

	if (size == 0) {
		str_append_c(ctx.str, '"');
		doveadm_print_json_value_footer();
		ctx.in_stream = FALSE;
		return;
	}

	json_append_escaped_data(ctx.str, value, size);

	if (str_len(ctx.str) >= IO_BLOCK_SIZE)
		doveadm_print_json_flush_internal();
}

static void doveadm_print_json_flush_internal(void)
{
	o_stream_nsend(doveadm_print_ostream, str_data(ctx.str), str_len(ctx.str));
	str_truncate(ctx.str, 0);
}

static void doveadm_print_json_flush(void)
{
	if (ctx.flushed)
		return;
	ctx.flushed = TRUE;

	if (ctx.first_row == FALSE)
		str_append_c(ctx.str,']');
	else {
		str_append_c(ctx.str,'[');
		str_append_c(ctx.str,']');
	}
	doveadm_print_json_flush_internal();
}

static void doveadm_print_json_deinit(void)
{
	pool_unref(&ctx.pool);
}

struct doveadm_print_vfuncs doveadm_print_json_vfuncs = {
	"json",

	doveadm_print_json_init,
	doveadm_print_json_deinit,
	doveadm_print_json_header,
	doveadm_print_json_print,
	doveadm_print_json_print_stream,
	doveadm_print_json_flush
};

