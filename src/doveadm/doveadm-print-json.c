/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "json-ostream.h"
#include "doveadm.h"
#include "doveadm-print.h"
#include "doveadm-print-private.h"
#include "client-connection.h"

struct doveadm_print_json_context {
	unsigned int header_idx, header_count;
	bool flushed;
	struct json_ostream *json_output;
	struct ostream *str_stream;
	ARRAY(struct doveadm_print_header) headers;
	pool_t pool;
	string_t *str;
};

static struct doveadm_print_json_context ctx;

static void doveadm_print_json_init(void)
{
	i_zero(&ctx);
	ctx.pool = pool_alloconly_create("doveadm json print", 1024);

	p_array_init(&ctx.headers, ctx.pool, 1);
}

static void doveadm_print_json_init_output(void)
{
	if (ctx.json_output != NULL)
		return;

	ctx.json_output = json_ostream_create(doveadm_print_ostream, 0);
	json_ostream_set_no_error_handling(ctx.json_output, TRUE);
	json_ostream_ndescend_array(ctx.json_output, NULL);
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
doveadm_print_json_value_header(void)
{
	doveadm_print_json_init_output();

	if (ctx.header_idx == 0)
		json_ostream_ndescend_object(ctx.json_output, NULL);
}

static void
doveadm_print_json_value_footer(void) {
	if (++ctx.header_idx == ctx.header_count) {
		ctx.header_idx = 0;
		json_ostream_nascend_object(ctx.json_output);
	}
}

static void doveadm_print_json_print(const char *value)
{
	const struct doveadm_print_header *hdr = array_idx(&ctx.headers, ctx.header_idx);

	doveadm_print_json_value_header();

	if (value == NULL) {
		json_ostream_nwrite_null(ctx.json_output, hdr->key);
	} else if ((hdr->flags & DOVEADM_PRINT_HEADER_FLAG_NUMBER) != 0) {
		i_assert(str_is_float(value, '\0'));
		json_ostream_nwrite_number_raw(ctx.json_output,
					       hdr->key, value);
	} else {
		json_ostream_nwrite_string(ctx.json_output, hdr->key, value);
	}

	doveadm_print_json_value_footer();
}

static void
doveadm_print_json_print_stream(const unsigned char *value, size_t size)
{
	if (ctx.str_stream == NULL) {
		const struct doveadm_print_header *hdr =
			array_idx(&ctx.headers, ctx.header_idx);
		doveadm_print_json_value_header();
		i_assert((hdr->flags & DOVEADM_PRINT_HEADER_FLAG_NUMBER) == 0);
		ctx.str_stream = json_ostream_nopen_string_stream(
			ctx.json_output, hdr->key);
		o_stream_set_no_error_handling(ctx.str_stream, TRUE);
	}

	if (size == 0) {
		o_stream_destroy(&ctx.str_stream);
		doveadm_print_json_value_footer();
		return;
	}

	o_stream_nsend(ctx.str_stream, value, size);
}

static void doveadm_print_json_flush(void)
{
	if (ctx.flushed)
		return;
	ctx.flushed = TRUE;

	if (ctx.json_output == NULL)
		doveadm_print_json_init_output();
	json_ostream_nflush(ctx.json_output);
}

static void doveadm_print_json_deinit(void)
{
	if (ctx.json_output != NULL)
		json_ostream_nascend_array(ctx.json_output);
	json_ostream_destroy(&ctx.json_output);
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

