/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "doveadm-print-private.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

#define DEFAULT_COLUMNS 80
#define MIN_COLUMNS 30
#define MAX_BUFFER_LINES 100

struct doveadm_print_table_header {
	const char *key;
	const char *title;
	enum doveadm_print_header_flags flags;
	unsigned int min_length, max_length, length;
};

struct doveadm_print_table_context {
	pool_t pool;
	ARRAY_DEFINE(headers, struct doveadm_print_table_header);
	ARRAY_TYPE(const_string) buffered_values;
	unsigned int hdr_idx;
	unsigned int columns;

	unsigned int lengths_set:1;
};

static struct doveadm_print_table_context *ctx;

static void
doveadm_print_table_header(const struct doveadm_print_header *hdr)
{
	struct doveadm_print_table_header *thdr;

	thdr = array_append_space(&ctx->headers);
	thdr->key = p_strdup(ctx->pool, hdr->key);
	thdr->title = p_strdup(ctx->pool, hdr->title);
	thdr->length = thdr->max_length = thdr->min_length = strlen(hdr->title);
	thdr->flags = hdr->flags;
}

static void doveadm_calc_header_length(void)
{
	struct doveadm_print_table_header *headers;
	const char *value, *const *values;
	unsigned int i, line, len, hdr_count, value_count, line_count;
	unsigned int max_length, orig_length, diff;

	ctx->lengths_set = TRUE;

	headers = array_get_modifiable(&ctx->headers, &hdr_count);
	values = array_get(&ctx->buffered_values, &value_count);
	i_assert((value_count % hdr_count) == 0);
	line_count = value_count / hdr_count;

	/* find min and max lengths of fields */
	for (line = 0; line < line_count; line++) {
		for (i = 0; i < hdr_count; i++) {
			value = values[line*hdr_count + i];
			len = value == NULL ? 0 : strlen(value);
			if (headers[i].min_length > len)
				headers[i].min_length = len;
			if (headers[i].max_length < len) {
				headers[i].max_length = len;
				headers[i].length = len;
			}
		}
	}

	/* +1 for space between fields */
	max_length = 0;
	for (i = 0; i < hdr_count; i++)
		max_length += headers[i].max_length + 1;
	max_length--;

	while (max_length > ctx->columns) {
		/* shrink something so we'll fit */
		orig_length = max_length;
		for (i = hdr_count - 1;; i--) {
			diff = headers[i].length - headers[i].min_length;
			if (max_length - diff <= ctx->columns) {
				/* we can finish with this */
				diff = max_length - ctx->columns;
				headers[i].length -= diff;
				max_length -= diff;
				break;
			}
			if (diff > 0) {
				/* take a bit off from it */
				headers[i].length -= diff == 1 ? 1 : diff/2;
			}

			if (i == 0)
				break;
		}
		if (max_length == orig_length) {
			/* can't shrink it any more */
			break;
		}
	}
	if (max_length < ctx->columns)
		headers[0].length += (ctx->columns - max_length) / 2;
}

static void doveadm_print_next(const char *value)
{
	const struct doveadm_print_table_header *hdr;

	hdr = array_idx(&ctx->headers, ctx->hdr_idx);

	if ((hdr->flags & DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY) == 0)
		printf("%-*s", (int)hdr->length, value);
	else
		printf("%*s", (int)hdr->length, value);

	if (++ctx->hdr_idx == array_count(&ctx->headers)) {
		ctx->hdr_idx = 0;
		printf("\n");
	} else {
		printf(" ");
	}
}

static void doveadm_buffer_flush(void)
{
	const struct doveadm_print_table_header *headers;
	const char *const *valuep;
	unsigned int i, count;

	doveadm_calc_header_length();

	headers = array_get(&ctx->headers, &count);
	for (i = 0; i < count; i++) {
		if (i > 0) fprintf(stderr, " ");

		if ((headers[i].flags &
		     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY) == 0) {
			fprintf(stderr, "%-*s", (int)headers[i].length,
				headers[i].title);
		} else {
			fprintf(stderr, "%*s", (int)headers[i].length,
				headers[i].title);
		}
	}
	fprintf(stderr, "\n");

	array_foreach(&ctx->buffered_values, valuep)
		doveadm_print_next(*valuep);
	array_clear(&ctx->buffered_values);
}

static void doveadm_print_table_print(const char *value)
{
	unsigned int line_count;

	if (!ctx->lengths_set) {
		line_count = array_count(&ctx->buffered_values) /
			array_count(&ctx->headers);
		if (line_count < MAX_BUFFER_LINES) {
			value = p_strdup(ctx->pool, value);
			array_append(&ctx->buffered_values, &value, 1);
			return;
		}
		doveadm_buffer_flush();
	}
	doveadm_print_next(value);
}

static void
doveadm_print_table_print_stream(const unsigned char *value ATTR_UNUSED,
				 size_t size ATTR_UNUSED)
{
	i_fatal("table formatter doesn't support multi-line values");
}

static void doveadm_print_table_flush(void)
{
	if (!ctx->lengths_set && array_count(&ctx->headers) > 0)
		doveadm_buffer_flush();
}

static void doveadm_print_table_init(void)
{
	pool_t pool;
	struct winsize ws;

	pool = pool_alloconly_create("doveadm print table", 1024);
	ctx = p_new(pool, struct doveadm_print_table_context, 1);
	ctx->pool = pool;
	p_array_init(&ctx->headers, pool, 16);
	i_array_init(&ctx->buffered_values, 64);
	ctx->columns = DEFAULT_COLUMNS;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
		ctx->columns = ws.ws_col < MIN_COLUMNS ?
			MIN_COLUMNS : ws.ws_col;
	}
}

static void doveadm_print_table_deinit(void)
{
	array_free(&ctx->buffered_values);
	pool_unref(&ctx->pool);
	ctx = NULL;
}

struct doveadm_print_vfuncs doveadm_print_table_vfuncs = {
	"table",

	doveadm_print_table_init,
	doveadm_print_table_deinit,
	doveadm_print_table_header,
	doveadm_print_table_print,
	doveadm_print_table_print_stream,
	doveadm_print_table_flush
};
