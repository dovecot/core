/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
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
	size_t min_length, max_length, length;
};

struct doveadm_print_table_context {
	pool_t pool;
	ARRAY(struct doveadm_print_table_header) headers;
	ARRAY_TYPE(const_string) buffered_values;
	string_t *stream;
	unsigned int hdr_idx;
	unsigned int columns;

	bool lengths_set:1;
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
	unsigned int i, line, hdr_count, value_count, line_count;
	size_t len, max_length, orig_length, diff;

	ctx->lengths_set = TRUE;

	headers = array_get_modifiable(&ctx->headers, &hdr_count);
	values = array_get(&ctx->buffered_values, &value_count);
	i_assert((value_count % hdr_count) == 0);
	line_count = value_count / hdr_count;

	/* find min and max lengths of fields */
	for (line = 0; line < line_count; line++) {
		for (i = 0; i < hdr_count; i++) {
			value = values[line*hdr_count + i];
			len = value == NULL ? 0 : uni_utf8_strlen(value);
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
	if (max_length < ctx->columns) {
		for (i = 0; i < hdr_count; i++) {
			if ((headers[i].flags & DOVEADM_PRINT_HEADER_FLAG_EXPAND) != 0) {
				i++;
				break;
			}
		}
		headers[i-1].length += (ctx->columns - max_length) / 2;
	}
}

static size_t utf8_correction(const char *str)
{
	size_t i, len = 0;

	for (i = 0; str[i] != '\0'; i++) {
		if ((str[i] & 0xc0) == 0x80)
			len++;
	}
	return len;
}

static void doveadm_print_next(const char *value)
{
	const struct doveadm_print_table_header *hdr;
	int value_padded_len;

	hdr = array_idx(&ctx->headers, ctx->hdr_idx);

	value_padded_len = hdr->length + utf8_correction(value);
	if ((hdr->flags & DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY) == 0)
		printf("%-*s", value_padded_len, value);
	else
		printf("%*s", value_padded_len, value);

	if (++ctx->hdr_idx == array_count(&ctx->headers)) {
		ctx->hdr_idx = 0;
		printf("\n");
	} else {
		printf(" ");
	}
}

static void doveadm_print_headers(void)
{
	const struct doveadm_print_table_header *headers;
	unsigned int i, count;

	if (doveadm_print_hide_titles)
		return;

	headers = array_get(&ctx->headers, &count);
	/* if all headers are hidden, don't print any of them */
	for (i = 0; i < count; i++) {
		if ((headers[i].flags & DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE) == 0)
			break;
	}
	if (i == count)
		return;
	for (i = 0; i < count; i++) {
		if (i > 0) printf(" ");

		if ((headers[i].flags &
		     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY) == 0) {
			printf("%-*s", (int)headers[i].length,
				headers[i].title);
		} else {
			printf("%*s", (int)headers[i].length,
				headers[i].title);
		}
	}
	printf("\n");
}

static void doveadm_buffer_flush(void)
{
	const char *const *valuep;

	doveadm_calc_header_length();
	doveadm_print_headers();

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
doveadm_print_table_print_stream(const unsigned char *value, size_t size)
{
	if (memchr(value, '\n', size) != NULL)
		i_fatal("table formatter doesn't support multi-line values");

	if (size != 0)
		str_append_data(ctx->stream, value, size);
	else {
		doveadm_print_table_print(str_c(ctx->stream));
		str_truncate(ctx->stream, 0);
	}
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

	pool = pool_alloconly_create("doveadm print table", 2048);
	ctx = p_new(pool, struct doveadm_print_table_context, 1);
	ctx->pool = pool;
	ctx->stream = str_new(default_pool, 128);
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
	str_free(&ctx->stream);
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
