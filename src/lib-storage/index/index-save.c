/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "index-storage.h"

#include <stdlib.h>
#include <unistd.h>

struct save_header_context {
	struct mail_storage *storage;
	const char *path;

	struct ostream *output;
	write_func_t *write_func;

	header_callback_t *header_callback;
	void *context;

	int failed;
};

static int write_with_crlf(struct ostream *output, const unsigned char *data,
			   size_t size)
{
	size_t i, start;

	i_assert(size <= SSIZE_T_MAX);

	if (size == 0)
		return 0;

	start = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n' && (i == 0 || data[i-1] != '\r')) {
			/* missing CR */
			if (o_stream_send(output, data + start, i - start) < 0)
				return -1;
			if (o_stream_send(output, "\r", 1) < 0)
				return -1;

			/* \n is written next time */
			start = i;
		}
	}

	/* if last char is \r, leave it to buffer */
	if (data[size-1] == '\r')
		size--;

	if (o_stream_send(output, data + start, size - start) < 0)
		return -1;

	return size;
}

static int write_with_lf(struct ostream *output, const unsigned char *data,
			 size_t size)
{
	size_t i, start;

	i_assert(size <= SSIZE_T_MAX);

	if (size == 0)
		return 0;

	start = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n' && i > 0 && data[i-1] == '\r') {
			/* \r\n - skip \r */
			if (o_stream_send(output, data + start,
					   i - start - 1) < 0)
				return -1;

			/* \n is written next time */
			start = i;
		}
	}

	/* if last char is \r, leave it to buffer */
	if (data[size-1] == '\r')
		size--;

	if (o_stream_send(output, data + start, size - start) < 0)
		return -1;

	return size;
}

static void set_write_error(struct mail_storage *storage,
			    struct ostream *output, const char *path)
{
	errno = output->stream_errno;
	if (errno == ENOSPC)
		mail_storage_set_error(storage, "Not enough disk space");
	else {
		mail_storage_set_critical(storage,
					  "Can't write to file %s: %m", path);
	}
}

static void save_header_callback(struct message_part *part __attr_unused__,
				 const unsigned char *name, size_t name_len,
				 const unsigned char *value, size_t value_len,
				 void *context)
{
	struct save_header_context *ctx = context;
	int ret;

	if (ctx->failed)
		return;

	ret = ctx->header_callback(name, name_len, ctx->write_func,
				   ctx->context);
	if (ret <= 0) {
		if (ret < 0)
			ctx->failed = TRUE;
		return;
	}

	if (name_len == 0) {
		name = "\n"; value_len = 1;
	} else {
		if (value[value_len] == '\r')
			value_len++;
		i_assert(value[value_len] == '\n');
		value_len += (size_t) (value-name) + 1;
	}

	if (ctx->write_func(ctx->output, name, value_len) < 0) {
		set_write_error(ctx->storage, ctx->output, ctx->path);
		ctx->failed = TRUE;
	}
}

int index_storage_save(struct mail_storage *storage, const char *path,
		       struct istream *input, struct ostream *output,
		       header_callback_t *header_callback, void *context)
{
	int (*write_func)(struct ostream *, const unsigned char *, size_t);
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	int failed;

	write_func = getenv("MAIL_SAVE_CRLF") ? write_with_crlf : write_with_lf;

	if (header_callback != NULL) {
		struct save_header_context ctx;

		memset(&ctx, 0, sizeof(ctx));
		ctx.storage = storage;
		ctx.output = output;
		ctx.path = path;
		ctx.write_func = write_func;
		ctx.header_callback = header_callback;
		ctx.context = context;

		message_parse_header(NULL, input, NULL,
				     save_header_callback, &ctx);

		if (ctx.failed)
			return FALSE;
	}

	failed = FALSE;
	for (;;) {
		data = i_stream_get_data(input, &size);
		if (!failed) {
			ret = write_func(output, data, size);
			if (ret < 0) {
				set_write_error(storage, output, path);
				failed = TRUE;
			} else {
				size = ret;
			}
		}
		i_stream_skip(input, size);

		ret = i_stream_read(input);
		if (ret < 0) {
			errno = input->stream_errno;
			if (errno == 0) {
				/* EOF */
				if (input->v_offset != input->v_limit) {
					/* too early */
					mail_storage_set_error(storage,
						"Unexpected EOF");
					failed = TRUE;
				}
				break;
			} else if (errno == EAGAIN) {
				mail_storage_set_error(storage,
					"Timeout while waiting for input");
			} else {
				mail_storage_set_critical(storage,
					"Error reading mail from client: %m");
			}
			failed = TRUE;
			break;
		}
	}

	return !failed;
}
