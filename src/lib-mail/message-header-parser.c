/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "message-size.h"
#include "message-header-parser.h"

struct message_header_parser_ctx {
	struct message_header_line line;

	struct istream *input;
	struct message_size *hdr_size;

	string_t *name;
	buffer_t *value_buf;
	size_t skip;

	enum message_header_parser_flags flags;
	unsigned int skip_line:1;
	unsigned int has_nuls:1;
};

struct message_header_parser_ctx *
message_parse_header_init(struct istream *input, struct message_size *hdr_size,
			  enum message_header_parser_flags flags)
{
	struct message_header_parser_ctx *ctx;

	ctx = i_new(struct message_header_parser_ctx, 1);
	ctx->input = input;
	ctx->hdr_size = hdr_size;
	ctx->name = str_new(default_pool, 128);
	ctx->flags = flags;
	ctx->value_buf = buffer_create_dynamic(default_pool, 4096);

	if (hdr_size != NULL)
		memset(hdr_size, 0, sizeof(*hdr_size));
	return ctx;
}

void message_parse_header_deinit(struct message_header_parser_ctx **_ctx)
{
	struct message_header_parser_ctx *ctx = *_ctx;

	i_stream_skip(ctx->input, ctx->skip);
	buffer_free(&ctx->value_buf);
	str_free(&ctx->name);
	i_free(ctx);

	*_ctx = NULL;
}

int message_parse_header_next(struct message_header_parser_ctx *ctx,
			      struct message_header_line **hdr_r)
{
        struct message_header_line *line = &ctx->line;
	const unsigned char *msg;
	size_t i, size, startpos, colon_pos, parse_size;
	int ret;
	bool continued, continues, last_no_newline, last_crlf;
	bool no_newline, crlf_newline;

	*hdr_r = NULL;
	if (line->eoh)
		return -1;

	if (ctx->skip > 0) {
		i_stream_skip(ctx->input, ctx->skip);
		ctx->skip = 0;
	}

	if (line->continues)
		colon_pos = 0;
	else {
		/* new header line */
		line->name_offset = ctx->input->v_offset;
		colon_pos = UINT_MAX;
		buffer_set_used_size(ctx->value_buf, 0);
	}

	no_newline = FALSE;
	crlf_newline = FALSE;
	continued = line->continues;
	continues = FALSE;

	for (startpos = 0;;) {
		ret = i_stream_read_data(ctx->input, &msg, &size, startpos+1);
		if (ret >= 0) {
			/* we want to know one byte in advance to find out
			   if it's multiline header */
			parse_size = size == 0 ? 0 : size-1;
		} else {
			parse_size = size;
		}

		if (ret <= 0 && startpos == parse_size) {
			if (ret == -1) {
				if (startpos > 0) {
					/* header ended unexpectedly. */
					no_newline = TRUE;
					ctx->skip = startpos;
					break;
				}
				/* error / EOF with no bytes */
				return -1;
			}

			if (size > 0 && !ctx->skip_line &&
			    (msg[0] == '\n' ||
			     (msg[0] == '\r' && size > 1 && msg[1] == '\n'))) {
				/* end of headers - this mostly happens just
				   with mbox where headers are read separately
				   from body */
				size = 0;
				if (ctx->hdr_size != NULL)
					ctx->hdr_size->lines++;
				if (msg[0] == '\r') {
					ctx->skip = 2;
					crlf_newline = TRUE;
				} else {
					ctx->skip = 1;
					if (ctx->hdr_size != NULL)
						ctx->hdr_size->virtual_size++;
				}
				break;
			}
			if (ret == 0 && !ctx->input->eof) {
				/* stream is nonblocking - need more data */
				return 0;
			}
			i_assert(size > 0);

			/* a) line is larger than input buffer
			   b) header ended unexpectedly */
			if (colon_pos == UINT_MAX && ret == -2 && !continued) {
				/* header name is huge. just skip it. */
				i_assert(size > 1);
				if (msg[size-1] == '\r')
					size--;

				if (ctx->hdr_size != NULL) {
					ctx->hdr_size->physical_size += size;
					ctx->hdr_size->virtual_size += size;
				}
				i_stream_skip(ctx->input, size);
				ctx->skip_line = TRUE;
				startpos = 0;
				continue;
			}

			if (ret == -2) {
				/* go back to last LWSP if found. */
				size_t min_pos = !continued ? colon_pos : 0;
				for (i = size-1; i > min_pos; i--) {
					if (IS_LWSP(msg[i])) {
						size = i;
						break;
					}
				}

				continues = TRUE;
			}
			no_newline = TRUE;
			ctx->skip = size;
			break;
		}

		/* find ':' */
		if (colon_pos == UINT_MAX) {
			for (i = startpos; i < parse_size; i++) {
				if (msg[i] > ':')
					continue;

				if (msg[i] == ':' && !ctx->skip_line) {
					colon_pos = i;
					line->full_value_offset =
						ctx->input->v_offset + i + 1;
					break;
				}
				if (msg[i] == '\n') {
					/* end of headers, or error */
					break;
				}

				if (msg[i] == '\0')
					ctx->has_nuls = TRUE;
			}
		} else {
			i = startpos;
		}

		/* find '\n' */
		for (; i < parse_size; i++) {
			if (msg[i] <= '\n') {
				if (msg[i] == '\n')
					break;
				if (msg[i] == '\0')
					ctx->has_nuls = TRUE;
			}
		}

		if (i < parse_size) {
			/* got a line */
			if (ctx->skip_line) {
				/* skipping a line with a huge header name */
				if (ctx->hdr_size != NULL) {
					ctx->hdr_size->lines++;
					ctx->hdr_size->physical_size += i + 1;
					ctx->hdr_size->virtual_size += i + 1;
				}
				if (i == 0 || msg[i-1] != '\r') {
					/* missing CR */
					if (ctx->hdr_size != NULL)
						ctx->hdr_size->virtual_size++;
				}

				i_stream_skip(ctx->input, i + 1);
				startpos = 0;
				ctx->skip_line = FALSE;
				continue;
			}
			continues = i+1 < size && IS_LWSP(msg[i+1]);

			if (ctx->hdr_size != NULL)
				ctx->hdr_size->lines++;
			if (i == 0 || msg[i-1] != '\r') {
				/* missing CR */
				if (ctx->hdr_size != NULL)
					ctx->hdr_size->virtual_size++;
				size = i;
			} else {
				size = i-1;
				crlf_newline = TRUE;
			}

			ctx->skip = i+1;
			break;
		}

		startpos = i;
	}

	last_crlf = line->crlf_newline &&
		(ctx->flags & MESSAGE_HEADER_PARSER_FLAG_DROP_CR) == 0;
	last_no_newline = line->no_newline ||
		(ctx->flags & MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE) != 0;

	line->continues = continues;
	line->continued = continued;
	line->crlf_newline = crlf_newline;
	line->no_newline = no_newline;
	if (size == 0) {
		/* end of headers */
		line->eoh = TRUE;
		line->name_len = line->value_len = line->full_value_len = 0;
		line->name = ""; line->value = line->full_value = NULL;
		line->middle = NULL; line->middle_len = 0;
		line->full_value_offset = line->name_offset;
		line->continues = FALSE;
	} else if (line->continued) {
		line->value = msg;
		line->value_len = size;
	} else if (colon_pos == UINT_MAX) {
		/* missing ':', assume the whole line is name */
		line->value = NULL;
		line->value_len = 0;

		str_truncate(ctx->name, 0);
		buffer_append(ctx->name, msg, size);
		line->name = str_c(ctx->name);
		line->name_len = str_len(ctx->name);

		line->middle = NULL;
		line->middle_len = 0;
	} else {
		size_t pos;

		line->value = msg + colon_pos+1;
		line->value_len = size - colon_pos - 1;
		if (ctx->flags & MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP) {
			/* get value. skip all LWSP after ':'. Note that
			   RFC2822 doesn't say we should, but history behind
			   it..

			   Exception to this is if the value consists only of
			   LWSP, then skip only the one LWSP after ':'. */
			for (pos = 0; pos < line->value_len; pos++) {
				if (!IS_LWSP(line->value[pos]))
					break;
			}

			if (pos == line->value_len) {
				/* everything was LWSP */
				if (line->value_len > 0 &&
				    IS_LWSP(line->value[0]))
					pos = 1;
			}
		} else {
			pos = line->value_len > 0 &&
				IS_LWSP(line->value[0]) ? 1 : 0;
		}

		line->value += pos;
		line->value_len -= pos;
		line->full_value_offset += pos;

		/* get name, skip LWSP before ':' */
		while (colon_pos > 0 && IS_LWSP(msg[colon_pos-1]))
			colon_pos--;

		str_truncate(ctx->name, 0);
		/* use buffer_append() so the name won't be truncated if there
		   are NULs. */
		buffer_append(ctx->name, msg, colon_pos);
		str_append_c(ctx->name, '\0');

		/* keep middle stored also in ctx->name so it's available
		   with use_full_value */
		line->middle = msg + colon_pos;
		line->middle_len = (size_t)(line->value - line->middle);
		str_append_n(ctx->name, line->middle, line->middle_len);

		line->name = str_c(ctx->name);
		line->name_len = colon_pos;
		line->middle = str_data(ctx->name) + line->name_len + 1;
	}

	if (!line->continued) {
		/* first header line. make a copy of the line since we can't
		   really trust input stream not to lose it. */
		buffer_append(ctx->value_buf, line->value, line->value_len);
		line->value = line->full_value = ctx->value_buf->data;
		line->full_value_len = line->value_len;
	} else if (line->use_full_value) {
		/* continue saving the full value. */
		if (last_no_newline) {
			/* line is longer than fit into our buffer, so we
			   were forced to break it into multiple
			   message_header_lines */
		} else {
			if (last_crlf)
				buffer_append_c(ctx->value_buf, '\r');
			buffer_append_c(ctx->value_buf, '\n');
		}
		if ((ctx->flags & MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE) &&
		    line->value_len > 0 && line->value[0] != ' ' &&
		    IS_LWSP(line->value[0])) {
			buffer_append_c(ctx->value_buf, ' ');
			buffer_append(ctx->value_buf,
				      line->value + 1, line->value_len - 1);
		} else {
			buffer_append(ctx->value_buf,
				      line->value, line->value_len);
		}
		line->full_value = buffer_get_data(ctx->value_buf,
						   &line->full_value_len);
	} else {
		/* we didn't want full_value, and this is a continued line. */
		line->full_value = NULL;
		line->full_value_len = 0;
	}

	/* always reset it */
	line->use_full_value = FALSE;

	if (ctx->hdr_size != NULL) {
		ctx->hdr_size->physical_size += ctx->skip;
		ctx->hdr_size->virtual_size += ctx->skip;
	}

	*hdr_r = line;
	return 1;
}

bool message_parse_header_has_nuls(const struct message_header_parser_ctx *ctx)
{
	return ctx->has_nuls;
}

#undef message_parse_header
void message_parse_header(struct istream *input, struct message_size *hdr_size,
			  enum message_header_parser_flags flags,
			  message_header_callback_t *callback, void *context)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	int ret;

	hdr_ctx = message_parse_header_init(input, hdr_size, flags);
	while ((ret = message_parse_header_next(hdr_ctx, &hdr)) > 0)
		callback(hdr, context);
	i_assert(ret != 0);
	message_parse_header_deinit(&hdr_ctx);

	/* call after the final skipping */
	callback(NULL, context);
}
