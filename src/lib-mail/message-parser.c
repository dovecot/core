/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "strescape.h"
#include "message-content-parser.h"
#include "message-parser.h"
#include "message-size.h"

struct message_boundary {
	struct message_boundary *next;

	struct message_part *part;
	const char *boundary;
	size_t len;
};

struct message_parser_ctx {
	pool_t parser_pool, part_pool;
	struct istream *input;
	struct message_part *parts, *part;

	char *last_boundary;
	char *last_content_type;
	struct message_boundary *boundaries;

	message_header_callback_t *callback;
	message_body_callback_t *body_callback;
	void *context;
};

struct message_header_parser_ctx {
	struct message_header_line line;

	struct istream *input;
	struct message_size *hdr_size;

	string_t *name;
	buffer_t *value_buf;
	size_t skip;

	int has_nuls;
};

static void
message_parse_part_header(struct message_parser_ctx *parser_ctx);

static struct message_part *
message_parse_part_body(struct message_parser_ctx *parser_ctx);

static struct message_part *
message_parse_body(struct message_parser_ctx *parser_ctx,
		   struct message_boundary *boundaries,
		   struct message_size *msg_size, int *has_nuls);

static struct message_part *
message_skip_boundary(struct message_parser_ctx *parser_ctx,
		      struct message_boundary *boundaries,
		      struct message_size *boundary_size, int *has_nuls);

static void message_size_add_part(struct message_size *dest,
				  struct message_part *part)
{
	dest->physical_size +=
		part->header_size.physical_size +
		part->body_size.physical_size;
	dest->virtual_size +=
		part->header_size.virtual_size +
		part->body_size.virtual_size;
	dest->lines += part->header_size.lines + part->body_size.lines;
}

static struct message_part *
message_part_append(pool_t pool, struct message_part *parent)
{
	struct message_part *part, **list;

	part = p_new(pool, struct message_part, 1);
	part->parent = parent;

	/* set child position */
	part->physical_pos =
		parent->physical_pos +
		parent->body_size.physical_size +
		parent->header_size.physical_size;

	list = &part->parent->children;
	while (*list != NULL)
		list = &(*list)->next;

	*list = part;
	return part;
}

static void parse_content_type(const unsigned char *value, size_t value_len,
			       void *context)
{
	struct message_parser_ctx *parser_ctx = context;
	const char *str;

	if (parser_ctx->last_content_type != NULL || value_len == 0)
		return;

	str = parser_ctx->last_content_type =
		p_strndup(parser_ctx->parser_pool, value, value_len);

	if (strcasecmp(str, "message/rfc822") == 0)
		parser_ctx->part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
	else if (strncasecmp(str, "text", 4) == 0 &&
		 (str[4] == '/' || str[4] == '\0'))
		parser_ctx->part->flags |= MESSAGE_PART_FLAG_TEXT;
	else if (strncasecmp(str, "multipart/", 10) == 0) {
		parser_ctx->part->flags |= MESSAGE_PART_FLAG_MULTIPART;

		if (strcasecmp(str+10, "digest") == 0) {
			parser_ctx->part->flags |=
				MESSAGE_PART_FLAG_MULTIPART_DIGEST;
		}
	}
}

static void
parse_content_type_param(const unsigned char *name, size_t name_len,
			 const unsigned char *value, size_t value_len,
			 int value_quoted, void *context)
{
	struct message_parser_ctx *parser_ctx = context;

	if ((parser_ctx->part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
	    name_len != 8 || memcasecmp(name, "boundary", 8) != 0)
		return;

	if (parser_ctx->last_boundary == NULL) {
		parser_ctx->last_boundary =
			p_strndup(parser_ctx->parser_pool, value, value_len);
		if (value_quoted)
			str_unescape(parser_ctx->last_boundary);
	}
}

static struct message_part *
message_parse_multipart(struct message_parser_ctx *parser_ctx)
{
	struct message_part *parent_part, *next_part, *part;
	struct message_boundary *b;
	int has_nuls;

	/* multipart message. add new boundary */
	b = p_new(parser_ctx->parser_pool, struct message_boundary, 1);
	b->part = parser_ctx->part;
	b->boundary = parser_ctx->last_boundary;
	b->len = strlen(b->boundary);

	b->next = parser_ctx->boundaries;
	parser_ctx->boundaries = b;

	/* reset fields */
	parser_ctx->last_boundary = NULL;
	parser_ctx->last_content_type = NULL;

	/* skip the data before the first boundary */
	parent_part = parser_ctx->part;
	next_part = message_skip_boundary(parser_ctx, parser_ctx->boundaries,
					  &parent_part->body_size, &has_nuls);
	if (has_nuls)
		parent_part->flags |= MESSAGE_PART_FLAG_HAS_NULS;

	/* now, parse the parts */
	while (next_part == parent_part) {
		/* new child */
		part = message_part_append(parser_ctx->part_pool, parent_part);
		if ((parent_part->flags & MESSAGE_PART_FLAG_IS_MIME) != 0)
			part->flags |= MESSAGE_PART_FLAG_IS_MIME;

		parser_ctx->part = part;
                message_parse_part_header(parser_ctx);
		next_part = message_parse_part_body(parser_ctx);

		if ((part->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
			/* it also belongs to parent */
			parent_part->flags |= MESSAGE_PART_FLAG_HAS_NULS;
		}

		/* update our size */
		message_size_add_part(&parent_part->body_size, part);

		if (next_part != parent_part)
			break;

		/* skip the boundary */
		next_part = message_skip_boundary(parser_ctx,
						  parser_ctx->boundaries,
						  &parent_part->body_size,
						  &has_nuls);
		if (has_nuls)
			parent_part->flags |= MESSAGE_PART_FLAG_HAS_NULS;
	}

	/* remove boundary */
	i_assert(parser_ctx->boundaries == b);
	parser_ctx->boundaries = b->next;
	return next_part;
}

#define MUTEX_FLAGS \
	(MESSAGE_PART_FLAG_MESSAGE_RFC822 | MESSAGE_PART_FLAG_MULTIPART)

static void message_parse_part_header(struct message_parser_ctx *parser_ctx)
{
	struct message_part *part = parser_ctx->part;
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;

	hdr_ctx = message_parse_header_init(parser_ctx->input,
					    &part->header_size);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL) {
		/* call the user-defined header parser */
		if (parser_ctx->callback != NULL)
			parser_ctx->callback(part, hdr, parser_ctx->context);

		if (!hdr->eoh && strcasecmp(hdr->name, "Mime-Version") == 0) {
			/* it's MIME. Content-* headers are valid */
			part->flags |= MESSAGE_PART_FLAG_IS_MIME;
		}

		if (!hdr->eoh && strcasecmp(hdr->name, "Content-Type") == 0) {
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				continue;
			}
			/* we need to know the boundary */
			message_content_parse_header(hdr->full_value,
						     hdr->full_value_len,
						     parse_content_type,
						     parse_content_type_param,
						     parser_ctx);
		}
	}

	if ((part->flags & MESSAGE_PART_FLAG_IS_MIME) == 0) {
		/* It's not MIME. Reset everything we found from
		   Content-Type. */
		part->flags = 0;
                parser_ctx->last_boundary = NULL;
		parser_ctx->last_content_type = NULL;
	}
	if (parser_ctx->callback != NULL)
		parser_ctx->callback(part, NULL, parser_ctx->context);
	if (hdr_ctx->has_nuls)
		part->flags |= MESSAGE_PART_FLAG_HAS_NULS;
	message_parse_header_deinit(hdr_ctx);

	i_assert((part->flags & MUTEX_FLAGS) != MUTEX_FLAGS);
}

static struct message_part *
message_parse_part_body(struct message_parser_ctx *parser_ctx)
{
	struct message_part *part = parser_ctx->part;
        struct message_part *next_part;
	int has_nuls;

	if (parser_ctx->last_boundary != NULL)
		return message_parse_multipart(parser_ctx);

	if (parser_ctx->last_content_type == NULL) {
		if (part->parent != NULL &&
		    (part->parent->flags &
		     MESSAGE_PART_FLAG_MULTIPART_DIGEST)) {
			/* when there's no content-type specified and we're
			   below multipart/digest, the assume message/rfc822
			   content-type */
			part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
		} else {
			/* otherwise we default to text/plain */
			part->flags |= MESSAGE_PART_FLAG_TEXT;
		}
	}

	parser_ctx->last_boundary = NULL;
        parser_ctx->last_content_type = NULL;

	if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		/* message/rfc822 part - the message body begins with
		   headers again, this works pretty much the same as
		   a single multipart/mixed item */
		part = message_part_append(parser_ctx->part_pool, part);

		parser_ctx->part = part;
		message_parse_part_header(parser_ctx);
		next_part = message_parse_part_body(parser_ctx);
		parser_ctx->part = part->parent;

		/* our body size is the size of header+body in message/rfc822 */
		message_size_add_part(&part->parent->body_size, part);
	} else {
		/* normal message, read until the next boundary */
		next_part = message_parse_body(parser_ctx,
					       parser_ctx->boundaries,
					       &part->body_size, &has_nuls);
		if (has_nuls)
			part->flags |= MESSAGE_PART_FLAG_HAS_NULS;
	}

	if ((part->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0 &&
	    part->parent != NULL) {
		/* it also belongs to parent */
		part->parent->flags |= MESSAGE_PART_FLAG_HAS_NULS;
	}

	return next_part;
}

static void message_skip_line(struct istream *input,
			      struct message_size *msg_size, int skip_lf,
			      int *has_nuls)
{
	const unsigned char *msg;
	size_t i, size, startpos;

	startpos = 0;
	*has_nuls = FALSE;

	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] == '\0')
				*has_nuls = TRUE;
			else if (msg[i] == '\n') {
				if (!skip_lf) {
					if (i > 0 && msg[i-1] == '\r')
						i--;
					startpos = i;
					goto __break;
				}

				if (msg_size != NULL) {
					if (i == 0 || msg[i-1] != '\r')
						msg_size->virtual_size++;
					msg_size->lines++;
				}
				startpos = i+1;
				goto __break;
			}
		}

		/* leave the last character, it may be \r */
		i_stream_skip(input, i - 1);
		startpos = 1;

		if (msg_size != NULL) {
			msg_size->physical_size += i - 1;
			msg_size->virtual_size += i - 1;
		}
	}
__break:
	i_stream_skip(input, startpos);

	if (msg_size != NULL) {
		msg_size->physical_size += startpos;
		msg_size->virtual_size += startpos;
	}
}

static struct message_boundary *
boundary_find(struct message_boundary *boundaries,
	      const unsigned char *msg, size_t len)
{
	while (boundaries != NULL) {
		if (boundaries->len <= len &&
		    memcmp(boundaries->boundary, msg, boundaries->len) == 0)
			return boundaries;

		boundaries = boundaries->next;
	}

	return NULL;
}

/* read until next boundary is found. if skip_over = FALSE, stop at the
   [\r]\n before the boundary, otherwise leave it right after the known
   boundary so the ending "--" can be checked. */
static struct message_boundary *
message_find_boundary(struct istream *input,
		      struct message_boundary *boundaries,
		      struct message_size *msg_size, int skip_over,
		      int *has_nuls)
{
	struct message_boundary *boundary;
	const unsigned char *msg;
	size_t i, size, startpos, line_start, missing_cr_count;

	boundary = NULL;
	missing_cr_count = startpos = line_start = 0;
	*has_nuls = FALSE;

	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] != '\n') {
				if (msg[i] == '\0')
					*has_nuls = TRUE;
				continue;
			}

			if (line_start != (size_t)-1 &&
			    i >= line_start+2 && msg[line_start] == '-' &&
			    msg[line_start+1] == '-') {
				/* possible boundary */
				boundary = boundary_find(boundaries,
							 msg + line_start + 2,
							 i - line_start - 2);
				if (boundary != NULL)
					break;
			}

			if (i == 0 || msg[i-1] != '\r') {
				/* missing CR */
				missing_cr_count++;
			}

			msg_size->lines++;
			line_start = i+1;
		}

		if (boundary != NULL)
			break;

		if (line_start == (size_t)-1) {
			/* continued long line, continue skipping over it */
		} else if (i - line_start > 128) {
			/* long partial line, see if it's a boundary.
			   RFC-2046 says that the boundaries must be
			   70 chars without "--" or less. We allow
			   a bit larger.. */
			if (msg[line_start] == '-' &&
			    msg[line_start+1] == '-') {
				boundary = boundary_find(boundaries,
							 msg + line_start + 2,
							 i - line_start - 2);
				if (boundary != NULL)
					break;
			}

			/* nope, we can skip over the line, just
			   leave the last char since it may be \r */
			i--;
			line_start = (size_t)-1;
		} else {
			/* leave the last line to buffer, it may be
			   boundary */
			i = line_start;
			if (i > 0) i--; /* leave the \r\n too */
			if (i > 0) i--;
			line_start -= i;
		}

		i_stream_skip(input, i);
		msg_size->physical_size += i;
		msg_size->virtual_size += i;

		startpos = size - i;
	}

	if (boundary == NULL &&
	    line_start != (size_t)-1 && line_start+2 <= size &&
	    msg[line_start] == '-' && msg[line_start+1] == '-') {
		/* possible boundary without line feed at end */
		boundary = boundary_find(boundaries,
					 msg + line_start + 2,
					 size - line_start - 2);
	}

	if (boundary != NULL) {
		i_assert(line_start != (size_t)-1);
		if (skip_over) {
			/* leave the pointer right after the boundary */
			line_start += 2 + boundary->len;
		} else if (line_start > 0 && msg[line_start-1] == '\n') {
			/* leave the \r\n before the boundary */
			line_start--;
			msg_size->lines--;

			if (line_start > 0 && msg[line_start-1] == '\r')
				line_start--;
			else
				missing_cr_count--;
		}
		startpos = line_start;
	}

	i_stream_skip(input, startpos);
	msg_size->physical_size += startpos;
	msg_size->virtual_size += startpos + missing_cr_count;

	i_assert(msg_size->virtual_size >= msg_size->physical_size);

	return boundary;
}

static struct message_part *
message_parse_body(struct message_parser_ctx *parser_ctx,
		   struct message_boundary *boundaries,
		   struct message_size *msg_size, int *has_nuls)
{
	struct message_boundary *boundary;
	struct message_size body_size;

	if (boundaries == NULL) {
		message_get_body_size(parser_ctx->input, &body_size, has_nuls);
		message_size_add(msg_size, &body_size);
		boundary = NULL;
	} else {
		boundary = message_find_boundary(parser_ctx->input, boundaries,
						 msg_size, FALSE, has_nuls);
	}

	return boundary == NULL ? NULL : boundary->part;
}

/* skip data until next boundary is found. if it's end boundary,
   skip the footer as well. */
static struct message_part *
message_skip_boundary(struct message_parser_ctx *parser_ctx,
		      struct message_boundary *boundaries,
		      struct message_size *boundary_size, int *has_nuls)
{
	struct message_boundary *boundary;
	const unsigned char *msg;
	size_t size;
	int end_boundary;

	boundary = message_find_boundary(parser_ctx->input, boundaries,
					 boundary_size, TRUE, has_nuls);
	if (boundary == NULL)
		return NULL;

	/* now, see if it's end boundary */
	end_boundary = FALSE;
	if (i_stream_read_data(parser_ctx->input, &msg, &size, 1) > 0)
		end_boundary = msg[0] == '-' && msg[1] == '-';

	/* skip the rest of the line */
	message_skip_line(parser_ctx->input, boundary_size,
			  !end_boundary, has_nuls);

	if (end_boundary) {
		/* skip the footer */
		return message_parse_body(parser_ctx, boundary->next,
					  boundary_size, has_nuls);
	}

	return boundary == NULL ? NULL : boundary->part;
}

struct message_parser_ctx *
message_parser_init(pool_t part_pool, struct istream *input)
{
	struct message_parser_ctx *ctx;
	pool_t pool;

	pool = pool_alloconly_create("Message Parser", 1024);
	ctx = p_new(pool, struct message_parser_ctx, 1);
	ctx->parser_pool = pool;
	ctx->part_pool = part_pool;
	ctx->input = input;
	ctx->parts = ctx->part = p_new(part_pool, struct message_part, 1);
	return ctx;
}

struct message_part *message_parser_deinit(struct message_parser_ctx *ctx)
{
	struct message_part *parts = ctx->parts;

	pool_unref(ctx->parser_pool);
	return parts;
}

void message_parser_parse_header(struct message_parser_ctx *ctx,
				 struct message_size *hdr_size,
				 message_header_callback_t *callback,
				 void *context)
{
	ctx->callback = callback;
	ctx->context = context;

	message_parse_part_header(ctx);
        *hdr_size = ctx->part->header_size;
}

void message_parser_parse_body(struct message_parser_ctx *ctx,
			       message_header_callback_t *hdr_callback,
			       message_body_callback_t *body_callback,
			       void *context)
{
	ctx->callback = hdr_callback;
	ctx->body_callback = body_callback;
	ctx->context = context;

	message_parse_part_body(ctx);
}

static void part_parse_headers(struct message_part *part, struct istream *input,
			       message_header_callback_t *callback,
			       void *context)
{
	while (part != NULL) {
		/* note that we want to parse the header of all
		   the message parts, multiparts too. */
		i_assert(part->physical_pos >= input->v_offset);
		i_stream_skip(input, part->physical_pos - input->v_offset);

		message_parse_header(part, input, NULL, callback, context);
		if (part->children != NULL) {
			part_parse_headers(part->children, input,
					   callback, context);
		}

		part = part->next;
	}
}

void message_parse_from_parts(struct message_part *part, struct istream *input,
			      message_header_callback_t *callback,
			      void *context)
{
	part_parse_headers(part, input, callback, context);
}

void message_parse_header(struct message_part *part, struct istream *input,
			  struct message_size *hdr_size,
			  message_header_callback_t *callback, void *context)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;

	hdr_ctx = message_parse_header_init(input, hdr_size);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL)
		callback(part, hdr, context);
	message_parse_header_deinit(hdr_ctx);

	/* call after the final skipping */
	callback(part, NULL, context);
}

struct message_header_parser_ctx *
message_parse_header_init(struct istream *input, struct message_size *hdr_size)
{
	struct message_header_parser_ctx *ctx;

	ctx = i_new(struct message_header_parser_ctx, 1);
	ctx->input = input;
	ctx->hdr_size = hdr_size;
	ctx->name = str_new(default_pool, 128);

	if (hdr_size != NULL)
		memset(hdr_size, 0, sizeof(*hdr_size));
	return ctx;
}

void message_parse_header_deinit(struct message_header_parser_ctx *ctx)
{
	i_stream_skip(ctx->input, ctx->skip);
	if (ctx->value_buf != NULL)
		buffer_free(ctx->value_buf);
	str_free(ctx->name);
	i_free(ctx);
}

struct message_header_line *
message_parse_header_next(struct message_header_parser_ctx *ctx)
{
        struct message_header_line *line = &ctx->line;
	const unsigned char *msg;
	size_t i, size, startpos, colon_pos, parse_size;
	int ret;

	if (line->eoh)
		return NULL;

	if (ctx->skip > 0) {
		i_stream_skip(ctx->input, ctx->skip);
		ctx->skip = 0;
	}

	startpos = 0; colon_pos = UINT_MAX;

	line->no_newline = FALSE;

	if (line->continues) {
		if (line->use_full_value && !line->continued) {
			/* save the first line */
			if (ctx->value_buf != NULL)
				buffer_set_used_size(ctx->value_buf, 0);
			else {
				ctx->value_buf =
					buffer_create_dynamic(default_pool,
							      4096, (size_t)-1);
			}
			buffer_append(ctx->value_buf,
				      line->value, line->value_len);
		}

		line->continued = TRUE;
		line->continues = FALSE;
		colon_pos = 0;
	} else {
		/* new header line */
		line->continued = FALSE;
                line->name_offset = ctx->input->v_offset;
	}

	for (;;) {
		ret = i_stream_read_data(ctx->input, &msg, &size, startpos+1);

		if (ret != 0) {
			/* we want to know one byte in advance to find out
			   if it's multiline header */
			parse_size = size-1;
		} else {
			parse_size = size;
		}

		if (ret <= 0 && (ret != 0 || startpos == size)) {
			if (ret == -1) {
				/* error / EOF with no bytes */
				return NULL;
			}

			if (msg[0] == '\n' ||
			    (msg[0] == '\r' && size > 1 && msg[1] == '\n')) {
				/* end of headers - this mostly happens just
				   with mbox where headers are read separately
				   from body */
				size = 0;
				if (ctx->hdr_size != NULL)
					ctx->hdr_size->lines++;
				if (msg[0] == '\r')
					ctx->skip = 2;
				else {
					ctx->skip = 1;
					if (ctx->hdr_size != NULL)
						ctx->hdr_size->virtual_size++;
				}
				break;
			}

			/* a) line is larger than input buffer
			   b) header ended unexpectedly */
			if (colon_pos == UINT_MAX) {
				/* header name is huge. just skip it. */
				message_skip_line(ctx->input, ctx->hdr_size,
						  TRUE, &ctx->has_nuls);
				continue;
			}

			/* go back to last LWSP if found. */
			for (i = size-1; i > colon_pos; i--) {
				if (IS_LWSP(msg[i])) {
					size = i;
					break;
				}
			}

			line->no_newline = TRUE;
			line->continues = TRUE;
			ctx->skip = size;
			break;
		}

		/* find ':' */
		if (colon_pos == UINT_MAX) {
			for (i = startpos; i < parse_size; i++) {
				if (msg[i] <= ':') {
					if (msg[i] == ':') {
						colon_pos = i;
						// FIXME: correct?
						line->full_value_offset =
							ctx->input->v_offset +
							i + 1;
						break;
					}
					if (msg[i] == '\n') {
						/* end of headers, or error */
						break;
					}

					if (msg[i] == '\0')
						ctx->has_nuls = TRUE;
				}
			}
		}

		/* find '\n' */
		for (i = startpos; i < parse_size; i++) {
			if (msg[i] <= '\n') {
				if (msg[i] == '\n')
					break;
				if (msg[i] == '\0')
					ctx->has_nuls = TRUE;
			}
		}

		if (i < parse_size) {
			/* got a line */
			line->continues = i+1 < size && IS_LWSP(msg[i+1]);

			if (ctx->hdr_size != NULL)
				ctx->hdr_size->lines++;
			if (i == 0 || msg[i-1] != '\r') {
				/* missing CR */
				if (ctx->hdr_size != NULL)
					ctx->hdr_size->virtual_size++;
				size = i;
			} else {
				size = i-1;
			}

			ctx->skip = i+1;
			break;
		}

		startpos = i;
	}

	if (size == 0) {
		/* end of headers */
		line->eoh = TRUE;
		line->name_len = line->value_len = line->full_value_len = 0;
		line->name = ""; line->value = line->full_value = NULL;
	} else if (line->continued) {
		line->value = msg;
		line->value_len = size;
	} else if (colon_pos == UINT_MAX) {
		/* missing ':', assume the whole line is name */
		line->value = NULL;
		line->value_len = 0;

		str_truncate(ctx->name, 0);
		str_append_n(ctx->name, msg, size);
		line->name = str_c(ctx->name);
		line->name_len = str_len(ctx->name);
	} else {
		/* get value. skip all LWSP after ':'. Note that RFC2822
		   doesn't say we should, but history behind it.. */
		line->value = msg + colon_pos+1;
		line->value_len = size - colon_pos - 1;
		while (line->value_len > 0 &&
		       IS_LWSP(line->value[0])) {
			line->value++;
			line->value_len--;
		}

		/* get name, skip LWSP before ':' */
		while (colon_pos > 0 && IS_LWSP(msg[colon_pos-1]))
			colon_pos--;

		str_truncate(ctx->name, 0);
		str_append_n(ctx->name, msg, colon_pos);
		line->name = str_c(ctx->name);
		line->name_len = str_len(ctx->name);
	}

	if (!line->continued) {
		/* first header line, set full_value = value */
		line->full_value = line->value;
		line->full_value_len = line->value_len;
	} else if (line->use_full_value) {
		/* continue saving the full value */
		buffer_append(ctx->value_buf, line->value, line->value_len);
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
	return line;
}
