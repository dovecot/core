/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
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

struct parser_context {
	pool_t pool;
	struct message_part *part;

	char *last_boundary;
	char *last_content_type;
	struct message_boundary *boundaries;

	message_header_callback_t *callback;
	void *context;
};

static struct message_part *
message_parse_part(struct istream *input,
		   struct parser_context *parser_ctx);

static struct message_part *
message_parse_body(struct istream *input, struct message_boundary *boundaries,
		   struct message_size *body_size);

static struct message_part *
message_skip_boundary(struct istream *input,
		      struct message_boundary *boundaries,
		      struct message_size *boundary_size);

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
	struct parser_context *parser_ctx = context;
	const char *str;

	if (parser_ctx->last_content_type != NULL || value_len == 0)
		return;

	str = parser_ctx->last_content_type =
		p_strndup(parser_ctx->pool, value, value_len);

	if (strcasecmp(str, "message/rfc822") == 0)
		parser_ctx->part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
	else if (strncasecmp(str, "text/", 5) == 0)
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
	struct parser_context *parser_ctx = context;

	if ((parser_ctx->part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
	    name_len != 8 || memcasecmp(name, "boundary", 8) != 0)
		return;

	if (parser_ctx->last_boundary == NULL) {
		parser_ctx->last_boundary =
			p_strndup(parser_ctx->pool, value, value_len);
		if (value_quoted)
			str_unescape(parser_ctx->last_boundary);
	}
}

static void parse_header_field(struct message_part *part,
			       const unsigned char *name, size_t name_len,
			       const unsigned char *value, size_t value_len,
			       void *context)
{
	struct parser_context *parser_ctx = context;

	/* call the user-defined header parser */
	if (parser_ctx->callback != NULL) {
		parser_ctx->callback(part, name, name_len, value, value_len,
				     parser_ctx->context);
	}

	if (name_len == 12 && memcasecmp(name, "Content-Type", 12) == 0) {
		/* we need to know the boundary */
		message_content_parse_header(value, value_len,
					     parse_content_type,
					     parse_content_type_param,
					     parser_ctx);
	}
}

static struct message_part *
message_parse_multipart(struct istream *input,
			struct parser_context *parser_ctx)
{
	struct message_part *parent_part, *next_part, *part;
	struct message_boundary *b;

	/* multipart message. add new boundary */
	b = t_new(struct message_boundary, 1);
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
	next_part = message_skip_boundary(input, parser_ctx->boundaries,
					  &parent_part->body_size);

	/* now, parse the parts */
	while (next_part == parent_part) {
		/* new child */
		part = message_part_append(parser_ctx->pool, parent_part);

                parser_ctx->part = part;
		next_part = message_parse_part(input, parser_ctx);

		/* update our size */
		message_size_add_part(&parent_part->body_size, part);

		if (next_part != parent_part)
			break;

		/* skip the boundary */
		next_part = message_skip_boundary(input, parser_ctx->boundaries,
						  &parent_part->body_size);
	}

	/* remove boundary */
	i_assert(parser_ctx->boundaries == b);
	parser_ctx->boundaries = b->next;
	return next_part;
}

#define MUTEX_FLAGS \
	(MESSAGE_PART_FLAG_MESSAGE_RFC822 | MESSAGE_PART_FLAG_MULTIPART)

static struct message_part *
message_parse_part(struct istream *input, struct parser_context *parser_ctx)
{
	struct message_part *next_part, *part;
	uoff_t hdr_size;

	message_parse_header(parser_ctx->part, input,
			     &parser_ctx->part->header_size,
			     parse_header_field, parser_ctx);

	i_assert((parser_ctx->part->flags & MUTEX_FLAGS) != MUTEX_FLAGS);

	/* update message position/size */
	hdr_size = parser_ctx->part->header_size.physical_size;

	if (parser_ctx->last_boundary != NULL)
		return message_parse_multipart(input, parser_ctx);

	if (parser_ctx->last_content_type == NULL) {
		if (parser_ctx->part->parent != NULL &&
		    (parser_ctx->part->parent->flags &
		     MESSAGE_PART_FLAG_MULTIPART_DIGEST)) {
			/* when there's no content-type specified and we're
			   below multipart/digest, the assume message/rfc822
			   content-type */
			parser_ctx->part->flags |=
				MESSAGE_PART_FLAG_MESSAGE_RFC822;
		} else {
			/* otherwise we default to text/plain */
			parser_ctx->part->flags |= MESSAGE_PART_FLAG_TEXT;
		}
	}

	parser_ctx->last_boundary = NULL;
        parser_ctx->last_content_type = NULL;

	if (parser_ctx->part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		/* message/rfc822 part - the message body begins with
		   headers again, this works pretty much the same as
		   a single multipart/mixed item */
		part = message_part_append(parser_ctx->pool, parser_ctx->part);

		parser_ctx->part = part;
		next_part = message_parse_part(input, parser_ctx);
		parser_ctx->part = part->parent;

		/* our body size is the size of header+body in message/rfc822 */
		message_size_add_part(&part->parent->body_size, part);
	} else {
		/* normal message, read until the next boundary */
		part = parser_ctx->part;
		next_part = message_parse_body(input, parser_ctx->boundaries,
					       &part->body_size);
	}

	return next_part;
}

struct message_part *message_parse(pool_t pool, struct istream *input,
				   message_header_callback_t *callback,
				   void *context)
{
	struct message_part *part;
	struct parser_context parser_ctx;

	memset(&parser_ctx, 0, sizeof(parser_ctx));
	parser_ctx.pool = pool;
	parser_ctx.callback = callback;
	parser_ctx.context = context;
	parser_ctx.part = part = p_new(pool, struct message_part, 1);

	message_parse_part(input, &parser_ctx);
	return part;
}

/* skip over to next line increasing message size */
static void message_skip_line(struct istream *input,
			      struct message_size *msg_size)
{
	const unsigned char *msg;
	size_t i, size, startpos;

	startpos = 0;

	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] == '\n') {
				if (msg_size != NULL) {
					if (i == 0 || msg[i-1] != '\r')
						msg_size->virtual_size++;
					msg_size->lines++;
				}
				break;
			}
		}

		if (i < size) {
			startpos = i+1;
			break;
		}

		/* leave the last character, it may be \r */
		i_stream_skip(input, i - 1);
		startpos = 1;

		if (msg_size != NULL) {
			msg_size->physical_size += i - 1;
			msg_size->virtual_size += i - 1;
		}
	}

	i_stream_skip(input, startpos);

	if (msg_size != NULL) {
		msg_size->physical_size += startpos;
		msg_size->virtual_size += startpos;
	}
}

void message_parse_header(struct message_part *part, struct istream *input,
			  struct message_size *hdr_size,
			  message_header_callback_t *callback, void *context)
{
	const unsigned char *msg;
	size_t i, size, parse_size, startpos, missing_cr_count;
	size_t line_start, colon_pos, end_pos, name_len, value_len;
	int ret;

	if (hdr_size != NULL)
		memset(hdr_size, 0, sizeof(struct message_size));

	missing_cr_count = startpos = line_start = 0;
	colon_pos = UINT_MAX;
	for (;;) {
		ret = i_stream_read_data(input, &msg, &size, startpos+1);
		if (ret == -2) {
			/* overflow, line is too long. just skip it. */
			i_assert(size > 2);

                        message_skip_line(input, hdr_size);
			startpos = line_start = 0;
			colon_pos = UINT_MAX;
			continue;
		}

		if (ret < 0 || (ret <= 0 && size == startpos)) {
			/* EOF and nothing in buffer. the later check is
			   needed only when there's no message body */
			break;
		}

		parse_size = size <= startpos+1 ? size : size-1;
		for (i = startpos; i < parse_size; i++) {
			if (msg[i] == ':' && colon_pos == UINT_MAX) {
				colon_pos = i;
				continue;
			}

			if (msg[i] != '\n')
				continue;

			if (hdr_size != NULL)
				hdr_size->lines++;

			if (i == 0 || msg[i-1] != '\r') {
				/* missing CR */
				missing_cr_count++;
			}

			if (i == 0 || (i == 1 && msg[i-1] == '\r')) {
				/* no headers at all */
				break;
			}

			if ((i > 0 && msg[i-1] == '\n') ||
			    (i > 1 && msg[i-2] == '\n' && msg[i-1] == '\r')) {
				/* \n\n or \n\r\n - end of headers */
				break;
			}

			/* make sure the header doesn't continue to next line */
			if (i+1 == size || !IS_LWSP(msg[i+1])) {
				if (colon_pos != UINT_MAX &&
				    colon_pos != line_start &&
				    callback != NULL &&
				    !IS_LWSP(msg[line_start])) {
					/* we have a valid header line */

					/* get length of name-field */
					end_pos = colon_pos-1;
					while (end_pos > line_start &&
					       IS_LWSP(msg[end_pos]))
						end_pos--;
					name_len = end_pos - line_start + 1;

					/* get length of value field. skip
					   only the initial LWSP after ':'.
					   some fields may want to keep
					   the extra spaces.. */
					colon_pos++;
					if (colon_pos < i &&
					    IS_LWSP(msg[colon_pos]))
						colon_pos++;
					value_len = i - colon_pos;
					if (msg[i-1] == '\r') value_len--;

					/* and finally call the function */
					callback(part,
						 msg + line_start, name_len,
						 msg + colon_pos, value_len,
						 context);
				}

				colon_pos = UINT_MAX;
				line_start = i+1;
			}
		}

		if (i < parse_size) {
			/* end of header */
			startpos = i+1;
			break;
		}

		/* leave the last line to buffer */
		if (colon_pos != UINT_MAX)
			colon_pos -= line_start;
		if (hdr_size != NULL)
			hdr_size->physical_size += line_start;
		i_stream_skip(input, line_start);

		startpos = i-line_start;
		line_start = 0;
	}

	i_stream_skip(input, startpos);

	if (hdr_size != NULL) {
		hdr_size->physical_size += startpos;
		hdr_size->virtual_size +=
			hdr_size->physical_size + missing_cr_count;
		i_assert(hdr_size->virtual_size >= hdr_size->physical_size);
	}

	if (callback != NULL) {
		/* "end of headers" notify */
		callback(part, NULL, 0, NULL, 0, context);
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
		      struct message_size *msg_size, int skip_over)
{
	struct message_boundary *boundary;
	const unsigned char *msg;
	size_t i, size, startpos, line_start, missing_cr_count;

	boundary = NULL;
	missing_cr_count = startpos = line_start = 0;

	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] != '\n')
				continue;

			if (i > line_start+2 && msg[line_start] == '-' &&
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

		if (i - line_start > 128 &&
		    msg[line_start] == '-' && msg[line_start+1] == '-') {
			/* long partial line, see if it's a boundary.
			   RFC-2046 says that the boundaries must be
			   70 chars without "--" or less. We allow
			   a bit larger.. */
			boundary = boundary_find(boundaries,
						 msg + line_start + 2,
						 i - line_start - 2);
			if (boundary != NULL)
				break;

			/* nope, we can skip over the line, just
			   leave the last char since it may be \r */
			i--;
		} else {
			/* leave the last line to buffer, it may be
			   boundary */
			i = line_start;
			if (i > 2) i -= 2; /* leave the \r\n too */
			line_start -= i;
		}

		i_stream_skip(input, i);
		msg_size->physical_size += i;
		msg_size->virtual_size += i;

		startpos = size - i;
	}

	if (boundary != NULL) {
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
message_parse_body(struct istream *input, struct message_boundary *boundaries,
		   struct message_size *body_size)
{
	struct message_boundary *boundary;

	if (boundaries == NULL) {
		message_get_body_size(input, body_size, (uoff_t)-1, NULL);
		return NULL;
	} else {
		boundary = message_find_boundary(input, boundaries,
						 body_size, FALSE);
		return boundary == NULL ? NULL : boundary->part;
	}
}

/* skip data until next boundary is found. if it's end boundary,
   skip the footer as well. */
static struct message_part *
message_skip_boundary(struct istream *input,
		      struct message_boundary *boundaries,
		      struct message_size *boundary_size)
{
	struct message_boundary *boundary;
	const unsigned char *msg;
	size_t size;
	int end_boundary;

	boundary = message_find_boundary(input, boundaries,
					 boundary_size, TRUE);
	if (boundary == NULL)
		return NULL;

	/* now, see if it's end boundary */
	end_boundary = FALSE;
	if (i_stream_read_data(input, &msg, &size, 1) > 0)
		end_boundary = msg[0] == '-' && msg[1] == '-';

	/* skip the rest of the line */
	message_skip_line(input, boundary_size);

	if (end_boundary) {
		/* skip the footer */
		return message_parse_body(input, boundaries, boundary_size);
	}

	return boundary == NULL ? NULL : boundary->part;
}
