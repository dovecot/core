/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "rfc822-tokenize.h"
#include "message-content-parser.h"
#include "message-parser.h"
#include "message-size.h"

typedef struct _MessageBoundary {
	struct _MessageBoundary *next;

	MessagePart *part;
	const char *boundary;
	size_t len;
} MessageBoundary;

typedef struct {
	Pool pool;
	MessagePart *part;

	char *last_boundary;
	char *last_content_type;
	MessageBoundary *boundaries;

	MessageHeaderFunc func;
	void *context;
} MessageParseContext;

static MessagePart *message_parse_part(IBuffer *inbuf,
				       MessageParseContext *parse_ctx);
static MessagePart *message_parse_body(IBuffer *inbuf,
				       MessageBoundary *boundaries,
				       MessageSize *body_size);
static MessagePart *message_skip_boundary(IBuffer *inbuf,
					  MessageBoundary *boundaries,
					  MessageSize *boundary_size);

static void message_size_add_part(MessageSize *dest, MessagePart *part)
{
	dest->physical_size +=
		part->header_size.physical_size +
		part->body_size.physical_size;
	dest->virtual_size +=
		part->header_size.virtual_size +
		part->body_size.virtual_size;
	dest->lines += part->header_size.lines + part->body_size.lines;
}

static MessagePart *message_part_append(Pool pool, MessagePart *parent)
{
	MessagePart *part, **list;

	part = p_new(pool, MessagePart, 1);
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

static void parse_content_type(const Rfc822Token *tokens, int count,
			       void *context)
{
	MessageParseContext *parse_ctx = context;
	const char *str;

	if (tokens[0].token != 'A')
		return;

	if (parse_ctx->last_content_type != NULL)
		return;

	str = rfc822_tokens_get_value(tokens, count);
	parse_ctx->last_content_type = p_strdup(parse_ctx->pool, str);

	if (strcasecmp(str, "message/rfc822") == 0)
		parse_ctx->part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
	else if (strncasecmp(str, "text/", 5) == 0)
		parse_ctx->part->flags |= MESSAGE_PART_FLAG_TEXT;
	else if (strncasecmp(str, "multipart/", 10) == 0) {
		parse_ctx->part->flags |= MESSAGE_PART_FLAG_MULTIPART;

		if (strcasecmp(str+10, "digest") == 0) {
			parse_ctx->part->flags |=
				MESSAGE_PART_FLAG_MULTIPART_DIGEST;
		}
	}
}

static void parse_content_type_param(const Rfc822Token *name,
				     const Rfc822Token *value,
				     int value_count, void *context)
{
	MessageParseContext *parse_ctx = context;
	const char *str;

	if ((parse_ctx->part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
	    name->len != 8 || strncasecmp(name->ptr, "boundary", 8) != 0)
		return;

	if (parse_ctx->last_boundary == NULL) {
		str = rfc822_tokens_get_value(value, value_count);
		parse_ctx->last_boundary = p_strdup(parse_ctx->pool, str);
	}
}

static void parse_header_field(MessagePart *part,
			       const char *name, size_t name_len,
			       const char *value, size_t value_len,
			       void *context)
{
	MessageParseContext *parse_ctx = context;

	/* call the user-defined header parser */
	if (parse_ctx->func != NULL) {
		parse_ctx->func(part, name, name_len, value, value_len,
				parse_ctx->context);
	}

	if (name_len == 12 && strncasecmp(name, "Content-Type", 12) == 0) {
		/* we need to know the boundary */
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_type,
						   parse_content_type_param,
						   parse_ctx);
	}
}

static MessagePart *message_parse_multipart(IBuffer *inbuf,
					    MessageParseContext *parse_ctx)
{
	MessagePart *parent_part, *next_part, *part;
	MessageBoundary *b;

	/* multipart message. add new boundary */
	b = t_new(MessageBoundary, 1);
	b->part = parse_ctx->part;
	b->boundary = parse_ctx->last_boundary;
	b->len = strlen(b->boundary);

	b->next = parse_ctx->boundaries;
	parse_ctx->boundaries = b;

	/* reset fields */
	parse_ctx->last_boundary = NULL;
	parse_ctx->last_content_type = NULL;

	/* skip the data before the first boundary */
	parent_part = parse_ctx->part;
	next_part = message_skip_boundary(inbuf, parse_ctx->boundaries,
					  &parent_part->body_size);

	/* now, parse the parts */
	while (next_part == parent_part) {
		/* new child */
		part = message_part_append(parse_ctx->pool, parent_part);

                parse_ctx->part = part;
		next_part = message_parse_part(inbuf, parse_ctx);

		/* update our size */
		message_size_add_part(&parent_part->body_size, part);

		if (next_part != parent_part)
			break;

		/* skip the boundary */
		next_part = message_skip_boundary(inbuf, parse_ctx->boundaries,
						  &parent_part->body_size);
	}

	/* remove boundary */
	i_assert(parse_ctx->boundaries == b);
	parse_ctx->boundaries = b->next;
	return next_part;
}

static MessagePart *message_parse_part(IBuffer *inbuf,
				       MessageParseContext *parse_ctx)
{
	MessagePart *next_part, *part;
	uoff_t hdr_size;

	message_parse_header(parse_ctx->part, inbuf,
			     &parse_ctx->part->header_size,
			     parse_header_field, parse_ctx);

	/* update message position/size */
	hdr_size = parse_ctx->part->header_size.physical_size;

	if (parse_ctx->last_boundary != NULL)
		return message_parse_multipart(inbuf, parse_ctx);

	if (parse_ctx->last_content_type == NULL) {
		if (parse_ctx->part->parent != NULL &&
		    (parse_ctx->part->parent->flags &
		     MESSAGE_PART_FLAG_MULTIPART_DIGEST)) {
			/* when there's no content-type specified and we're
			   below multipart/digest, the assume message/rfc822
			   content-type */
			parse_ctx->part->flags |=
				MESSAGE_PART_FLAG_MESSAGE_RFC822;
		} else {
			/* otherwise we default to text/plain */
			parse_ctx->part->flags |= MESSAGE_PART_FLAG_TEXT;
		}
	}

	parse_ctx->last_boundary = NULL;
        parse_ctx->last_content_type = NULL;

	if (parse_ctx->part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) {
		/* message/rfc822 part - the message body begins with
		   headers again, this works pretty much the same as
		   a single multipart/mixed item */
		part = message_part_append(parse_ctx->pool, parse_ctx->part);

		parse_ctx->part = part;
		next_part = message_parse_part(inbuf, parse_ctx);
		parse_ctx->part = part->parent;

		/* our body size is the size of header+body in message/rfc822 */
		message_size_add_part(&part->parent->body_size, part);
	} else {
		/* normal message, read until the next boundary */
		part = parse_ctx->part;
		next_part = message_parse_body(inbuf, parse_ctx->boundaries,
					       &part->body_size);
	}

	return next_part;
}

MessagePart *message_parse(Pool pool, IBuffer *inbuf,
			   MessageHeaderFunc func, void *context)
{
	MessagePart *part;
	MessageParseContext parse_ctx;

	memset(&parse_ctx, 0, sizeof(parse_ctx));
	parse_ctx.pool = pool;
	parse_ctx.func = func;
	parse_ctx.context = context;
	parse_ctx.part = part = p_new(pool, MessagePart, 1);

	t_push();
	message_parse_part(inbuf, &parse_ctx);
	t_pop();
	return part;
}

/* skip over to next line increasing message size */
static void message_skip_line(IBuffer *inbuf, MessageSize *msg_size)
{
	const unsigned char *msg;
	size_t i, size, startpos;

	startpos = 0;

	while (i_buffer_read_data(inbuf, &msg, &size, startpos) > 0) {
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
		i_buffer_skip(inbuf, i - 1);
		startpos = 1;

		if (msg_size != NULL) {
			msg_size->physical_size += i - 1;
			msg_size->virtual_size += i - 1;
		}
	}

	i_buffer_skip(inbuf, startpos);

	if (msg_size != NULL) {
		msg_size->physical_size += startpos;
		msg_size->virtual_size += startpos;
	}
}

void message_parse_header(MessagePart *part, IBuffer *inbuf,
			  MessageSize *hdr_size,
			  MessageHeaderFunc func, void *context)
{
	const unsigned char *msg;
	size_t i, size, parse_size, startpos, missing_cr_count;
	size_t line_start, colon_pos, end_pos, name_len, value_len;
	int ret;

	if (hdr_size != NULL)
		memset(hdr_size, 0, sizeof(MessageSize));

	missing_cr_count = startpos = line_start = 0;
	colon_pos = UINT_MAX;
	for (;;) {
		ret = i_buffer_read_data(inbuf, &msg, &size, startpos+1);
		if (ret == -2) {
			/* overflow, line is too long. just skip it. */
			i_assert(size > 2);

                        message_skip_line(inbuf, hdr_size);
			startpos = line_start = 0;
			colon_pos = UINT_MAX;
			continue;
		}

		if (size <= startpos) {
			if (ret <= 0) {
				/* EOF and nothing in buffer. the later check is
				   needed only when there's no message body */
				break;
			}

			parse_size = size;
		} else {
			parse_size = size-1;
		}

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
				    colon_pos != line_start && func != NULL &&
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
					func(part,
					     (char*) msg + line_start, name_len,
					     (char*) msg + colon_pos, value_len,
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
		i_buffer_skip(inbuf, line_start);

		startpos = i-line_start;
		line_start = 0;
	}

	i_buffer_skip(inbuf, startpos);

	if (hdr_size != NULL) {
		hdr_size->physical_size += startpos;
		hdr_size->virtual_size +=
			hdr_size->physical_size + missing_cr_count;
		i_assert(hdr_size->virtual_size >= hdr_size->physical_size);
	}

	if (func != NULL) {
		/* "end of headers" notify */
		func(part, "", 0, "", 0, context);
	}
}

static MessageBoundary *boundary_find(MessageBoundary *boundaries,
				      const char *msg, size_t len)
{
	while (boundaries != NULL) {
		if (boundaries->len <= len &&
		    strncmp(boundaries->boundary, msg, boundaries->len) == 0)
			return boundaries;

		boundaries = boundaries->next;
	}

	return NULL;
}

/* read until next boundary is found. if skip_over = FALSE, stop at the
   [\r]\n before the boundary, otherwise leave it right after the known
   boundary so the ending "--" can be checked. */
static MessageBoundary *
message_find_boundary(IBuffer *inbuf, MessageBoundary *boundaries,
		      MessageSize *msg_size, int skip_over)
{
	MessageBoundary *boundary;
	const unsigned char *msg;
	size_t i, size, startpos, line_start, missing_cr_count;

	boundary = NULL;
	missing_cr_count = startpos = line_start = 0;

	while (i_buffer_read_data(inbuf, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] != '\n')
				continue;

			if (i > line_start+2 && msg[line_start] == '-' &&
			    msg[line_start+1] == '-') {
				/* possible boundary */
				boundary = boundary_find(boundaries,
					(const char *) msg + line_start + 2,
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
					(const char *) msg + line_start + 2,
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

		i_buffer_skip(inbuf, i);
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

	i_buffer_skip(inbuf, startpos);
	msg_size->physical_size += startpos;
	msg_size->virtual_size += startpos + missing_cr_count;

	i_assert(msg_size->virtual_size >= msg_size->physical_size);

	return boundary;
}

static MessagePart *message_parse_body(IBuffer *inbuf,
				       MessageBoundary *boundaries,
				       MessageSize *body_size)
{
	MessageBoundary *boundary;

	if (boundaries == NULL) {
		message_get_body_size(inbuf, body_size, (uoff_t)-1);
		return NULL;
	} else {
		boundary = message_find_boundary(inbuf, boundaries,
						 body_size, FALSE);
		return boundary == NULL ? NULL : boundary->part;
	}
}

/* skip data until next boundary is found. if it's end boundary,
   skip the footer as well. */
static MessagePart *message_skip_boundary(IBuffer *inbuf,
					  MessageBoundary *boundaries,
					  MessageSize *boundary_size)
{
	MessageBoundary *boundary;
	const unsigned char *msg;
	size_t size;
	int end_boundary;

	boundary = message_find_boundary(inbuf, boundaries,
					 boundary_size, TRUE);
	if (boundary == NULL)
		return NULL;

	/* now, see if it's end boundary */
	end_boundary = FALSE;
	if (i_buffer_read_data(inbuf, &msg, &size, 1) > 0)
		end_boundary = msg[0] == '-' && msg[1] == '-';

	/* skip the rest of the line */
	message_skip_line(inbuf, boundary_size);

	if (end_boundary) {
		/* skip the footer */
		return message_parse_body(inbuf, boundaries, boundary_size);
	}

	return boundary == NULL ? NULL : boundary->part;
}
