/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "rfc822-tokenize.h"
#include "message-content-parser.h"
#include "message-parser.h"

typedef struct _MessageBoundary {
	struct _MessageBoundary *next;

	MessagePart *part;
	const char *boundary;
	unsigned int len;
} MessageBoundary;

typedef struct {
	Pool pool;
	MessagePart *part;

	char *last_boundary;
	char *last_content_type;
	MessageBoundary *boundaries;

	MessageHeaderFunc func;
	void *user_data;
} MessageParseData;

static MessagePart *message_parse_part(const char *msg, size_t size,
				       MessageParseData *parse_data);
static MessagePart *message_parse_body(const char *msg, size_t size,
				       MessageBoundary *boundaries,
				       MessageSize *body_size);
static MessagePart *message_skip_boundary(const char *msg, size_t size,
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

	list = &part->parent->children;
	while (*list != NULL)
		list = &(*list)->next;

	*list = part;
	return part;
}

static void parse_content_type(const Rfc822Token *tokens, int count,
			       void *user_data)
{
	MessageParseData *parse_data = user_data;
	const char *str;

	if (tokens[0].token != 'A')
		return;

	if (parse_data->last_content_type != NULL)
		return;

	str = rfc822_tokens_get_value(tokens, count, FALSE);
	parse_data->last_content_type = p_strdup(parse_data->pool, str);

	if (strcasecmp(str, "message/rfc822") == 0)
		parse_data->part->message_rfc822 = TRUE;
	else if (strncasecmp(str, "text/", 5) == 0)
		parse_data->part->text = TRUE;
	else if (strncasecmp(str, "multipart/", 10) == 0) {
		parse_data->part->multipart = TRUE;

		if (strcasecmp(str+10, "digest") == 0)
			parse_data->part->multipart_digest = TRUE;
	}
}

static void parse_content_type_param(const Rfc822Token *name,
				     const Rfc822Token *value,
				     int value_count, void *user_data)
{
	MessageParseData *parse_data = user_data;
	const char *str;

	if (!parse_data->part->multipart || name->len != 8 ||
	    strncasecmp(name->ptr, "boundary", 8) != 0)
		return;

	if (parse_data->last_boundary == NULL) {
		str = rfc822_tokens_get_value(value, value_count, FALSE);
		parse_data->last_boundary = p_strdup(parse_data->pool, str);
	}
}

static void parse_header_field(MessagePart *part,
			       const char *name, unsigned int name_len,
			       const char *value, unsigned int value_len,
			       void *user_data)
{
	MessageParseData *parse_data = user_data;

	/* call the user-defined header parser */
	if (parse_data->func != NULL) {
		parse_data->func(part, name, name_len, value, value_len,
				 parse_data->user_data);
	}

	if (name_len == 12 && strncasecmp(name, "Content-Type", 12) == 0) {
		/* we need to know the boundary */
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_type,
						   parse_content_type_param,
						   parse_data);
	}
}

static MessagePart *message_parse_multipart(const char *msg, size_t size,
					    MessageParseData *parse_data)
{
	MessagePart *parent_part, *next_part, *part;
	MessageBoundary *b;
	off_t offset;

	/* multipart message. add new boundary */
	b = t_new(MessageBoundary, 1);
	b->part = parse_data->part;
	b->boundary = t_strdup(parse_data->last_boundary);
	b->len = strlen(b->boundary);

	b->next = parse_data->boundaries;
	parse_data->boundaries = b;

	/* reset fields */
	p_free_and_null(parse_data->pool, parse_data->last_boundary);
	p_free_and_null(parse_data->pool, parse_data->last_content_type);

	/* skip the data before the first boundary */
	parent_part = parse_data->part;
	next_part = message_skip_boundary(msg, size, parse_data->boundaries,
					  &parent_part->body_size);

	/* now, parse the parts */
	while (next_part == parent_part) {
		/* new child */
		part = message_part_append(parse_data->pool, parent_part);

		/* set child position */
		memcpy(&part->pos, &parent_part->pos, sizeof(MessagePosition));
		part->pos.physical_pos += parent_part->body_size.physical_size +
			parent_part->header_size.physical_size;
		part->pos.virtual_pos += parent_part->body_size.virtual_size +
			parent_part->header_size.virtual_size;

		offset = parent_part->body_size.physical_size;
                parse_data->part = part;
		next_part = message_parse_part(msg + offset, size - offset,
					       parse_data);

		/* update our size */
		message_size_add_part(&parent_part->body_size, part);

		if (next_part != parent_part)
			break;

		/* skip the boundary */
		offset = parent_part->body_size.physical_size;
		next_part = message_skip_boundary(msg + offset, size - offset,
						  parse_data->boundaries,
						  &parent_part->body_size);
	}

	/* remove boundary */
	i_assert(parse_data->boundaries == b);
	parse_data->boundaries = b->next;
	return next_part;
}

static MessagePart *message_parse_part(const char *msg, size_t size,
				       MessageParseData *parse_data)
{
	MessagePart *next_part, *part;
	size_t hdr_size;

	message_parse_header(parse_data->part, msg, size,
			     &parse_data->part->header_size,
			     parse_header_field, parse_data);

	/* update message position/size */
	hdr_size = parse_data->part->header_size.physical_size;
	msg += hdr_size; size -= hdr_size;

	if (parse_data->last_boundary != NULL)
		return message_parse_multipart(msg, size, parse_data);

	if (parse_data->last_content_type == NULL) {
		if (parse_data->part->parent != NULL &&
		    parse_data->part->parent->multipart_digest) {
			/* when there's no content-type specified and we're
			   below multipart/digest, the assume message/rfc822
			   content-type */
			parse_data->part->message_rfc822 = TRUE;
		} else {
			/* otherwise we default to text/plain */
			parse_data->part->text = TRUE;
		}
	}

	p_free_and_null(parse_data->pool, parse_data->last_boundary);
	p_free_and_null(parse_data->pool, parse_data->last_content_type);

	if (parse_data->part->message_rfc822) {
		/* message/rfc822 part - the message body begins with
		   headers again, this works pretty much the same as
		   a single multipart/mixed item */
		part = message_part_append(parse_data->pool, parse_data->part);

		parse_data->part = part;
		next_part = message_parse_part(msg, size, parse_data);
		parse_data->part = part->parent;

		/* our body size is the size of header+body in message/rfc822 */
		message_size_add_part(&part->parent->body_size, part);
	} else {
		/* normal message, read until the next boundary */
		part = parse_data->part;
		next_part = message_parse_body(msg, size,
					       parse_data->boundaries,
					       &part->body_size);
	}

	return next_part;
}

MessagePart *message_parse(Pool pool, const char *msg, size_t size,
			   MessageHeaderFunc func, void *user_data)
{
	MessagePart *part;
	MessageParseData parse_data;

	memset(&parse_data, 0, sizeof(parse_data));
	parse_data.pool = pool;
	parse_data.func = func;
	parse_data.user_data = user_data;
	parse_data.part = part = p_new(pool, MessagePart, 1);

	t_push();
	message_parse_part(msg, size, &parse_data);
	t_pop();
	return part;
}

void message_parse_header(MessagePart *part, const char *msg, size_t size,
			  MessageSize *hdr_size,
			  MessageHeaderFunc func, void *user_data)
{
	const char *msg_start, *msg_end, *cr, *last_lf;
	const char *name, *value, *name_end, *value_end;
	int missing_cr_count, stop;

	msg_start = msg;
	msg_end = msg + size;

	missing_cr_count = 0; cr = NULL;
	name = msg; name_end = value = last_lf = NULL;

	if (hdr_size != NULL)
		hdr_size->lines = 0;

	stop = FALSE;
	while (msg != msg_end && !stop) {
		switch (*msg) {
		case '\n':
			if (hdr_size != NULL)
				hdr_size->lines++;

			if (msg == msg_start ||
			    (cr == msg_start && cr == msg-1)) {
				/* no headers at all */
				if (cr != msg-1)
					missing_cr_count++;
				stop = TRUE;
				break;
			} else if (cr == msg-1) {
				/* CR+LF */
				value_end = cr;

				if (last_lf == cr-1) {
					/* LF+CR+LF -> end of headers */
					stop = TRUE;
					break;
				}
			} else {
				/* missing CR */
				missing_cr_count++;
				value_end = msg;

				if (last_lf == msg-1) {
					/* LF+LF -> end of headers */
					stop = TRUE;
					break;
				}
			}
			last_lf = msg;

			if (msg+1 != msg_end && IS_LWSP(msg[1])) {
				/* long header continuing in next line */
				break;
			}

			/* Ignore header lines missing ':' (value == NULL) */
			if (func != NULL && value != NULL) {
				func(part, name, (unsigned int) (name_end-name),
				     value, (unsigned int) (value_end-value),
				     user_data);
			}

			/* reset the data */
			name = msg+1;
			name_end = NULL;
			value = NULL;
			break;
		case '\r':
			cr = msg;
			break;
		case ':':
			if (value != NULL)
				break;
			name_end = msg;

			/* skip the ending whitespace for field */
			while (name_end != name && IS_LWSP(name_end[-1]))
				name_end--;

			/* get beginning of field value */
			value = msg+1;
			if (msg+1 != msg_end && IS_LWSP(msg[1]))
				value++;
			break;
		}

		msg++;
	}

	if (hdr_size != NULL) {
		hdr_size->physical_size = (int) (msg - msg_start);
		hdr_size->virtual_size =
			hdr_size->physical_size + missing_cr_count;
	}
}

static MessageBoundary *boundary_find(MessageBoundary *boundaries,
				      const char *msg, unsigned int len)
{
	while (boundaries != NULL) {
		if (boundaries->len <= len &&
		    strncmp(boundaries->boundary, msg, boundaries->len) == 0)
			return boundaries;

		boundaries = boundaries->next;
	}

	return NULL;
}

static MessagePart *message_parse_body(const char *msg, size_t size,
				       MessageBoundary *boundaries,
				       MessageSize *body_size)
{
	MessageBoundary *boundary;
	const char *msg_start, *msg_end, *cr;
	unsigned int missing_cr_count, len;

	msg_start = msg;
	msg_end = msg + size;

	missing_cr_count = 0; cr = NULL;

	boundary = NULL;
	while (msg != msg_end) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			if (cr != msg-1)
				missing_cr_count++;
			body_size->lines++;
		} else if (*msg == '-' && msg+2 < msg_end && msg[1] == '-' &&
			   (msg == msg_start || msg[-1] == '\n')) {
			/* "\n--", could be boundary */
			len = (unsigned int) (msg_end - (msg+2));

			boundary = boundary_find(boundaries, msg+2, len);
			if (boundary != NULL) {
				/* boundary found, move the pointer
				   before the [CR]LF */
				if (msg != msg_start) {
					msg--;
					if (cr == msg-1)
						msg--;
					else
						missing_cr_count--;
					body_size->lines--;
				}
				break;
			}
		}

		msg++;
	}

	len = (unsigned int) (msg - msg_start);
	body_size->physical_size += len;
	body_size->virtual_size += len + missing_cr_count;

	return boundary == NULL ? NULL : boundary->part;
}

static MessagePart *message_skip_boundary(const char *msg, size_t size,
					  MessageBoundary *boundaries,
					  MessageSize *boundary_size)
{
	MessageBoundary *boundary;
	const char *msg_start, *msg_end, *cr;
	unsigned int len, missing_cr_count;
	int end_boundary;

	/* first find and skip the boundary */
	msg_start = msg;
	msg_end = msg + size;

	cr = NULL; missing_cr_count = 0;

	boundary = NULL;
	while (msg != msg_end) {
		if (*msg == '-' && msg+2 < msg_end && msg[1] == '-' &&
		    (msg == msg_start || msg[-1] == '\n')) {
			/* possible boundary */
			len = (unsigned int) (msg_end - (msg+2));
			boundary = boundary_find(boundaries, msg+2, len);
			if (boundary != NULL) {
				/* skip the boundary */
				msg += 2 + boundary->len;
				break;
			}
		} else if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			if (cr != msg-1)
				missing_cr_count++;
			boundary_size->lines++;
		}
		msg++;
	}

	len = (unsigned int) (msg - msg_start);
	boundary_size->physical_size += len;
	boundary_size->virtual_size += len + missing_cr_count;

	if (boundary == NULL)
		return NULL;

	/* now read the boundary until we reach the end of line */
	msg_start = msg;
	end_boundary = msg+2 <= msg_end && msg[0] == '-' && msg[1] == '-';
	while (msg != msg_end) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			if (cr != msg-1)
				boundary_size->virtual_size++;
			boundary_size->lines++;
			msg++;
			break;
		}

		msg++;
	}

	len = (unsigned int) (msg - msg_start);
	boundary_size->physical_size += len;
	boundary_size->virtual_size += len;

	if (end_boundary) {
		/* skip the footer */
		return message_parse_body(msg, (unsigned int) (msg_end-msg),
					  boundaries, boundary_size);
	}

	return boundary->part;
}
