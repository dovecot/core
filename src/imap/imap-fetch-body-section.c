/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "message-parser.h"
#include "message-send.h"
#include "mail-storage.h"
#include "imap-fetch.h"

#include <ctype.h>
#include <unistd.h>

/* For FETCH[HEADER.FIELDS*] we need to modify the header data before sending
   it. We can either save it in memory and then send it, or we can parse it
   twice, first calculating the size and then send it. This value specifies
   the maximum amount of memory we allow to allocate before using
   double-parsing. */
#define MAX_HEADER_BUFFER_SIZE (32*1024)

struct fetch_header_field_context {
	string_t *dest;
	struct ostream *output;
	uoff_t dest_size;

	uoff_t skip, max_size;
	const char *const *fields;
	int (*match_func) (const char *const *, const unsigned char *, size_t);
};

struct partial_cache {
	unsigned int select_counter;
	unsigned int uid;

	uoff_t physical_start;
	struct message_size pos;
};

static struct partial_cache partial = { 0, 0, 0, { 0, 0, 0 } };

static int seek_partial(unsigned int select_counter, unsigned int uid,
			struct partial_cache *partial, struct istream *stream,
			uoff_t physical_start, uoff_t virtual_skip)
{
	int cr_skipped;

	if (select_counter == partial->select_counter && uid == partial->uid &&
	    physical_start == partial->physical_start &&
	    virtual_skip >= partial->pos.virtual_size) {
		/* we can use the cache */
		virtual_skip -= partial->pos.virtual_size;
	} else {
		partial->select_counter = select_counter;
		partial->uid = uid;
		partial->physical_start = physical_start;
		memset(&partial->pos, 0, sizeof(partial->pos));
	}

	i_stream_seek(stream, partial->physical_start +
		      partial->pos.physical_size);
	message_skip_virtual(stream, virtual_skip, &partial->pos, &cr_skipped);

	if (cr_skipped)
		partial->pos.virtual_size--;

	return cr_skipped;
}

/* fetch BODY[] or BODY[TEXT] */
static int fetch_body(struct imap_fetch_context *ctx,
		      const struct imap_fetch_body_data *body,
		      struct mail *mail, int fetch_header)
{
	struct message_size hdr_size, body_size;
	struct istream *stream;
	const char *str;
	int skip_cr;
	uoff_t size;
	off_t ret;

	stream = mail->get_stream(mail, &hdr_size, &body_size);
	if (stream == NULL)
		return FALSE;

	if (fetch_header)
		message_size_add(&body_size, &hdr_size);

	if (body->skip >= body_size.virtual_size)
		size = 0;
	else {
		size = body_size.virtual_size - body->skip;
		if (size > body->max_size) size = body->max_size;
	}
	str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n", ctx->prefix, size);
	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	skip_cr = seek_partial(ctx->select_counter, mail->uid,
			       &partial, stream,
			       fetch_header ? 0 : hdr_size.physical_size,
			       body->skip);

	ret = message_send(ctx->output, stream, &body_size,
			   skip_cr, body->max_size);
	if (ret > 0) {
		partial.pos.physical_size =
			stream->v_offset - partial.physical_start;
		partial.pos.virtual_size += ret;
	}
	return ret >= 0;
}

static const char **get_fields_array(const char *fields)
{
	const char **field_list, **field;

	while (*fields == ' ')
		fields++;
	if (*fields == '(')
		fields++;

	field_list = t_strsplit(fields, " )");

	/* array ends at ")" element */
	for (field = field_list; *field != NULL; field++) {
		if (strcmp(*field, ")") == 0)
			*field = NULL;
	}

	return field_list;
}

static int header_match(const char *const *fields,
			const unsigned char *name, size_t size)
{
	const unsigned char *name_start, *name_end;
	const char *field;

	if (size == 0)
		return FALSE;

	name_start = name;
	name_end = name + size;

	for (; *fields != NULL; fields++) {
		field = *fields;
		if (*field == '\0')
			continue;

		for (name = name_start; name != name_end; name++) {
			/* field has been uppercased long time ago while
			   parsing FETCH command */
			if (i_toupper(*name) != *field)
				break;

			field++;
			if (*field == '\0') {
				if (name+1 == name_end)
					return TRUE;
				break;
			}
		}
	}

	return FALSE;
}

static int header_match_not(const char *const *fields,
			    const unsigned char *name, size_t size)
{
	return !header_match(fields, name, size);
}

static int header_match_mime(const char *const *fields __attr_unused__,
			     const unsigned char *name, size_t size)
{
	if (size > 8 && memcasecmp(name, "Content-", 8) == 0)
		return TRUE;

	if (size == 12 && memcasecmp(name, "Mime-Version", 12) == 0)
		return TRUE;

	return FALSE;
}

static int fetch_header_append(struct fetch_header_field_context *ctx,
			       const unsigned char *str, size_t size)
{
	if (ctx->skip > 0) {
		if (ctx->skip >= size) {
			ctx->skip -= size;
			return TRUE;
		}

		str += ctx->skip;
		size -= ctx->skip;
		ctx->skip = 0;
	}

	if (ctx->dest_size + size > ctx->max_size) {
		i_assert(ctx->dest_size <= ctx->max_size);
		size = ctx->max_size - ctx->dest_size;
	}

	if (ctx->dest != NULL)
		str_append_n(ctx->dest, str, size);
	ctx->dest_size += size;

	if (ctx->output != NULL) {
		if (o_stream_send(ctx->output, str, size) < 0)
			return FALSE;
	}
	return ctx->dest_size < ctx->max_size;
}

static int fetch_header_fields(struct istream *input, const char *section,
			       struct fetch_header_field_context *ctx)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;

	if (strncmp(section, "HEADER.FIELDS ", 14) == 0) {
		ctx->fields = get_fields_array(section + 14);
		ctx->match_func = header_match;
	} else if (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
		ctx->fields = get_fields_array(section + 18);
		ctx->match_func = header_match_not;
	} else if (strcmp(section, "MIME") == 0) {
		/* Mime-Version + Content-* fields */
		ctx->match_func = header_match_mime;
	} else {
		i_warning("BUG: Accepted invalid section from user: '%s'",
			  section);
		return FALSE;
	}

	ctx->dest_size = 0;

	hdr_ctx = message_parse_header_init(input, NULL);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL) {
		/* see if we want this field.
		   we always want the end-of-headers line */
		if (!ctx->match_func(ctx->fields, hdr->name, hdr->name_len) &&
		    !hdr->eoh)
			continue;

		if (!hdr->continued && !hdr->eoh) {
			if (!fetch_header_append(ctx, hdr->name, hdr->name_len))
				break;
			if (!fetch_header_append(ctx,
					(const unsigned char *) ": ", 2))
				break;
		}
		if (!fetch_header_append(ctx, hdr->value, hdr->value_len))
			break;
		if (!hdr->no_newline) {
			if (!fetch_header_append(ctx,
					(const unsigned char *) "\r\n", 2))
				break;
		}
	}
	message_parse_header_deinit(hdr_ctx);

	i_assert(ctx->dest_size <= ctx->max_size);
	i_assert(ctx->dest == NULL || str_len(ctx->dest) == ctx->dest_size);
	return TRUE;
}

/* fetch wanted headers from given data */
static int fetch_header_from(struct imap_fetch_context *ctx,
			     struct istream *input,
			     const struct message_size *size,
			     const struct imap_fetch_body_data *body,
			     const char *header_section)
{
	struct fetch_header_field_context hdr_ctx;
	const char *str;
	uoff_t start_offset;
	int failed;

	/* HEADER, MIME, HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */

	if (strcmp(header_section, "HEADER") == 0) {
		/* all headers */
		str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n",
				      ctx->prefix, size->virtual_size);
		if (o_stream_send_str(ctx->output, str) < 0)
			return FALSE;
		return message_send(ctx->output, input, size,
				    body->skip, body->max_size) >= 0;
	}

	/* partial headers - copy the wanted fields into memory, inserting
	   missing CRs on the way. If the header is too large, calculate 
	   the size first and then send the data directly to output stream. */

	memset(&hdr_ctx, 0, sizeof(hdr_ctx));
	hdr_ctx.skip = body->skip;
	hdr_ctx.max_size = body->max_size;

	failed = FALSE;
	start_offset = input->v_offset;

	t_push();

	/* first pass, we need at least the size */
	if (size->virtual_size > MAX_HEADER_BUFFER_SIZE &&
	    body->max_size > MAX_HEADER_BUFFER_SIZE) {
		if (!fetch_header_fields(input, header_section, &hdr_ctx))
			failed = TRUE;

		i_assert(hdr_ctx.dest_size <= size->virtual_size);
	} else {
		hdr_ctx.dest = t_str_new(size->virtual_size < 8192 ?
					 size->virtual_size : 8192);
		if (!fetch_header_fields(input, header_section, &hdr_ctx))
			failed = TRUE;
	}

	if (!failed) {
		str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n",
				      ctx->prefix, hdr_ctx.dest_size);
		if (o_stream_send_str(ctx->output, str) < 0)
			failed = TRUE;
	}

	if (!failed) {
		if (hdr_ctx.dest == NULL) {
			/* second pass, write the data to output stream */
			uoff_t first_size = hdr_ctx.dest_size;

			hdr_ctx.output = ctx->output;
			i_stream_seek(input, start_offset);

			if (!failed &&
			    !fetch_header_fields(input, header_section,
						 &hdr_ctx))
				failed = TRUE;

			i_assert(first_size == hdr_ctx.dest_size);
		} else {
			if (o_stream_send(ctx->output, str_data(hdr_ctx.dest),
					  str_len(hdr_ctx.dest)) < 0)
				failed = TRUE;
		}
	}

	t_pop();
	return !failed;
}

static int fetch_header(struct imap_fetch_context *ctx, struct mail *mail,
			const struct imap_fetch_body_data *body)
{
	struct istream *stream;
	struct message_size hdr_size;

	stream = mail->get_stream(mail, &hdr_size, NULL);
	if (stream == NULL)
		return FALSE;

	return fetch_header_from(ctx, stream, &hdr_size, body, body->section);
}

/* Find message_part for section (eg. 1.3.4) */
static const struct message_part *
part_find(struct mail *mail, const struct imap_fetch_body_data *body,
	  const char **section)
{
	const struct message_part *part;
	const char *path;
	unsigned int num;

	part = mail->get_parts(mail);
	if (part == NULL)
		return NULL;

	path = body->section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number */
		num = 0;
		while (*path != '\0' && *path != '.') {
			if (*path < '0' || *path > '9')
				return NULL;
			num = num*10 + (*path - '0');
			path++;
		}

		if (*path == '.')
			path++;

		if (part->flags & MESSAGE_PART_FLAG_MULTIPART) {
			/* find the part */
			part = part->children;
			for (; num > 1 && part != NULL; num--)
				part = part->next;
		} else {
			/* only 1 allowed with non-multipart messages */
			if (num != 1)
				return NULL;
		}

		if (part != NULL &&
		    (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822)) {
			/* skip the message/rfc822 part */
			part = part->children;
		}
	}

	*section = path;
	return part;
}

/* fetch BODY[1.2] or BODY[1.2.TEXT] */
static int fetch_part_body(struct imap_fetch_context *ctx,
			   struct istream *stream,
			   const struct imap_fetch_body_data *body,
			   struct mail *mail, const struct message_part *part)
{
	const char *str;
	int skip_cr;
	uoff_t size;
	off_t ret;

	if (body->skip >= part->body_size.virtual_size)
		size = 0;
	else {
		size = part->body_size.virtual_size - body->skip;
		if (size > body->max_size) size = body->max_size;
	}
	str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n", ctx->prefix, size);
	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	skip_cr = seek_partial(ctx->select_counter, mail->uid,
			       &partial, stream, part->physical_pos +
			       part->header_size.physical_size, body->skip);
	ret = message_send(ctx->output, stream, &part->body_size,
			   skip_cr, body->max_size);
	if (ret > 0) {
		partial.pos.physical_size =
			stream->v_offset - partial.physical_start;
		partial.pos.virtual_size += ret;
	}
	return ret >= 0;
}

static int fetch_part(struct imap_fetch_context *ctx, struct mail *mail,
		      const struct imap_fetch_body_data *body)
{
	struct istream *stream;
	const struct message_part *part;
	const char *section;

	part = part_find(mail, body, &section);
	if (part == NULL)
		return FALSE;

	stream = mail->get_stream(mail, NULL, NULL);
	if (stream == NULL)
		return FALSE;

	if (*section == '\0' || strcmp(section, "TEXT") == 0)
		return fetch_part_body(ctx, stream, body, mail, part);

	if (strncmp(section, "HEADER", 6) == 0 ||
	    strcmp(section, "MIME") == 0) {
		i_stream_seek(stream, part->physical_pos);
		return fetch_header_from(ctx, stream, &part->header_size,
					 body, section);
	}

	i_warning("BUG: Accepted invalid section from user: '%s'",
		  body->section);
	return FALSE;
}

int imap_fetch_body_section(struct imap_fetch_context *ctx,
			    const struct imap_fetch_body_data *body,
			    struct mail *mail)
{
	ctx->prefix = !body->skip_set ?
		t_strdup_printf(" BODY[%s]", body->section) :
		t_strdup_printf(" BODY[%s]<%"PRIuUOFF_T">",
				body->section, body->skip);
	if (ctx->first) {
		ctx->prefix++; ctx->first = FALSE;
	}

	if (*body->section == '\0')
		return fetch_body(ctx, body, mail, TRUE);
	if (strcmp(body->section, "TEXT") == 0)
		return fetch_body(ctx, body, mail, FALSE);
	if (strncmp(body->section, "HEADER", 6) == 0)
		return fetch_header(ctx, mail, body);
	if (*body->section >= '0' && *body->section <= '9')
		return fetch_part(ctx, mail, body);

	i_warning("BUG: Accepted invalid section from user: '%s'",
		  body->section);
	return FALSE;
}
