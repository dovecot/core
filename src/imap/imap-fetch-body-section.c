/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
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
        struct imap_fetch_context *fetch_ctx;
	struct mail *mail;

	buffer_t *dest;
	struct ostream *output;
	uoff_t dest_size;

	uoff_t skip, max_size;
	const char *const *fields;
	int (*match_func) (const char *const *, const char *, size_t);

	unsigned int fix_nuls:1;
};

struct partial_cache {
	unsigned int select_counter;
	unsigned int uid;

	uoff_t physical_start;
	int cr_skipped;
	struct message_size pos;
};

static struct partial_cache partial = { 0, 0, 0, 0, { 0, 0, 0 } };

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
		partial->cr_skipped = FALSE;
		memset(&partial->pos, 0, sizeof(partial->pos));
	}

	i_stream_seek(stream, partial->physical_start +
		      partial->pos.physical_size);
	message_skip_virtual(stream, virtual_skip, &partial->pos,
			     partial->cr_skipped, &cr_skipped);

	partial->cr_skipped = FALSE;
	return cr_skipped;
}

static uoff_t get_send_size(const struct imap_fetch_body_data *body,
			    uoff_t max_size)
{
	uoff_t size;

	if (body->skip >= max_size)
		return 0;

	size = max_size - body->skip;
	return size <= body->max_size ? size : body->max_size;
}

static int fetch_data(struct imap_fetch_context *ctx,
		      const struct imap_fetch_body_data *body,
		      struct mail *mail, struct istream *input,
		      uoff_t physical_start, const struct message_size *size)
{
	const char *str;
	uoff_t send_size;
	off_t ret;
	int skip_cr, last_cr;

	send_size = get_send_size(body, size->virtual_size);

	str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n", ctx->prefix, send_size);
	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	skip_cr = seek_partial(ctx->select_counter, mail->uid,
			       &partial, input, physical_start, body->skip);

	ret = message_send(ctx->output, input, size, skip_cr, send_size,
			   &last_cr, !mail->has_no_nuls);
	if (ret > 0) {
		partial.cr_skipped = last_cr != 0;
		partial.pos.physical_size =
			input->v_offset - partial.physical_start;
		partial.pos.virtual_size += ret;
	}

	if (ret != (off_t)send_size) {
		/* Input stream gave less data then we expected. Two choices
		   here: either we fill the missing data with spaces or we
		   disconnect the client.

		   We shouldn't really ever get here. One reason is if mail
		   was deleted from NFS server while we were reading it.
		   Another is some temporary disk error.

		   If we filled the missing data the client could cache it,
		   and if it was just a temporary error the message would be
		   permanently left corrupted in client's local cache. So, we
		   disconnect the client and hope that next try works. */
		o_stream_close(ctx->output);
		return FALSE;
	}

	return TRUE;
}

/* fetch BODY[] or BODY[TEXT] */
static int fetch_body(struct imap_fetch_context *ctx,
		      const struct imap_fetch_body_data *body,
		      struct mail *mail, int fetch_header)
{
	struct message_size hdr_size, body_size;
	struct istream *stream;

	stream = mail->get_stream(mail, &hdr_size, &body_size);
	if (stream == NULL)
		return FALSE;

	if (fetch_header)
		message_size_add(&body_size, &hdr_size);

	return fetch_data(ctx, body, mail, stream,
			  fetch_header ? 0 : hdr_size.physical_size,
			  &body_size);
}

static int header_match(const char *const *fields,
			const char *name, size_t size)
{
	const char *name_start, *name_end, *field;

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
			    const char *name, size_t size)
{
	return !header_match(fields, name, size);
}

static int header_match_mime(const char *const *fields __attr_unused__,
			     const char *name, size_t size)
{
	if (strncasecmp(name, "Content-", 8) == 0)
		return TRUE;

	if (size == 12 && strcasecmp(name, "Mime-Version") == 0)
		return TRUE;

	return FALSE;
}

static int fetch_header_append(struct fetch_header_field_context *ctx,
			       const void *data, size_t size)
{
	const unsigned char *str = data;
	size_t i;

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

	ctx->dest_size += size;

	if (ctx->fix_nuls && (ctx->dest != NULL || ctx->output != NULL)) {
		for (i = 0; i < size; ) {
			if (str[i] != 0) {
				i++;
				continue;
			}

			/* NUL found, change it to #128 */
			if (ctx->dest != NULL) {
				buffer_append(ctx->dest, str, i);
				buffer_append(ctx->dest, "\x80", 1);
			} else {
				if (o_stream_send(ctx->output, str, i) < 0 ||
				    o_stream_send(ctx->output, "\x80", 1) < 0)
					return FALSE;
			}

			str += i+1;
			size -= i+1;
			i = 0;
		}
	}

	if (ctx->dest != NULL)
		buffer_append(ctx->dest, str, size);
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
		ctx->fields = imap_fetch_get_body_fields(section + 14);
		ctx->match_func = header_match;

		if (ctx->fetch_ctx->body_fetch_from_cache) {
			input = ctx->mail->get_headers(ctx->mail, ctx->fields);
			if (input == NULL)
				return FALSE;
		}
	} else if (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
		ctx->fields = imap_fetch_get_body_fields(section + 18);
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
		if (!hdr->eoh &&
		    !ctx->match_func(ctx->fields, hdr->name, hdr->name_len))
			continue;

		if (!hdr->continued && !hdr->eoh) {
			if (!fetch_header_append(ctx, hdr->name, hdr->name_len))
				break;
			if (!fetch_header_append(ctx, ": ", 2))
				break;
		}
		if (!fetch_header_append(ctx, hdr->value, hdr->value_len))
			break;
		if (!hdr->no_newline) {
			if (!fetch_header_append(ctx, "\r\n", 2))
				break;
		}
	}
	message_parse_header_deinit(hdr_ctx);

	i_assert(ctx->dest_size <= ctx->max_size);
	i_assert(ctx->dest == NULL ||
		 buffer_get_used_size(ctx->dest) == ctx->dest_size);
	return TRUE;
}

/* fetch wanted headers from given data */
static int fetch_header_from(struct imap_fetch_context *ctx,
			     struct istream *input,
			     const struct message_size *size, struct mail *mail,
			     const struct imap_fetch_body_data *body,
			     const char *header_section)
{
	struct fetch_header_field_context hdr_ctx;
	const char *str;
	const void *data;
	size_t data_size;
	uoff_t start_offset;
	int failed;

	/* HEADER, MIME, HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */

	if (strcmp(header_section, "HEADER") == 0) {
		/* all headers */
		return fetch_data(ctx, body, mail, input, 0, size);
	}

	/* partial headers - copy the wanted fields into memory, inserting
	   missing CRs on the way. If the header is too large, calculate 
	   the size first and then send the data directly to output stream. */

	memset(&hdr_ctx, 0, sizeof(hdr_ctx));
	hdr_ctx.mail = mail;
	hdr_ctx.fetch_ctx = ctx;
	hdr_ctx.skip = body->skip;
	hdr_ctx.max_size = body->max_size;
	hdr_ctx.fix_nuls = !mail->has_no_nuls;

	failed = FALSE;
	start_offset = input == NULL ? 0 : input->v_offset;

	t_push();

	/* first pass, we need at least the size */
	if (size->virtual_size > MAX_HEADER_BUFFER_SIZE &&
	    body->max_size > MAX_HEADER_BUFFER_SIZE &&
	    !ctx->body_fetch_from_cache) {
		if (!fetch_header_fields(input, header_section, &hdr_ctx))
			failed = TRUE;

		i_assert(hdr_ctx.dest_size <= size->virtual_size);
	} else {
		hdr_ctx.dest =
			buffer_create_dynamic(pool_datastack_create(),
					      I_MIN(size->virtual_size, 8192),
					      (size_t)-1);
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
			data = buffer_get_data(hdr_ctx.dest, &data_size);
			if (o_stream_send(ctx->output, data, data_size) < 0)
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

	if (ctx->body_fetch_from_cache)
		stream = NULL;
	else {
		stream = mail->get_stream(mail, &hdr_size, NULL);
		if (stream == NULL)
			return FALSE;
	}

	return fetch_header_from(ctx, stream, &hdr_size,
				 mail, body, body->section);
}

/* Find message_part for section (eg. 1.3.4) */
static int part_find(struct mail *mail, const struct imap_fetch_body_data *body,
		     const struct message_part **part_r, const char **section)
{
	const struct message_part *part;
	const char *path;
	unsigned int num;

	part = mail->get_parts(mail);
	if (part == NULL)
		return FALSE;

	path = body->section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number */
		num = 0;
		while (*path != '\0' && *path != '.') {
			if (*path < '0' || *path > '9')
				return FALSE;
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
				part = NULL;
		}

		if (part != NULL &&
		    (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822)) {
			/* skip the message/rfc822 part */
			part = part->children;
		}
	}

	*part_r = part;
	*section = path;
	return TRUE;
}

static int fetch_part(struct imap_fetch_context *ctx, struct mail *mail,
		      const struct imap_fetch_body_data *body)
{
	struct istream *stream;
	const struct message_part *part;
	const char *section;

	if (!part_find(mail, body, &part, &section))
		return FALSE;

	if (part == NULL) {
		/* part doesn't exist */
		return o_stream_send_str(ctx->output, ctx->prefix) > 0 &&
			o_stream_send_str(ctx->output, " NIL") > 0;
	}

	stream = mail->get_stream(mail, NULL, NULL);
	if (stream == NULL)
		return FALSE;

	if (*section == '\0' || strcmp(section, "TEXT") == 0) {
		return fetch_data(ctx, body, mail, stream,
				  part->physical_pos +
				  part->header_size.physical_size,
				  &part->body_size);
	}

	if (strncmp(section, "HEADER", 6) == 0 ||
	    strcmp(section, "MIME") == 0) {
		i_stream_seek(stream, part->physical_pos);
		return fetch_header_from(ctx, stream, &part->header_size,
					 mail, body, section);
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
