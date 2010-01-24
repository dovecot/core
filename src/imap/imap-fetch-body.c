/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "buffer.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "istream-header-filter.h"
#include "message-parser.h"
#include "message-send.h"
#include "mail-storage.h"
#include "imap-parser.h"
#include "imap-fetch.h"

#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

struct imap_fetch_body_data {
	struct imap_fetch_body_data *next;

        struct mailbox_header_lookup_ctx *header_ctx;
	const char *section; /* NOTE: always uppercased */
	uoff_t skip, max_size; /* if you don't want max_size,
	                          set it to (uoff_t)-1 */

	const char *const *fields;
	size_t fields_count;

	unsigned int skip_set:1;
	unsigned int peek:1;
};

struct partial_cache {
	unsigned int select_counter;
	unsigned int uid;

	uoff_t physical_start;
	bool cr_skipped;
	struct message_size pos;
};

static struct partial_cache last_partial = { 0, 0, 0, 0, { 0, 0, 0 } };

static void fetch_read_error(struct imap_fetch_context *ctx)
{
	errno = ctx->cur_input->stream_errno;
	i_error("FETCH for mailbox %s UID %u "
		"failed to read message input: %m",
		mailbox_get_vname(ctx->mail->box), ctx->mail->uid);
}

static int seek_partial(unsigned int select_counter, unsigned int uid,
			struct partial_cache *partial, struct istream *stream,
			uoff_t virtual_skip, bool *cr_skipped_r)
{
	if (select_counter == partial->select_counter && uid == partial->uid &&
	    stream->v_offset == partial->physical_start &&
	    virtual_skip >= partial->pos.virtual_size) {
		/* we can use the cache */
		virtual_skip -= partial->pos.virtual_size;
	} else {
		partial->select_counter = select_counter;
		partial->uid = uid;
		partial->physical_start = stream->v_offset;
		partial->cr_skipped = FALSE;
		memset(&partial->pos, 0, sizeof(partial->pos));
	}

	i_stream_seek(stream, partial->physical_start +
		      partial->pos.physical_size);
	if (message_skip_virtual(stream, virtual_skip, &partial->pos,
				 partial->cr_skipped, cr_skipped_r) < 0)
		return -1;

	partial->cr_skipped = FALSE;
	return 0;
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

static const char *get_body_name(const struct imap_fetch_body_data *body)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "BODY[%s]", body->section);
	if (body->skip_set)
		str_printfa(str, "<%"PRIuUOFF_T">", body->skip);
	return str_c(str);
}

static string_t *get_prefix(struct imap_fetch_context *ctx,
			    const struct imap_fetch_body_data *body,
			    uoff_t size)
{
	string_t *str;

	str = t_str_new(128);
	if (ctx->first)
		ctx->first = FALSE;
	else
		str_append_c(str, ' ');

	str_append(str, get_body_name(body));

	if (size != (uoff_t)-1)
		str_printfa(str, " {%"PRIuUOFF_T"}\r\n", size);
	else
		str_append(str, " NIL");
	return str;
}

static off_t imap_fetch_send(struct imap_fetch_context *ctx,
			     struct ostream *output, struct istream *input,
			     bool cr_skipped, uoff_t virtual_size,
			     bool add_missing_eoh, bool *last_cr)
{
	const unsigned char *msg;
	size_t i, size;
	uoff_t vsize_left, sent;
	off_t ret;
	unsigned char add;
	bool blocks = FALSE;

	/* go through the message data and insert CRs where needed.  */
	sent = 0; vsize_left = virtual_size;
	while (vsize_left > 0 && !blocks &&
	       i_stream_read_data(input, &msg, &size, 0) > 0) {
		add = '\0';
		for (i = 0; i < size && vsize_left > 0; i++) {
			vsize_left--;

			if (msg[i] == '\n') {
				if ((i > 0 && msg[i-1] != '\r') ||
				    (i == 0 && !cr_skipped)) {
					/* missing CR */
					add = '\r';
					break;
				}
			} else if (msg[i] == '\0') {
				add = 128;
				break;
			}
		}

		if ((ret = o_stream_send(output, msg, i)) < 0)
			return -1;
		if ((uoff_t)ret < i) {
			add = '\0';
			blocks = TRUE;
		}

		if (ret > 0)
			cr_skipped = msg[ret-1] == '\r';

		i_stream_skip(input, ret);
		sent += ret;

		if (add != '\0') {
			if ((ret = o_stream_send(output, &add, 1)) < 0)
				return -1;
			if (ret == 0)
				blocks = TRUE;
			else {
				sent++;
				cr_skipped = add == '\r';
				if (add == 128)
					i_stream_skip(input, 1);
			}
		}
	}
	if (input->stream_errno != 0) {
		fetch_read_error(ctx);
		return -1;
	}

	if (add_missing_eoh && sent + 2 == virtual_size) {
		/* Netscape missing EOH workaround. */
		o_stream_set_max_buffer_size(output, (size_t)-1);
		if (o_stream_send(output, "\r\n", 2) < 0)
			return -1;
		sent += 2;
	}

	if ((uoff_t)sent != virtual_size && !blocks) {
		/* Input stream gave less data than we expected. Two choices
		   here: either we fill the missing data with spaces or we
		   disconnect the client.

		   We shouldn't really ever get here. One reason is if mail
		   was deleted from NFS server while we were reading it.
		   Another is some temporary disk error.

		   If we filled the missing data the client could cache it,
		   and if it was just a temporary error the message would be
		   permanently left corrupted in client's local cache. So, we
		   disconnect the client and hope that next try works. */
		i_error("FETCH %s for mailbox %s UID %u got too little data: "
			"%"PRIuUOFF_T" vs %"PRIuUOFF_T, ctx->cur_name,
			mailbox_get_vname(ctx->mail->box), ctx->mail->uid,
			(uoff_t)sent, virtual_size);
		mail_set_cache_corrupted(ctx->mail, ctx->cur_size_field);
		client_disconnect(ctx->client, "FETCH failed");
		return -1;
	}

	*last_cr = cr_skipped;
	return sent;
}

static int fetch_stream_send(struct imap_fetch_context *ctx)
{
	off_t ret;

	o_stream_set_max_buffer_size(ctx->client->output, 4096);
	ret = imap_fetch_send(ctx, ctx->client->output, ctx->cur_input,
			      ctx->skip_cr, ctx->cur_size - ctx->cur_offset,
			      ctx->cur_append_eoh, &ctx->skip_cr);
	o_stream_set_max_buffer_size(ctx->client->output, (size_t)-1);

	if (ret < 0)
		return -1;

	ctx->cur_offset += ret;
	if (ctx->update_partial) {
		last_partial.cr_skipped = ctx->skip_cr != 0;
		last_partial.pos.physical_size =
			ctx->cur_input->v_offset - last_partial.physical_start;
		last_partial.pos.virtual_size += ret;
	}

	return ctx->cur_offset == ctx->cur_size;
}

static int fetch_stream_send_direct(struct imap_fetch_context *ctx)
{
	off_t ret;

	o_stream_set_max_buffer_size(ctx->client->output, 0);
	ret = o_stream_send_istream(ctx->client->output, ctx->cur_input);
	o_stream_set_max_buffer_size(ctx->client->output, (size_t)-1);

	if (ret < 0)
		return -1;

	ctx->cur_offset += ret;

	if (ctx->cur_append_eoh && ctx->cur_offset + 2 == ctx->cur_size) {
		/* Netscape missing EOH workaround. */
		if (o_stream_send(ctx->client->output, "\r\n", 2) < 0)
			return -1;
		ctx->cur_offset += 2;
		ctx->cur_append_eoh = FALSE;
	}

	if (ctx->cur_offset != ctx->cur_size) {
		/* unfinished */
		if (!i_stream_have_bytes_left(ctx->cur_input)) {
			/* Input stream gave less data than expected */
			i_error("FETCH %s for mailbox %s UID %u "
				"got too little data (copying): "
				"%"PRIuUOFF_T" vs %"PRIuUOFF_T,
				ctx->cur_name, mailbox_get_vname(ctx->mail->box),
				ctx->mail->uid, ctx->cur_offset, ctx->cur_size);
			client_disconnect(ctx->client, "FETCH failed");
			return -1;
		}

		o_stream_set_flush_pending(ctx->client->output, TRUE);
		return 0;
	}
	return 1;
}

static int fetch_stream(struct imap_fetch_context *ctx,
			const struct message_size *size)
{
	struct istream *input;

	if (size->physical_size == size->virtual_size &&
	    ctx->cur_mail->has_no_nuls) {
		/* no need to kludge with CRs, we can use sendfile() */
		input = i_stream_create_limit(ctx->cur_input, ctx->cur_size);
		i_stream_unref(&ctx->cur_input);
		ctx->cur_input = input;

		ctx->cont_handler = fetch_stream_send_direct;
	} else {
                ctx->cont_handler = fetch_stream_send;
	}

	return ctx->cont_handler(ctx);
}

static int fetch_data(struct imap_fetch_context *ctx,
		      const struct imap_fetch_body_data *body,
		      const struct message_size *size)
{
	string_t *str;

	ctx->cur_name = p_strconcat(ctx->cmd->pool,
				    "[", body->section, "]", NULL);
	ctx->cur_size = get_send_size(body, size->virtual_size);

	str = get_prefix(ctx, body, ctx->cur_size);
	if (o_stream_send(ctx->client->output,
			  str_data(str), str_len(str)) < 0)
		return -1;

	if (!ctx->update_partial) {
		if (message_skip_virtual(ctx->cur_input, body->skip, NULL,
					 FALSE, &ctx->skip_cr) < 0) {
			fetch_read_error(ctx);
			return -1;
		}
	} else {
		if (seek_partial(ctx->select_counter, ctx->cur_mail->uid,
				 &last_partial, ctx->cur_input, body->skip,
				 &ctx->skip_cr) < 0) {
			fetch_read_error(ctx);
			return -1;
		}
	}

	return fetch_stream(ctx, size);
}

static int fetch_body(struct imap_fetch_context *ctx, struct mail *mail,
		      const struct imap_fetch_body_data *body)
{
	const struct message_size *fetch_size;
	struct istream *input;
	struct message_size hdr_size, body_size;

	if (body->section[0] == '\0') {
		if (mail_get_stream(mail, NULL, NULL, &input) < 0 ||
		    mail_get_virtual_size(mail, &body_size.virtual_size) < 0 ||
		    mail_get_physical_size(mail, &body_size.physical_size) < 0)
			return -1;
	} else {
		if (mail_get_stream(mail, &hdr_size,
				    body->section[0] == 'H' ? NULL : &body_size,
				    &input) < 0)
			return -1;
	}

	ctx->cur_input = input;
	i_stream_ref(ctx->cur_input);
	ctx->update_partial = TRUE;

	switch (body->section[0]) {
	case '\0':
		/* BODY[] - fetch everything */
                fetch_size = &body_size;
		ctx->cur_size_field = MAIL_FETCH_VIRTUAL_SIZE;
		break;
	case 'H':
		/* BODY[HEADER] - fetch only header */
                fetch_size = &hdr_size;
		ctx->cur_size_field = MAIL_FETCH_MESSAGE_PARTS;
		break;
	case 'T':
		/* BODY[TEXT] - skip header */
		i_stream_skip(ctx->cur_input, hdr_size.physical_size);
                fetch_size = &body_size;
		ctx->cur_size_field = MAIL_FETCH_VIRTUAL_SIZE;
		break;
	default:
		i_unreached();
	}

	return fetch_data(ctx, body, fetch_size);
}

static void header_filter_eoh(struct message_header_line *hdr,
			      bool *matched ATTR_UNUSED,
			      struct imap_fetch_context *ctx)
{
	if (hdr != NULL && hdr->eoh)
		ctx->cur_have_eoh = TRUE;
}

static int fetch_header_partial_from(struct imap_fetch_context *ctx,
				     const struct imap_fetch_body_data *body,
				     const char *header_section)
{
	struct message_size msg_size;
	struct istream *input;
	uoff_t old_offset;

	/* MIME, HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */

	ctx->cur_have_eoh = FALSE;
	if (strncmp(header_section, "HEADER.FIELDS ", 14) == 0) {
		input = i_stream_create_header_filter(ctx->cur_input,
						      HEADER_FILTER_INCLUDE,
						      body->fields,
						      body->fields_count,
						      header_filter_eoh, ctx);
	} else if (strncmp(header_section, "HEADER.FIELDS.NOT ", 18) == 0) {
		input = i_stream_create_header_filter(ctx->cur_input,
						      HEADER_FILTER_EXCLUDE,
						      body->fields,
						      body->fields_count,
						      header_filter_eoh, ctx);
	} else {
		i_error("BUG: Accepted invalid section from user: '%s'",
			header_section);
		return -1;
	}

	i_stream_unref(&ctx->cur_input);
	ctx->cur_input = input;
	ctx->update_partial = FALSE;

	old_offset = ctx->cur_input->v_offset;
	if (message_get_header_size(ctx->cur_input, &msg_size, NULL) < 0) {
		fetch_read_error(ctx);
		return -1;
	}
	i_stream_seek(ctx->cur_input, old_offset);

	if (!ctx->cur_have_eoh &&
	    (ctx->client->set->parsed_workarounds & WORKAROUND_NETSCAPE_EOH) != 0) {
		/* Netscape 4.x doesn't like if end of headers line is
		   missing. */
		msg_size.virtual_size += 2;
		ctx->cur_append_eoh = TRUE;
	}

	ctx->cur_size_field = 0;
	return fetch_data(ctx, body, &msg_size);
}

static int
fetch_body_header_partial(struct imap_fetch_context *ctx, struct mail *mail,
			  const struct imap_fetch_body_data *body)
{
	if (mail_get_stream(mail, NULL, NULL, &ctx->cur_input) < 0)
		return -1;

	i_stream_ref(ctx->cur_input);
	ctx->update_partial = FALSE;

	return fetch_header_partial_from(ctx, body, body->section);
}

static int
fetch_body_header_fields(struct imap_fetch_context *ctx, struct mail *mail,
			 struct imap_fetch_body_data *body)
{
	struct message_size size;
	uoff_t old_offset;

	if (mail == NULL) {
		/* deinit */
		mailbox_header_lookup_unref(&body->header_ctx);
		return 0;
	}

	if (mail_get_header_stream(mail, body->header_ctx, &ctx->cur_input) < 0)
		return -1;

	i_stream_ref(ctx->cur_input);
	ctx->update_partial = FALSE;

	old_offset = ctx->cur_input->v_offset;
	if (message_get_body_size(ctx->cur_input, &size, NULL) < 0) {
		fetch_read_error(ctx);
		return -1;
	}
	i_stream_seek(ctx->cur_input, old_offset);

	/* FIXME: We'll just always add the end of headers line now.
	   ideally mail-storage would have a way to tell us if it exists. */
	size.virtual_size += 2;
	ctx->cur_append_eoh = TRUE;

	ctx->cur_size_field = 0;
	return fetch_data(ctx, body, &size);
}

/* Find message_part for section (eg. 1.3.4) */
static int part_find(struct mail *mail, const struct imap_fetch_body_data *body,
		     const struct message_part **part_r, const char **section_r)
{
	const struct message_part *part;
	const char *path;
	unsigned int num;

	if (mail_get_parts(mail, &part) < 0)
		return -1;

	path = body->section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number, we have already verified its validity */
		num = 0;
		while (*path != '\0' && *path != '.') {
			i_assert(*path >= '0' && *path <= '9');

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
		    (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) &&
		    (*path >= '0' && *path <= '9')) {
			/* if we continue inside the message/rfc822, skip this
			   body part */
			part = part->children;
		}
	}

	*part_r = part;
	*section_r = path;
	return 0;
}

static int fetch_body_mime(struct imap_fetch_context *ctx, struct mail *mail,
			   const struct imap_fetch_body_data *body)
{
	const struct message_part *part;
	const char *section;

	if (part_find(mail, body, &part, &section) < 0)
		return -1;

	if (part == NULL) {
		/* part doesn't exist */
		string_t *str = get_prefix(ctx, body, (uoff_t)-1);
		if (o_stream_send(ctx->client->output,
				  str_data(str), str_len(str)) < 0)
			return -1;
		return 1;
	}

	if (mail_get_stream(mail, NULL, NULL, &ctx->cur_input) < 0)
		return -1;

	i_stream_ref(ctx->cur_input);
	ctx->update_partial = TRUE;
	ctx->cur_size_field = MAIL_FETCH_MESSAGE_PARTS;

	if (*section == '\0') {
		/* fetch the whole section */
		i_stream_seek(ctx->cur_input, part->physical_pos +
			      part->header_size.physical_size);
		return fetch_data(ctx, body, &part->body_size);
	}

	if (strcmp(section, "MIME") == 0) {
		/* fetch section's MIME header */
		i_stream_seek(ctx->cur_input, part->physical_pos);
		return fetch_data(ctx, body, &part->header_size);
	}

	/* TEXT and HEADER are only for message/rfc822 parts */
	if ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) == 0) {
		string_t *str = get_prefix(ctx, body, 0);
		if (o_stream_send(ctx->client->output,
				  str_data(str), str_len(str)) < 0)
			return -1;
		return 1;
	}

	i_assert(part->children != NULL && part->children->next == NULL);
	part = part->children;

	if (strcmp(section, "TEXT") == 0) {
		i_stream_seek(ctx->cur_input, part->physical_pos +
			      part->header_size.physical_size);
		return fetch_data(ctx, body, &part->body_size);
	}

	if (strcmp(section, "HEADER") == 0) {
		/* all headers */
		i_stream_seek(ctx->cur_input, part->physical_pos);
		return fetch_data(ctx, body, &part->header_size);
	}

	if (strncmp(section, "HEADER", 6) == 0) {
		i_stream_seek(ctx->cur_input, part->physical_pos);
		return fetch_header_partial_from(ctx, body, section);
	}

	i_error("BUG: Accepted invalid section from user: '%s'", body->section);
	return 1;
}

static bool fetch_body_header_fields_check(const char *section)
{
	if (*section++ != '(')
		return FALSE;

	if (*section == ')')
		return FALSE; /* has to be at least one field */

	while (*section != '\0' && *section != ')') {
		if (*section == '(')
			return FALSE;
		section++;
	}

	if (*section++ != ')')
		return FALSE;

	if (*section != '\0')
		return FALSE;
	return TRUE;
}

static bool fetch_body_header_fields_init(struct imap_fetch_context *ctx,
					  struct imap_fetch_body_data *body,
					  const char *section)
{
	const char *const *arr, *name;

	if (!fetch_body_header_fields_check(section))
		return FALSE;

	name = get_body_name(body);
	if ((ctx->fetch_data & (MAIL_FETCH_STREAM_HEADER |
				MAIL_FETCH_STREAM_BODY)) != 0) {
		/* we'll need to open the file anyway, don't try to get the
		   headers from cache. */
		imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
				       fetch_body_header_partial, body);
		return TRUE;
	}

	for (arr = body->fields; *arr != NULL; arr++) {
		const char *hdr = p_strdup(ctx->cmd->pool, *arr);
		array_append(&ctx->all_headers, &hdr, 1);
	}

	body->header_ctx = mailbox_header_lookup_init(ctx->box, body->fields);
	imap_fetch_add_handler(ctx, FALSE, TRUE, name, "NIL",
			       fetch_body_header_fields, body);
	return TRUE;
}

static bool fetch_body_section_name_init(struct imap_fetch_context *ctx,
					 struct imap_fetch_body_data *body)
{
	const char *name, *section = body->section;

	name = get_body_name(body);
	if (*section == '\0') {
		ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER |
			MAIL_FETCH_STREAM_BODY;
		imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
				       fetch_body, body);
		return TRUE;
	}

	if (strcmp(section, "TEXT") == 0) {
		ctx->fetch_data |= MAIL_FETCH_STREAM_BODY;
		imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
				       fetch_body, body);
		return TRUE;
	}

	if (strncmp(section, "HEADER", 6) == 0) {
		/* exact header matches could be cached */
		if (section[6] == '\0') {
			ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER;
			imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
					       fetch_body, body);
			return TRUE;
		}

		if (strncmp(section, "HEADER.FIELDS ", 14) == 0 &&
		    fetch_body_header_fields_init(ctx, body, section+14))
			return TRUE;

		if (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0 &&
		    fetch_body_header_fields_check(section+18)) {
			imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
					       fetch_body_header_partial, body);
			return TRUE;
		}
	} else if (*section >= '0' && *section <= '9') {
		ctx->fetch_data |= MAIL_FETCH_STREAM_BODY |
			MAIL_FETCH_MESSAGE_PARTS;

		while ((*section >= '0' && *section <= '9') ||
		       *section == '.') section++;

		if (*section == '\0' ||
		    strcmp(section, "MIME") == 0 ||
		    strcmp(section, "TEXT") == 0 ||
		    strcmp(section, "HEADER") == 0 ||
		    (strncmp(section, "HEADER.FIELDS ", 14) == 0 &&
		     fetch_body_header_fields_check(section+14)) ||
		    (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0 &&
		     fetch_body_header_fields_check(section+18))) {
			imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
					       fetch_body_mime, body);
			return TRUE;
		}
	}

	client_send_command_error(ctx->cmd,
		"Invalid BODY[..] parameter: Unknown or broken section");
	return FALSE;
}

/* Parse next digits in string into integer. Returns FALSE if the integer
   becomes too big and wraps. */
static bool read_uoff_t(const char **p, uoff_t *value)
{
	uoff_t prev;

	*value = 0;
	while (**p >= '0' && **p <= '9') {
		prev = *value;
		*value = *value * 10 + (**p - '0');

		if (*value < prev)
			return FALSE;

		(*p)++;
	}

	return TRUE;
}

static bool body_section_build(struct imap_fetch_context *ctx,
			       struct imap_fetch_body_data *body,
			       const char *prefix,
			       const struct imap_arg *args,
			       unsigned int args_count)
{
	string_t *str;
	const char **arr;
	size_t i;

	str = str_new(ctx->cmd->pool, 128);
	str_append(str, prefix);
	str_append(str, " (");

	/* @UNSAFE: NULL-terminated list of headers */
	arr = p_new(ctx->cmd->pool, const char *, args_count + 1);

	for (i = 0; i < args_count; i++) {
		if (args[i].type != IMAP_ARG_ATOM &&
		    args[i].type != IMAP_ARG_STRING) {
			client_send_command_error(ctx->cmd,
				"Invalid BODY[..] parameter: "
				"Header list contains non-strings");
			return FALSE;
		}

		if (i != 0)
			str_append_c(str, ' ');
		arr[i] = t_str_ucase(IMAP_ARG_STR(&args[i]));

		if (args[i].type == IMAP_ARG_ATOM)
			str_append(str, arr[i]);
		else {
			str_append_c(str, '"');
			str_append(str, str_escape(arr[i]));
			str_append_c(str, '"');
		}
	}
	str_append_c(str, ')');

	qsort(arr, args_count, sizeof(*arr), i_strcasecmp_p);
	body->fields = arr;
	body->fields_count = args_count;
	body->section = str_c(str);
	return TRUE;
}
  
bool fetch_body_section_init(struct imap_fetch_context *ctx, const char *name,
			     const struct imap_arg **args)
{
	struct imap_fetch_body_data *body;
	const char *partial;
	const char *p = name + 4;

	body = p_new(ctx->cmd->pool, struct imap_fetch_body_data, 1);
	body->max_size = (uoff_t)-1;

	if (strncmp(p, ".PEEK", 5) == 0) {
		body->peek = TRUE;
		p += 5;
	} else {
		ctx->flags_update_seen = TRUE;
	}

	if (*p != '[') {
		client_send_command_error(ctx->cmd,
			"Invalid BODY[..] parameter: Missing '['");
		return FALSE;
	}

	if ((*args)[0].type == IMAP_ARG_LIST) {
		/* BODY[HEADER.FIELDS.. (headers list)] */
		if ((*args)[1].type != IMAP_ARG_ATOM ||
		    IMAP_ARG_STR(&(*args)[1])[0] != ']') {
			client_send_command_error(ctx->cmd,
				"Invalid BODY[..] parameter: Missing ']'");
			return FALSE;
		}
		if (!body_section_build(ctx, body, p+1,
					IMAP_ARG_LIST_ARGS(&(*args)[0]),
					IMAP_ARG_LIST_COUNT(&(*args)[0])))
			return FALSE;
		p = IMAP_ARG_STR(&(*args)[1]);
		*args += 2;
	} else {
		/* no headers list */
		body->section = p+1;
		p = strchr(body->section, ']');
		if (p == NULL) {
			client_send_command_error(ctx->cmd,
				"Invalid BODY[..] parameter: Missing ']'");
			return FALSE;
		}
		body->section = p_strdup_until(ctx->cmd->pool,
					       body->section, p);
	}

	if (*++p == '<') {
		/* <start.end> */
		partial = p;
		p++;
		body->skip_set = TRUE;

		if (!read_uoff_t(&p, &body->skip) || body->skip > OFF_T_MAX) {
			/* wrapped */
			client_send_command_error(ctx->cmd,
				"Invalid BODY[..] parameter: "
				"Too big partial start");
			return FALSE;
		}

		if (*p == '.') {
			p++;
			if (!read_uoff_t(&p, &body->max_size) ||
			    body->max_size > OFF_T_MAX) {
				/* wrapped */
				client_send_command_error(ctx->cmd,
					"Invalid BODY[..] parameter: "
					"Too big partial end");
				return FALSE;
			}
		}

		if (*p != '>') {
			client_send_command_error(ctx->cmd,
				t_strdup_printf("Invalid BODY[..] parameter: "
						"Missing '>' in '%s'",
						partial));
			return FALSE;
		}
	}

	return fetch_body_section_name_init(ctx, body);
}

static int fetch_rfc822_size(struct imap_fetch_context *ctx, struct mail *mail,
			     void *context ATTR_UNUSED)
{
	uoff_t size;

	if (mail_get_virtual_size(mail, &size) < 0)
		return -1;

	str_printfa(ctx->cur_str, "RFC822.SIZE %"PRIuUOFF_T" ", size);
	return 1;
}

static int fetch_rfc822(struct imap_fetch_context *ctx, struct mail *mail,
			void *context ATTR_UNUSED)
{
	struct message_size size;
	const char *str;
	struct istream *input;

	if (mail_get_stream(mail, NULL, NULL, &input) < 0 ||
	    mail_get_virtual_size(mail, &size.virtual_size) < 0 ||
	    mail_get_physical_size(mail, &size.physical_size) < 0)
		return -1;

	ctx->cur_input = input;
	i_stream_ref(ctx->cur_input);
	ctx->update_partial = FALSE;

	if (ctx->cur_offset == 0) {
		str = t_strdup_printf(" RFC822 {%"PRIuUOFF_T"}\r\n",
				      size.virtual_size);
		if (ctx->first) {
			str++; ctx->first = FALSE;
		}
		if (o_stream_send_str(ctx->client->output, str) < 0)
			return -1;
	}

	ctx->cur_name = "RFC822";
        ctx->cur_size = size.virtual_size;
	ctx->cur_size_field = MAIL_FETCH_VIRTUAL_SIZE;
	return fetch_stream(ctx, &size);
}

static int fetch_rfc822_header(struct imap_fetch_context *ctx,
			       struct mail *mail, void *context ATTR_UNUSED)
{
	struct message_size hdr_size;
	const char *str;

	if (mail_get_stream(mail, &hdr_size, NULL, &ctx->cur_input) < 0)
		return -1;

	i_stream_ref(ctx->cur_input);
	ctx->update_partial = FALSE;

	str = t_strdup_printf(" RFC822.HEADER {%"PRIuUOFF_T"}\r\n",
			      hdr_size.virtual_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_stream_send_str(ctx->client->output, str) < 0)
		return -1;

	ctx->cur_name = "RFC822.HEADER";
        ctx->cur_size = hdr_size.virtual_size;
	ctx->cur_size_field = MAIL_FETCH_MESSAGE_PARTS;
	return fetch_stream(ctx, &hdr_size);
}

static int fetch_rfc822_text(struct imap_fetch_context *ctx, struct mail *mail,
			     void *context ATTR_UNUSED)
{
	struct message_size hdr_size, body_size;
	const char *str;

	if (mail_get_stream(mail, &hdr_size, &body_size, &ctx->cur_input) < 0)
		return -1;

	i_stream_ref(ctx->cur_input);
	ctx->update_partial = FALSE;

	str = t_strdup_printf(" RFC822.TEXT {%"PRIuUOFF_T"}\r\n",
			      body_size.virtual_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_stream_send_str(ctx->client->output, str) < 0)
		return -1;

	i_stream_seek(ctx->cur_input, hdr_size.physical_size);
	ctx->cur_name = "RFC822.TEXT";
        ctx->cur_size = body_size.virtual_size;
	ctx->cur_size_field = MAIL_FETCH_VIRTUAL_SIZE;
	return fetch_stream(ctx, &body_size);
}

bool fetch_rfc822_init(struct imap_fetch_context *ctx, const char *name,
		       const struct imap_arg **args ATTR_UNUSED)
{
	if (name[6] == '\0') {
		ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER |
			MAIL_FETCH_STREAM_BODY;
		ctx->flags_update_seen = TRUE;
		imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
				       fetch_rfc822, NULL);
		return TRUE;
	}

	if (strcmp(name+6, ".SIZE") == 0) {
		ctx->fetch_data |= MAIL_FETCH_VIRTUAL_SIZE;
		imap_fetch_add_handler(ctx, TRUE, FALSE, name, "0",
				       fetch_rfc822_size, NULL);
		return TRUE;
	}
	if (strcmp(name+6, ".HEADER") == 0) {
		ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER;
		imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
				       fetch_rfc822_header, NULL);
		return TRUE;
	}
	if (strcmp(name+6, ".TEXT") == 0) {
		ctx->fetch_data |= MAIL_FETCH_STREAM_BODY;
		ctx->flags_update_seen = TRUE;
		imap_fetch_add_handler(ctx, FALSE, FALSE, name, "NIL",
				       fetch_rfc822_text, NULL);
		return TRUE;
	}

	client_send_command_error(ctx->cmd, t_strconcat(
		"Unknown parameter ", name, NULL));
	return FALSE;
}
