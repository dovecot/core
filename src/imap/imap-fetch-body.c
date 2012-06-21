/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "buffer.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "istream-header-filter.h"
#include "message-parser.h"
#include "message-send.h"
#include "mail-storage-private.h"
#include "imap-quote.h"
#include "imap-parser.h"
#include "imap-msgpart.h"
#include "imap-fetch.h"

#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

struct imap_fetch_body_data {
	const char *section; /* NOTE: always uppercased */
	struct imap_msgpart *msgpart;

	unsigned int partial:1;
	unsigned int peek:1;
};

static void fetch_read_error(struct imap_fetch_context *ctx)
{
	errno = ctx->cur_input->stream_errno;
	mail_storage_set_critical(ctx->box->storage,
		"read(%s) failed: %m (FETCH for mailbox %s UID %u)",
		i_stream_get_name(ctx->cur_input),
		mailbox_get_vname(ctx->cur_mail->box), ctx->cur_mail->uid);
}

static const char *get_body_name(const struct imap_fetch_body_data *body)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "BODY[%s]", body->section);
	if (body->partial) {
		str_printfa(str, "<%"PRIuUOFF_T">",
			    imap_msgpart_get_partial_offset(body->msgpart));
	}
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

static int fetch_stream_continue(struct imap_fetch_context *ctx)
{
	off_t ret;

	o_stream_set_max_buffer_size(ctx->client->output, 0);
	ret = o_stream_send_istream(ctx->client->output, ctx->cur_input);
	o_stream_set_max_buffer_size(ctx->client->output, (size_t)-1);

	if (ret > 0)
		ctx->cur_offset += ret;

	if (ctx->cur_offset != ctx->cur_size) {
		/* unfinished */
		if (ctx->cur_input->stream_errno != 0) {
			fetch_read_error(ctx);
			client_disconnect(ctx->client, "FETCH failed");
			return -1;
		}
		if (!i_stream_have_bytes_left(ctx->cur_input)) {
			/* Input stream gave less data than expected */
			i_error("FETCH %s for mailbox %s UID %u "
				"got too little data: "
				"%"PRIuUOFF_T" vs %"PRIuUOFF_T,
				ctx->cur_name, mailbox_get_vname(ctx->cur_mail->box),
				ctx->cur_mail->uid, ctx->cur_offset, ctx->cur_size);
			mail_set_cache_corrupted(ctx->cur_mail,
						 ctx->cur_size_field);
			client_disconnect(ctx->client, "FETCH failed");
			return -1;
		}
		if (ret < 0) {
			/* client probably disconnected */
			return -1;
		}

		o_stream_set_flush_pending(ctx->client->output, TRUE);
		return 0;
	}
	return 1;
}

static int fetch_body_msgpart(struct imap_fetch_context *ctx, struct mail *mail,
			      const struct imap_fetch_body_data *body)
{
	struct imap_msgpart_open_result result;
	string_t *str;

	if (imap_msgpart_open(mail, body->msgpart, &result) < 0)
		return -1;
	ctx->cur_input = result.input;
	ctx->cur_size = result.size;
	ctx->cur_size_field = result.size_field;
	ctx->cur_name = p_strconcat(ctx->pool, "[", body->section, "]", NULL);

	str = get_prefix(ctx, body, ctx->cur_size);
	if (o_stream_send(ctx->client->output, str_data(str), str_len(str)) < 0)
		return -1;

	ctx->cont_handler = fetch_stream_continue;
	return ctx->cont_handler(ctx);
}

/* Parse next digits in string into integer. Returns -1 if the integer
   becomes too big and wraps. */
static int read_uoff_t(const char **p, uoff_t *value)
{
	uoff_t prev;

	*value = 0;
	while (**p >= '0' && **p <= '9') {
		prev = *value;
		*value = *value * 10 + (**p - '0');

		if (*value < prev)
			return -1;

		(*p)++;
	}
	return 0;
}

static int
body_header_fields_parse(struct imap_fetch_init_context *ctx,
			 struct imap_fetch_body_data *body, const char *prefix,
			 const struct imap_arg *args, unsigned int args_count)
{
	string_t *str;
	const char *value;
	size_t i;

	str = str_new(ctx->fetch_ctx->pool, 128);
	str_append(str, prefix);
	str_append(str, " (");

	for (i = 0; i < args_count; i++) {
		if (!imap_arg_get_astring(&args[i], &value)) {
			ctx->error = "Invalid BODY[..] parameter: "
				"Header list contains non-strings";
			return -1;
		}
		value = t_str_ucase(value);

		if (i != 0)
			str_append_c(str, ' ');

		if (args[i].type == IMAP_ARG_ATOM)
			str_append(str, value);
		else {
			str_append_c(str, '"');
			imap_dquote_append(str, value);
			str_append_c(str, '"');
		}
	}
	str_append_c(str, ')');
	body->section = str_c(str);
	return 0;
}

static int body_parse_partial(struct imap_fetch_body_data *body,
			      const char *p, const char **error_r)
{
	uoff_t offset, size = (uoff_t)-1;

	if (*p == '\0')
		return 0;
	/* <start.end> */
	if (*p != '<') {
		*error_r = "Unexpected data after ']'";
		return -1;
	}

	p++;
	body->partial = TRUE;

	if (read_uoff_t(&p, &offset) < 0 || offset > OFF_T_MAX) {
		/* wrapped */
		*error_r = "Too big partial start";
		return -1;
	}

	if (*p == '.') {
		p++;
		if (read_uoff_t(&p, &size) < 0 || size > OFF_T_MAX) {
			/* wrapped */
			*error_r = "Too big partial end";
			return -1;
		}
	}

	if (*p != '>') {
		*error_r = "Missing '>' in partial";
		return -1;
	}
	if (p[1] != '\0') {
		*error_r = "Unexpected data after '>'";
		return -1;
	}
	imap_msgpart_set_partial(body->msgpart, offset, size);
	return 0;
}

bool imap_fetch_body_section_init(struct imap_fetch_init_context *ctx)
{
	struct imap_fetch_body_data *body;
	const struct imap_arg *list_args;
	unsigned int list_count;
	const char *str, *p, *error;

	i_assert(strncmp(ctx->name, "BODY", 4) == 0);
	p = ctx->name + 4;

	body = p_new(ctx->fetch_ctx->pool, struct imap_fetch_body_data, 1);

	if (strncmp(p, ".PEEK", 5) == 0) {
		body->peek = TRUE;
		p += 5;
	} else {
		ctx->fetch_ctx->flags_update_seen = TRUE;
	}

	if (*p != '[') {
		ctx->error = "Invalid BODY[..] parameter: Missing '['";
		return FALSE;
	}

	if (imap_arg_get_list_full(&ctx->args[0], &list_args, &list_count)) {
		/* BODY[HEADER.FIELDS.. (headers list)] */
		if (!imap_arg_get_atom(&ctx->args[1], &str) ||
		    str[0] != ']') {
			ctx->error = "Invalid BODY[..] parameter: Missing ']'";
			return FALSE;
		}
		if (body_header_fields_parse(ctx, body, p+1,
					     list_args, list_count) < 0)
			return FALSE;
		p = str+1;
		ctx->args += 2;
	} else {
		/* no headers list */
		body->section = p+1;
		p = strchr(body->section, ']');
		if (p == NULL) {
			ctx->error = "Invalid BODY[..] parameter: Missing ']'";
			return FALSE;
		}
		body->section = p_strdup_until(ctx->fetch_ctx->pool,
					       body->section, p);
		p++;
	}
	if (imap_msgpart_parse(ctx->fetch_ctx->box, body->section,
			       &body->msgpart) < 0) {
		ctx->error = "Invalid BODY[..] section";
		return -1;
	}
	ctx->fetch_ctx->fetch_data |=
		imap_msgpart_get_fetch_data(body->msgpart);

	if (body_parse_partial(body, p, &error) < 0) {
		ctx->error = p_strdup_printf(ctx->fetch_ctx->pool,
			"Invalid BODY[..] parameter: %s", error);
		return FALSE;
	}

	/* update the section name for the imap_fetch_add_handler() */
	ctx->name = p_strdup(ctx->fetch_ctx->pool, get_body_name(body));
	imap_fetch_add_handler(ctx, 0, "NIL", fetch_body_msgpart, body);
	return TRUE;
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

static int
fetch_and_free_msgpart(struct imap_fetch_context *ctx,
		       struct mail *mail, struct imap_msgpart **_msgpart)
{
	struct imap_msgpart_open_result result;
	int ret;

	ret = imap_msgpart_open(mail, *_msgpart, &result);
	imap_msgpart_free(_msgpart);
	if (ret < 0)
		return -1;
	ctx->cur_input = result.input;
	ctx->cur_size = result.size;
	ctx->cur_size_field = result.size_field;
	ctx->cont_handler = fetch_stream_continue;
	return 0;
}

static int fetch_rfc822(struct imap_fetch_context *ctx, struct mail *mail,
			void *context ATTR_UNUSED)
{
	struct imap_msgpart *msgpart;
	const char *str;

	msgpart = imap_msgpart_full();
	fetch_and_free_msgpart(ctx, mail, &msgpart);

	str = t_strdup_printf(" RFC822 {%"PRIuUOFF_T"}\r\n", ctx->cur_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_stream_send_str(ctx->client->output, str) < 0)
		return -1;

	ctx->cur_name = "RFC822";
	return ctx->cont_handler(ctx);
}

static int fetch_rfc822_header(struct imap_fetch_context *ctx,
			       struct mail *mail, void *context ATTR_UNUSED)
{
	struct imap_msgpart *msgpart;
	const char *str;

	msgpart = imap_msgpart_header();
	fetch_and_free_msgpart(ctx, mail, &msgpart);

	str = t_strdup_printf(" RFC822.HEADER {%"PRIuUOFF_T"}\r\n",
			      ctx->cur_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_stream_send_str(ctx->client->output, str) < 0)
		return -1;

	ctx->cur_name = "RFC822.HEADER";
	return ctx->cont_handler(ctx);
}

static int fetch_rfc822_text(struct imap_fetch_context *ctx, struct mail *mail,
			     void *context ATTR_UNUSED)
{
	struct imap_msgpart *msgpart;
	const char *str;

	msgpart = imap_msgpart_body();
	fetch_and_free_msgpart(ctx, mail, &msgpart);

	str = t_strdup_printf(" RFC822.TEXT {%"PRIuUOFF_T"}\r\n",
			      ctx->cur_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_stream_send_str(ctx->client->output, str) < 0)
		return -1;

	ctx->cur_name = "RFC822.TEXT";
	return ctx->cont_handler(ctx);
}

bool imap_fetch_rfc822_init(struct imap_fetch_init_context *ctx)
{
	const char *name = ctx->name;

	if (name[6] == '\0') {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER |
			MAIL_FETCH_STREAM_BODY;
		ctx->fetch_ctx->flags_update_seen = TRUE;
		imap_fetch_add_handler(ctx, 0, "NIL", fetch_rfc822, NULL);
		return TRUE;
	}

	if (strcmp(name+6, ".SIZE") == 0) {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_VIRTUAL_SIZE;
		imap_fetch_add_handler(ctx, IMAP_FETCH_HANDLER_FLAG_BUFFERED,
				       "0", fetch_rfc822_size, NULL);
		return TRUE;
	}
	if (strcmp(name+6, ".HEADER") == 0) {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER;
		imap_fetch_add_handler(ctx, 0, "NIL",
				       fetch_rfc822_header, NULL);
		return TRUE;
	}
	if (strcmp(name+6, ".TEXT") == 0) {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_STREAM_BODY;
		ctx->fetch_ctx->flags_update_seen = TRUE;
		imap_fetch_add_handler(ctx, 0, "NIL", fetch_rfc822_text, NULL);
		return TRUE;
	}

	ctx->error = t_strconcat("Unknown parameter ", name, NULL);
	return FALSE;
}
