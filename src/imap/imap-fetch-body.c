/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "buffer.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "istream-header-filter.h"
#include "message-parser.h"
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
	unsigned int binary:1;
	unsigned int binary_size:1;
};

static void fetch_read_error(struct imap_fetch_context *ctx)
{
	struct imap_fetch_state *state = &ctx->state;

	errno = state->cur_input->stream_errno;
	mail_storage_set_critical(state->cur_mail->box->storage,
		"read(%s) failed: %m (FETCH %s for mailbox %s UID %u)",
		state->cur_human_name,
		i_stream_get_name(state->cur_input),
		mailbox_get_vname(state->cur_mail->box), state->cur_mail->uid);
}

static const char *get_body_name(const struct imap_fetch_body_data *body)
{
	string_t *str;

	str = t_str_new(128);
	if (body->binary_size)
		str_append(str, "BINARY.SIZE");
	else if (body->binary)
		str_append(str, "BINARY");
	else
		str_append(str, "BODY");
	str_printfa(str, "[%s]", body->section);
	if (body->partial) {
		str_printfa(str, "<%"PRIuUOFF_T">",
			    imap_msgpart_get_partial_offset(body->msgpart));
	}
	return str_c(str);
}

static string_t *get_prefix(struct imap_fetch_state *state,
			    const struct imap_fetch_body_data *body,
			    uoff_t size, bool has_nuls)
{
	string_t *str;

	str = t_str_new(128);
	if (state->cur_first)
		state->cur_first = FALSE;
	else
		str_append_c(str, ' ');

	str_append(str, get_body_name(body));

	if (size == (uoff_t)-1)
		str_append(str, " NIL");
	else if (has_nuls && body->binary)
		str_printfa(str, " ~{%"PRIuUOFF_T"}\r\n", size);
	else
		str_printfa(str, " {%"PRIuUOFF_T"}\r\n", size);
	return str;
}

static int fetch_stream_continue(struct imap_fetch_context *ctx)
{
	struct imap_fetch_state *state = &ctx->state;
	off_t ret;

	o_stream_set_max_buffer_size(ctx->client->output, 0);
	ret = o_stream_send_istream(ctx->client->output, state->cur_input);
	o_stream_set_max_buffer_size(ctx->client->output, (size_t)-1);

	if (ret > 0)
		state->cur_offset += ret;

	if (state->cur_offset != state->cur_size) {
		/* unfinished */
		if (state->cur_input->stream_errno != 0) {
			fetch_read_error(ctx);
			client_disconnect(ctx->client, "FETCH failed");
			return -1;
		}
		if (!i_stream_have_bytes_left(state->cur_input)) {
			/* Input stream gave less data than expected */
			i_error("FETCH %s for mailbox %s UID %u "
				"got too little data: "
				"%"PRIuUOFF_T" vs %"PRIuUOFF_T,
				state->cur_human_name,
				mailbox_get_vname(state->cur_mail->box),
				state->cur_mail->uid,
				state->cur_offset, state->cur_size);
			mail_set_cache_corrupted(state->cur_mail,
						 state->cur_size_field);
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

static const char *
get_body_human_name(pool_t pool, struct imap_fetch_body_data *body)
{
	string_t *str;
	uoff_t partial_offset, partial_size;

	str = t_str_new(64);
	if (body->binary)
		str_append(str, "BINARY[");
	else
		str_append(str, "BODY[");
	str_append(str, body->section);
	str_append_c(str, ']');

	partial_offset = imap_msgpart_get_partial_offset(body->msgpart);
	partial_size = imap_msgpart_get_partial_size(body->msgpart);
	if (partial_offset != 0 || partial_size != (uoff_t)-1) {
		str_printfa(str, "<%"PRIuUOFF_T, partial_offset);
		if (partial_size != (uoff_t)-1)
			str_printfa(str, ".%"PRIuUOFF_T, partial_size);
		str_append_c(str, '>');
	}
	return p_strdup(pool, str_c(str));
}

static int fetch_body_msgpart(struct imap_fetch_context *ctx, struct mail *mail,
			      struct imap_fetch_body_data *body)
{
	struct imap_msgpart_open_result result;
	string_t *str;

	if (mail == NULL) {
		imap_msgpart_free(&body->msgpart);
		return 1;
	}

	if (imap_msgpart_open(mail, body->msgpart, &result) < 0) {
		if (!body->binary ||
		    mailbox_get_last_mail_error(mail->box) != MAIL_ERROR_INVALIDDATA)
			return -1;
		/* tried to do BINARY fetch for a MIME part with broken
		   content */
		str = get_prefix(&ctx->state, body, (uoff_t)-1, FALSE);
		o_stream_nsend(ctx->client->output, str_data(str), str_len(str));
		return 1;
	}
	ctx->state.cur_input = result.input;
	ctx->state.cur_size = result.size;
	ctx->state.cur_size_field = result.size_field;
	ctx->state.cur_human_name = get_body_human_name(ctx->ctx_pool, body);

	str = get_prefix(&ctx->state, body, ctx->state.cur_size,
			 result.binary_decoded_input_has_nuls);
	o_stream_nsend(ctx->client->output, str_data(str), str_len(str));

	ctx->state.cont_handler = fetch_stream_continue;
	return ctx->state.cont_handler(ctx);
}

static int fetch_binary_size(struct imap_fetch_context *ctx, struct mail *mail,
			     struct imap_fetch_body_data *body)
{
	string_t *str;
	uoff_t size;

	if (mail == NULL) {
		imap_msgpart_free(&body->msgpart);
		return 1;
	}

	if (imap_msgpart_size(mail, body->msgpart, &size) < 0) {
		if (mailbox_get_last_mail_error(mail->box) != MAIL_ERROR_INVALIDDATA)
			return -1;
		/* tried to do BINARY.SIZE fetch for a MIME part with broken
		   content */
		size = 0;
	}

	str = t_str_new(128);
	if (ctx->state.cur_first)
		ctx->state.cur_first = FALSE;
	else
		str_append_c(str, ' ');
	str_printfa(str, "%s %"PRIuUOFF_T, get_body_name(body), size);

	if (o_stream_send(ctx->client->output, str_data(str), str_len(str)) < 0)
		return -1;
	return 1;
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

	str = str_new(ctx->pool, 128);
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
		else
			imap_append_quoted(str, value);
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

	body = p_new(ctx->pool, struct imap_fetch_body_data, 1);

	if (strncmp(p, ".PEEK", 5) == 0)
		p += 5;
	else
		ctx->fetch_ctx->flags_update_seen = TRUE;
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
		body->section = p_strdup_until(ctx->pool, body->section, p);
		p++;
	}
	if (imap_msgpart_parse(body->section, &body->msgpart) < 0) {
		ctx->error = "Invalid BODY[..] section";
		return FALSE;
	}
	ctx->fetch_ctx->fetch_data |=
		imap_msgpart_get_fetch_data(body->msgpart);

	if (body_parse_partial(body, p, &error) < 0) {
		ctx->error = p_strdup_printf(ctx->pool,
			"Invalid BODY[..] parameter: %s", error);
		return FALSE;
	}

	/* update the section name for the imap_fetch_add_handler() */
	ctx->name = p_strdup(ctx->pool, get_body_name(body));
	imap_fetch_add_handler(ctx, IMAP_FETCH_HANDLER_FLAG_WANT_DEINIT,
			       "NIL", fetch_body_msgpart, body);
	return TRUE;
}

bool imap_fetch_binary_init(struct imap_fetch_init_context *ctx)
{
	struct imap_fetch_body_data *body;
	const struct imap_arg *list_args;
	unsigned int list_count;
	const char *str, *p, *error;

	i_assert(strncmp(ctx->name, "BINARY", 6) == 0);
	p = ctx->name + 6;

	body = p_new(ctx->pool, struct imap_fetch_body_data, 1);
	body->binary = TRUE;

	if (strncmp(p, ".SIZE", 5) == 0) {
		/* fetch decoded size of the section */
		p += 5;
		body->binary_size = TRUE;
	} else if (strncmp(p, ".PEEK", 5) == 0) {
		p += 5;
	} else {
		ctx->fetch_ctx->flags_update_seen = TRUE;
	}
	if (*p != '[') {
		ctx->error = "Invalid BINARY[..] parameter: Missing '['";
		return FALSE;
	}

	if (imap_arg_get_list_full(&ctx->args[0], &list_args, &list_count)) {
		/* BINARY[HEADER.FIELDS.. (headers list)] */
		if (!imap_arg_get_atom(&ctx->args[1], &str) ||
		    str[0] != ']') {
			ctx->error = "Invalid BINARY[..] parameter: Missing ']'";
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
			ctx->error = "Invalid BINARY[..] parameter: Missing ']'";
			return FALSE;
		}
		body->section = p_strdup_until(ctx->pool, body->section, p);
		p++;
	}
	if (imap_msgpart_parse(body->section, &body->msgpart) < 0) {
		ctx->error = "Invalid BINARY[..] section";
		return -1;
	}
	imap_msgpart_set_decode_to_binary(body->msgpart);
	ctx->fetch_ctx->fetch_data |=
		imap_msgpart_get_fetch_data(body->msgpart);

	if (!body->binary_size) {
		if (body_parse_partial(body, p, &error) < 0) {
			ctx->error = p_strdup_printf(ctx->pool,
				"Invalid BINARY[..] parameter: %s", error);
			return FALSE;
		}
	}

	/* update the section name for the imap_fetch_add_handler() */
	ctx->name = p_strdup(ctx->pool, get_body_name(body));
	if (body->binary_size) {
		imap_fetch_add_handler(ctx, IMAP_FETCH_HANDLER_FLAG_WANT_DEINIT,
				       "0", fetch_binary_size, body);
	} else {
		imap_fetch_add_handler(ctx, IMAP_FETCH_HANDLER_FLAG_WANT_DEINIT,
				       "NIL", fetch_body_msgpart, body);
	}
	return TRUE;
}

static int ATTR_NULL(3)
fetch_rfc822_size(struct imap_fetch_context *ctx, struct mail *mail,
		  void *context ATTR_UNUSED)
{
	uoff_t size;

	if (mail_get_virtual_size(mail, &size) < 0)
		return -1;

	str_printfa(ctx->state.cur_str, "RFC822.SIZE %"PRIuUOFF_T" ", size);
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
	ctx->state.cur_input = result.input;
	ctx->state.cur_size = result.size;
	ctx->state.cur_size_field = result.size_field;
	ctx->state.cont_handler = fetch_stream_continue;
	return 0;
}

static int ATTR_NULL(3)
fetch_rfc822(struct imap_fetch_context *ctx, struct mail *mail,
	     void *context ATTR_UNUSED)
{
	struct imap_msgpart *msgpart;
	const char *str;

	msgpart = imap_msgpart_full();
	if (fetch_and_free_msgpart(ctx, mail, &msgpart) < 0)
		return -1;

	str = t_strdup_printf(" RFC822 {%"PRIuUOFF_T"}\r\n",
			      ctx->state.cur_size);
	if (ctx->state.cur_first) {
		str++; ctx->state.cur_first = FALSE;
	}
	o_stream_nsend_str(ctx->client->output, str);

	ctx->state.cur_human_name = "RFC822";
	return ctx->state.cont_handler(ctx);
}

static int ATTR_NULL(3)
fetch_rfc822_header(struct imap_fetch_context *ctx,
		    struct mail *mail, void *context ATTR_UNUSED)
{
	struct imap_msgpart *msgpart;
	const char *str;

	msgpart = imap_msgpart_header();
	if (fetch_and_free_msgpart(ctx, mail, &msgpart) < 0)
		return -1;

	str = t_strdup_printf(" RFC822.HEADER {%"PRIuUOFF_T"}\r\n",
			      ctx->state.cur_size);
	if (ctx->state.cur_first) {
		str++; ctx->state.cur_first = FALSE;
	}
	o_stream_nsend_str(ctx->client->output, str);

	ctx->state.cur_human_name = "RFC822.HEADER";
	return ctx->state.cont_handler(ctx);
}

static int ATTR_NULL(3)
fetch_rfc822_text(struct imap_fetch_context *ctx, struct mail *mail,
		  void *context ATTR_UNUSED)
{
	struct imap_msgpart *msgpart;
	const char *str;

	msgpart = imap_msgpart_body();
	if (fetch_and_free_msgpart(ctx, mail, &msgpart) < 0)
		return -1;

	str = t_strdup_printf(" RFC822.TEXT {%"PRIuUOFF_T"}\r\n",
			      ctx->state.cur_size);
	if (ctx->state.cur_first) {
		str++; ctx->state.cur_first = FALSE;
	}
	o_stream_nsend_str(ctx->client->output, str);

	ctx->state.cur_human_name = "RFC822.TEXT";
	return ctx->state.cont_handler(ctx);
}

bool imap_fetch_rfc822_init(struct imap_fetch_init_context *ctx)
{
	const char *name = ctx->name;

	if (name[6] == '\0') {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER |
			MAIL_FETCH_STREAM_BODY;
		ctx->fetch_ctx->flags_update_seen = TRUE;
		imap_fetch_add_handler(ctx, 0, "NIL",
				       fetch_rfc822, (void *)NULL);
		return TRUE;
	}

	if (strcmp(name+6, ".SIZE") == 0) {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_VIRTUAL_SIZE;
		imap_fetch_add_handler(ctx, IMAP_FETCH_HANDLER_FLAG_BUFFERED,
				       "0", fetch_rfc822_size, (void *)NULL);
		return TRUE;
	}
	if (strcmp(name+6, ".HEADER") == 0) {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_STREAM_HEADER;
		imap_fetch_add_handler(ctx, 0, "NIL",
				       fetch_rfc822_header, (void *)NULL);
		return TRUE;
	}
	if (strcmp(name+6, ".TEXT") == 0) {
		ctx->fetch_ctx->fetch_data |= MAIL_FETCH_STREAM_BODY;
		ctx->fetch_ctx->flags_update_seen = TRUE;
		imap_fetch_add_handler(ctx, 0, "NIL",
				       fetch_rfc822_text, (void *)NULL);
		return TRUE;
	}

	ctx->error = t_strconcat("Unknown parameter ", name, NULL);
	return FALSE;
}
