/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "message-address.h"
#include "message-size.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "message-decoder.h"
#include "imap-util.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "mail-namespace.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"

#include <stdio.h>

struct fetch_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	struct ostream *output;
	struct mail *mail;

	ARRAY(struct fetch_field) fields;
	ARRAY_TYPE(const_string) header_fields;
	enum mail_fetch_field wanted_fields;

	const struct fetch_field *cur_field;
};

struct fetch_field {
	const char *name;
	enum mail_fetch_field wanted_fields;
	int (*print)(struct fetch_cmd_context *ctx);
};

static int fetch_user(struct fetch_cmd_context *ctx)
{
	doveadm_print(ctx->ctx.cur_mail_user->username);
	return 0;
}

static int fetch_mailbox(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_MAILBOX_NAME, &value) < 0)
		return -1;

	doveadm_print(value);
	return 0;
}

static int fetch_mailbox_guid(struct fetch_cmd_context *ctx)
{
	struct mailbox_metadata metadata;

	if (mailbox_get_metadata(ctx->mail->box, MAILBOX_METADATA_GUID,
				 &metadata) < 0)
		return -1;
	doveadm_print(guid_128_to_string(metadata.guid));
	return 0;
}

static int fetch_seq(struct fetch_cmd_context *ctx)
{
	doveadm_print_num(ctx->mail->seq);
	return 0;
}

static int fetch_uid(struct fetch_cmd_context *ctx)
{
	doveadm_print_num(ctx->mail->uid);
	return 0;
}

static int fetch_guid(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_GUID, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}

static int fetch_flags(struct fetch_cmd_context *ctx)
{
	string_t *str = t_str_new(64);

	imap_write_flags(str, mail_get_flags(ctx->mail),
			 mail_get_keywords(ctx->mail));
	doveadm_print(str_c(str));
	return 0;
}

static int fetch_modseq(struct fetch_cmd_context *ctx)
{
	doveadm_print_num(mail_get_modseq(ctx->mail));
	return 0;
}

static int fetch_hdr(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	struct message_size hdr_size;
	const unsigned char *data;
	size_t size;
	int ret = 0;

	if (mail_get_hdr_stream(ctx->mail, &hdr_size, &input) < 0)
		return -1;

	input = i_stream_create_limit(input, hdr_size.physical_size);
	while (!i_stream_is_eof(input)) {
		if (i_stream_read_data(input, &data, &size, 0) == -1)
			break;
		if (size == 0)
			break;
		doveadm_print_stream(data, size);
		i_stream_skip(input, size);
	}
	if (input->stream_errno != 0) {
		i_error("read() failed: %m");
		ret = -1;
	}
	i_stream_unref(&input);
	doveadm_print_stream("", 0);
	return ret;
}

static int fetch_hdr_field(struct fetch_cmd_context *ctx)
{
	const char *const *value, *filter, *name = ctx->cur_field->name;
	string_t *str = t_str_new(256);
	unsigned int pos;
	bool add_lf = FALSE;

	filter = strchr(name, '.');
	if (filter != NULL)
		name = t_strdup_until(name, filter++);

	if (mail_get_headers(ctx->mail, name, &value) < 0)
		return -1;

	for (; *value != NULL; value++) {
		if (add_lf)
			str_append_c(str, '\n');
		str_append(str, *value);
		add_lf = TRUE;
	}

	if (filter == NULL) {
		/* print the header as-is */
	} else if (strcmp(filter, "utf8") == 0) {
		pos = str_len(str);
		message_header_decode_utf8(str_data(str), str_len(str),
					   str, FALSE);
		str_delete(str, 0, pos);
	} else if (strcmp(filter, "address") == 0 ||
		   strcmp(filter, "address_name") == 0 ||
		   strcmp(filter, "address_name.utf8") == 0) {
		struct message_address *addr;

		addr = message_address_parse(pool_datastack_create(),
					     str_data(str), str_len(str),
					     UINT_MAX, FALSE);
		str_truncate(str, 0);
		add_lf = FALSE;
		for (; addr != NULL; addr = addr->next) {
			if (add_lf)
				str_append_c(str, '\n');
			if (strcmp(filter, "address") == 0) {
				if (addr->mailbox != NULL)
					str_append(str, addr->mailbox);
				if (addr->domain != NULL) {
					str_append_c(str, '@');
					str_append(str, addr->domain);
				}
			} else if (addr->name != NULL) {
				if (strcmp(filter, "address_name") == 0)
					str_append(str, addr->name);
				else {
					message_header_decode_utf8(
						(const void *)addr->name,
						strlen(addr->name), str, FALSE);
				}
			}
			add_lf = TRUE;
		}
	} else {
		i_fatal("Unknown header filter: %s", filter);
	}
	doveadm_print(str_c(str));
	return 0;
}

static int fetch_body(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	struct message_size hdr_size;
	const unsigned char *data;
	size_t size;
	int ret = 0;

	if (mail_get_stream(ctx->mail, &hdr_size, NULL, &input) < 0)
		return -1;

	i_stream_skip(input, hdr_size.physical_size);
	while (!i_stream_is_eof(input)) {
		if (i_stream_read_data(input, &data, &size, 0) == -1)
			break;
		if (size == 0)
			break;
		doveadm_print_stream(data, size);
		i_stream_skip(input, size);
	}
	if (input->stream_errno != 0) {
		i_error("read() failed: %m");
		ret = -1;
	}
	doveadm_print_stream("", 0);
	return ret;
}

static int fetch_text(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	const unsigned char *data;
	size_t size;
	int ret = 0;

	if (mail_get_stream(ctx->mail, NULL, NULL, &input) < 0)
		return -1;

	while (!i_stream_is_eof(input)) {
		if (i_stream_read_data(input, &data, &size, 0) == -1)
			break;
		if (size == 0)
			break;
		doveadm_print_stream(data, size);
		i_stream_skip(input, size);
	}
	if (input->stream_errno != 0) {
		i_error("read() failed: %m");
		ret = -1;
	}
	doveadm_print_stream("", 0);
	return ret;
}

static int fetch_text_utf8(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct message_part *parts;
	int ret = 0;

	if (mail_get_stream(ctx->mail, NULL, NULL, &input) < 0)
		return -1;

	parser = message_parser_init(pool_datastack_create(), input,
				     MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE,
				     0);
	decoder = message_decoder_init(NULL, 0);

	while ((ret = message_parser_parse_next_block(parser, &raw_block)) > 0) {
		if (!message_decoder_decode_next_block(decoder, &raw_block,
						       &block))
			continue;

		if (block.hdr == NULL) {
			if (block.size > 0)
				doveadm_print_stream(block.data, block.size);
		} else if (block.hdr->eoh)
			doveadm_print_stream("\n", 1);
		else {
			i_assert(block.hdr->name_len > 0);
			doveadm_print_stream(block.hdr->name,
					     block.hdr->name_len);
			doveadm_print_stream(": ", 2);
			if (block.hdr->full_value_len > 0) {
				doveadm_print_stream(block.hdr->full_value,
						     block.hdr->full_value_len);
			}
			doveadm_print_stream("\n", 1);
		}
	}
	i_assert(ret != 0);
	message_decoder_deinit(&decoder);
	(void)message_parser_deinit(&parser, &parts);

	doveadm_print_stream("", 0);
	if (input->stream_errno != 0) {
		i_error("read() failed: %m");
		return -1;
	}
	return 0;
}

static int fetch_size_physical(struct fetch_cmd_context *ctx)
{
	uoff_t size;

	if (mail_get_physical_size(ctx->mail, &size) < 0)
		return -1;
	doveadm_print_num(size);
	return 0;
}

static int fetch_size_virtual(struct fetch_cmd_context *ctx)
{
	uoff_t size;

	if (mail_get_virtual_size(ctx->mail, &size) < 0)
		return -1;
	doveadm_print_num(size);
	return 0;
}

static int fetch_date_received(struct fetch_cmd_context *ctx)
{
	time_t t;

	if (mail_get_received_date(ctx->mail, &t) < 0)
		return -1;
	doveadm_print(unixdate2str(t));
	return 0;
}

static int fetch_date_sent(struct fetch_cmd_context *ctx)
{
	time_t t;
	int tz;
	char chr;

	if (mail_get_date(ctx->mail, &t, &tz) < 0)
		return -1;

	chr = tz < 0 ? '-' : '+';
	if (tz < 0) tz = -tz;
	doveadm_print(t_strdup_printf("%s (%c%02u%02u)", unixdate2str(t),
				      chr, tz/60, tz%60));
	return 0;
}

static int fetch_date_saved(struct fetch_cmd_context *ctx)
{
	time_t t;

	if (mail_get_save_date(ctx->mail, &t) < 0)
		return -1;
	doveadm_print(unixdate2str(t));
	return 0;
}

static int fetch_imap_envelope(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_IMAP_ENVELOPE, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}

static int fetch_imap_body(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_IMAP_BODY, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}

static int fetch_imap_bodystructure(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_IMAP_BODYSTRUCTURE, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}
static int fetch_pop3_uidl(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_UIDL_BACKEND, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}

static const struct fetch_field fetch_fields[] = {
	{ "user",          0,                        fetch_user },
	{ "mailbox",       0,                        fetch_mailbox },
	{ "mailbox-guid",  0,                        fetch_mailbox_guid },
	{ "seq",           0,                        fetch_seq },
	{ "uid",           0,                        fetch_uid },
	{ "guid",          0,                        fetch_guid },
	{ "flags",         MAIL_FETCH_FLAGS,         fetch_flags },
	{ "modseq",        0,                        fetch_modseq },
	{ "hdr",           MAIL_FETCH_STREAM_HEADER, fetch_hdr },
	{ "body",          MAIL_FETCH_STREAM_BODY,   fetch_body },
	{ "text",          MAIL_FETCH_STREAM_HEADER |
	                   MAIL_FETCH_STREAM_BODY,   fetch_text },
	{ "text.utf8",     MAIL_FETCH_STREAM_HEADER |
	                   MAIL_FETCH_STREAM_BODY,   fetch_text_utf8 },
	{ "size.physical", MAIL_FETCH_PHYSICAL_SIZE, fetch_size_physical },
	{ "size.virtual",  MAIL_FETCH_VIRTUAL_SIZE,  fetch_size_virtual },
	{ "date.received", MAIL_FETCH_RECEIVED_DATE, fetch_date_received },
	{ "date.sent",     MAIL_FETCH_DATE,          fetch_date_sent },
	{ "date.saved",    MAIL_FETCH_SAVE_DATE,     fetch_date_saved },
	{ "imap.envelope", MAIL_FETCH_IMAP_ENVELOPE, fetch_imap_envelope },
	{ "imap.body",     MAIL_FETCH_IMAP_BODY,     fetch_imap_body },
	{ "imap.bodystructure", MAIL_FETCH_IMAP_BODYSTRUCTURE, fetch_imap_bodystructure },
	{ "pop3.uidl",     MAIL_FETCH_UIDL_BACKEND,  fetch_pop3_uidl }
};

static const struct fetch_field *fetch_field_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(fetch_fields); i++) {
		if (strcmp(fetch_fields[i].name, name) == 0)
			return &fetch_fields[i];
	}
	return NULL;
}

static void print_fetch_fields(void)
{
	unsigned int i;

	fprintf(stderr, "Available fetch fields: %s", fetch_fields[0].name);
	for (i = 1; i < N_ELEMENTS(fetch_fields); i++)
		fprintf(stderr, " %s", fetch_fields[i].name);
	fprintf(stderr, "\n");
}

static void parse_fetch_fields(struct fetch_cmd_context *ctx, const char *str)
{
	const char *const *fields, *name;
	const struct fetch_field *field;
	struct fetch_field hdr_field;

	memset(&hdr_field, 0, sizeof(hdr_field));
	hdr_field.print = fetch_hdr_field;

	t_array_init(&ctx->fields, 32);
	t_array_init(&ctx->header_fields, 32);
	fields = t_strsplit_spaces(str, " ");
	for (; *fields != NULL; fields++) {
		name = t_str_lcase(*fields);

		doveadm_print_header_simple(name);
		if (strncmp(name, "hdr.", 4) == 0) {
			name += 4;
			hdr_field.name = name;
			array_append(&ctx->fields, &hdr_field, 1);
			name = t_strcut(name, '.');
			array_append(&ctx->header_fields, &name, 1);
		} else {
			field = fetch_field_find(name);
			if (field == NULL) {
				print_fetch_fields();
				i_fatal("Unknown fetch field: %s", name);
			}
			ctx->wanted_fields |= field->wanted_fields;
			array_append(&ctx->fields, field, 1);
		}
	}
	array_append_zero(&ctx->header_fields);
}

static int cmd_fetch_mail(struct fetch_cmd_context *ctx)
{
	const struct fetch_field *field;
	struct mail *mail = ctx->mail;
	int ret = 0;

	array_foreach(&ctx->fields, field) {
		ctx->cur_field = field;
		if (field->print(ctx) < 0) {
			i_error("fetch(%s) failed for box=%s uid=%u: %s",
				field->name, mailbox_get_vname(mail->box),
				mail->uid, mailbox_get_last_error(mail->box, NULL));
			doveadm_mail_failed_mailbox(&ctx->ctx, mail->box);
			ret = -1;
		}
	}
	return ret;
}

static int
cmd_fetch_box(struct fetch_cmd_context *ctx, const struct mailbox_info *info)
{
	struct doveadm_mail_iter *iter;
	int ret = 0;

	if (doveadm_mail_iter_init(&ctx->ctx, info, ctx->ctx.search_args,
				   ctx->wanted_fields,
				   array_idx(&ctx->header_fields, 0),
				   &iter) < 0)
		return -1;

	while (doveadm_mail_iter_next(iter, &ctx->mail)) {
		T_BEGIN {
			if (cmd_fetch_mail(ctx) < 0)
				ret = -1;
		} T_END;
	}
	if (doveadm_mail_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static int
cmd_fetch_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct fetch_cmd_context *ctx = (struct fetch_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = doveadm_mailbox_list_iter_init(_ctx, user, _ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_fetch_box(ctx, info) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_fetch_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct fetch_cmd_context *ctx = (struct fetch_cmd_context *)_ctx;

	o_stream_unref(&ctx->output);
}

static void cmd_fetch_init(struct doveadm_mail_cmd_context *_ctx,
			   const char *const args[])
{
	struct fetch_cmd_context *ctx = (struct fetch_cmd_context *)_ctx;
	const char *fetch_fields = args[0];

	if (fetch_fields == NULL || args[1] == NULL)
		doveadm_mail_help_name("fetch");

	parse_fetch_fields(ctx, fetch_fields);
	_ctx->search_args = doveadm_mail_build_search_args(args + 1);

	ctx->output = o_stream_create_fd(STDOUT_FILENO, 0, FALSE);
	o_stream_set_no_error_handling(ctx->output, TRUE);
}

static struct doveadm_mail_cmd_context *cmd_fetch_alloc(void)
{
	struct fetch_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct fetch_cmd_context);
	ctx->ctx.v.init = cmd_fetch_init;
	ctx->ctx.v.run = cmd_fetch_run;
	ctx->ctx.v.deinit = cmd_fetch_deinit;
	doveadm_print_init("pager");
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_fetch = {
	cmd_fetch_alloc, "fetch", "<fields> <search query>"
};
