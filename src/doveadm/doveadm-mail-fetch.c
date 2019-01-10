/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

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
#include "imap-msgpart.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"

#include <stdio.h>

struct fetch_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	struct mail *mail;

	ARRAY(struct fetch_field) fields;
	ARRAY_TYPE(const_string) header_fields;
	enum mail_fetch_field wanted_fields;

	const struct fetch_field *cur_field;
	/* if print() returns -1, log this error if non-NULL. otherwise log
	   the storage error. */
	const char *print_error;
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

static void
fetch_set_istream_error(struct fetch_cmd_context *ctx, struct istream *input)
{
	ctx->print_error = t_strdup_printf("read(%s) failed: %s",
		i_stream_get_name(input), i_stream_get_error(input));
}

static int fetch_hdr(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	struct message_size hdr_size;
	int ret;

	if (mail_get_hdr_stream(ctx->mail, &hdr_size, &input) < 0)
		return -1;

	input = i_stream_create_limit(input, hdr_size.physical_size);
	if ((ret = doveadm_print_istream(input)) < 0)
		fetch_set_istream_error(ctx, input);
	i_stream_unref(&input);
	return ret;
}

static int fetch_hdr_field(struct fetch_cmd_context *ctx)
{
	const char *const *value, *filter, *name = ctx->cur_field->name;
	string_t *str = t_str_new(256);
	bool add_lf = FALSE;

	filter = strchr(name, '.');
	if (filter != NULL)
		name = t_strdup_until(name, filter++);

	if (filter != NULL && strcmp(filter, "utf8") == 0) {
		if (mail_get_headers_utf8(ctx->mail, name, &value) < 0)
			return -1;
	} else {
		if (mail_get_headers(ctx->mail, name, &value) < 0)
			return -1;
	}

	for (; *value != NULL; value++) {
		if (add_lf)
			str_append_c(str, '\n');
		str_append(str, *value);
		add_lf = TRUE;
	}

	if (filter == NULL || strcmp(filter, "utf8") == 0) {
		/* print the header as-is */
	} else if (strcmp(filter, "address") == 0 ||
		   strcmp(filter, "address_name") == 0 ||
		   strcmp(filter, "address_name.utf8") == 0) {
		struct message_address *addr;

		addr = message_address_parse(pool_datastack_create(),
					     str_data(str), str_len(str),
					     UINT_MAX, 0);
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
						strlen(addr->name), str, NULL);
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

static int fetch_body_field(struct fetch_cmd_context *ctx)
{
	const char *name = ctx->cur_field->name;
	struct imap_msgpart *msgpart;
	struct imap_msgpart_open_result result;
	bool binary;
	int ret;

	binary = str_begins(name, "binary.");
	name += binary ? 7 : 5;
	if (imap_msgpart_parse(name, &msgpart) < 0)
		i_unreached(); /* we already verified this was ok */
	if (binary)
		imap_msgpart_set_decode_to_binary(msgpart);

	if (imap_msgpart_open(ctx->mail, msgpart, &result) < 0) {
		imap_msgpart_free(&msgpart);
		return -1;
	}
	if ((ret = doveadm_print_istream(result.input)) < 0)
		fetch_set_istream_error(ctx, result.input);
	i_stream_unref(&result.input);
	imap_msgpart_free(&msgpart);
	return ret;
}

static int fetch_body(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	struct message_size hdr_size;
	int ret;

	if (mail_get_stream(ctx->mail, &hdr_size, NULL, &input) < 0)
		return -1;

	i_stream_skip(input, hdr_size.physical_size);
	if ((ret = doveadm_print_istream(input)) < 0)
		fetch_set_istream_error(ctx, input);
	return ret;
}

static int fetch_body_snippet(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_BODY_SNIPPET, &value) < 0)
		return -1;
	/* [0] contains the snippet algorithm, skip over it */
	i_assert(value[0] != '\0');
	doveadm_print(value + 1);
	return 0;
}

static int fetch_text(struct fetch_cmd_context *ctx)
{
	struct istream *input;
	int ret;

	if (mail_get_stream(ctx->mail, NULL, NULL, &input) < 0)
		return -1;
	if ((ret = doveadm_print_istream(input)) < 0)
		fetch_set_istream_error(ctx, input);
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
	message_parser_deinit(&parser, &parts);

	doveadm_print_stream("", 0);
	if (input->stream_errno != 0) {
		i_error("read(%s) failed: %s", i_stream_get_name(input),
			i_stream_get_error(input));
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

static int fetch_date_received_unixtime(struct fetch_cmd_context *ctx)
{
	time_t t;

	if (mail_get_received_date(ctx->mail, &t) < 0)
		return -1;
	doveadm_print(dec2str(t));
	return 0;
}

static int fetch_date_sent_unixtime(struct fetch_cmd_context *ctx)
{
	time_t t;
	int tz;

	if (mail_get_date(ctx->mail, &t, &tz) < 0)
		return -1;

	doveadm_print(dec2str(t));
	return 0;
}

static int fetch_date_saved_unixtime(struct fetch_cmd_context *ctx)
{
	time_t t;

	if (mail_get_save_date(ctx->mail, &t) < 0)
		return -1;
	doveadm_print(dec2str(t));
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

static int fetch_pop3_order(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_POP3_ORDER, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}

static int fetch_refcount(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_REFCOUNT, &value) < 0)
		return -1;
	doveadm_print(value);
	return 0;
}

static int fetch_storageid(struct fetch_cmd_context *ctx)
{
	const char *value;

	if (mail_get_special(ctx->mail, MAIL_FETCH_STORAGE_ID, &value) < 0)
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
	{ "body.snippet",  MAIL_FETCH_BODY_SNIPPET,  fetch_body_snippet },
	{ "text",          MAIL_FETCH_STREAM_HEADER |
	                   MAIL_FETCH_STREAM_BODY,   fetch_text },
	{ "text.utf8",     MAIL_FETCH_STREAM_HEADER |
	                   MAIL_FETCH_STREAM_BODY,   fetch_text_utf8 },
	{ "size.physical", MAIL_FETCH_PHYSICAL_SIZE, fetch_size_physical },
	{ "size.virtual",  MAIL_FETCH_VIRTUAL_SIZE,  fetch_size_virtual },
	{ "date.received", MAIL_FETCH_RECEIVED_DATE, fetch_date_received },
	{ "date.sent",     MAIL_FETCH_DATE,          fetch_date_sent },
	{ "date.saved",    MAIL_FETCH_SAVE_DATE,     fetch_date_saved },
	{ "date.received.unixtime", MAIL_FETCH_RECEIVED_DATE, fetch_date_received_unixtime },
	{ "date.sent.unixtime",     MAIL_FETCH_DATE,          fetch_date_sent_unixtime },
	{ "date.saved.unixtime",    MAIL_FETCH_SAVE_DATE,     fetch_date_saved_unixtime },
	{ "imap.envelope", MAIL_FETCH_IMAP_ENVELOPE, fetch_imap_envelope },
	{ "imap.body",     MAIL_FETCH_IMAP_BODY,     fetch_imap_body },
	{ "imap.bodystructure", MAIL_FETCH_IMAP_BODYSTRUCTURE, fetch_imap_bodystructure },
	{ "pop3.uidl",     MAIL_FETCH_UIDL_BACKEND,  fetch_pop3_uidl },
	{ "pop3.order",    MAIL_FETCH_POP3_ORDER,    fetch_pop3_order },
	{ "refcount",      MAIL_FETCH_REFCOUNT,      fetch_refcount },
	{ "storageid",     MAIL_FETCH_STORAGE_ID,    fetch_storageid }
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

	fprintf(stderr, "Available fetch fields: hdr.<name> body.<section> binary.<section> %s", fetch_fields[0].name);
	for (i = 1; i < N_ELEMENTS(fetch_fields); i++)
		fprintf(stderr, " %s", fetch_fields[i].name);
	fprintf(stderr, "\n");
}

static void parse_fetch_fields(struct fetch_cmd_context *ctx, const char *str)
{
	const char *const *fields, *name;
	const struct fetch_field *field;
	struct fetch_field hdr_field, body_field;
	struct imap_msgpart *msgpart;

	i_zero(&hdr_field);
	hdr_field.print = fetch_hdr_field;

	i_zero(&body_field);
	body_field.print = fetch_body_field;

	t_array_init(&ctx->fields, 32);
	t_array_init(&ctx->header_fields, 32);
	fields = t_strsplit_spaces(str, " ");
	for (; *fields != NULL; fields++) {
		name = t_str_lcase(*fields);

		doveadm_print_header_simple(name);
		if ((field = fetch_field_find(name)) != NULL) {
			ctx->wanted_fields |= field->wanted_fields;
			array_push_back(&ctx->fields, field);
		} else if (str_begins(name, "hdr.")) {
			name += 4;
			hdr_field.name = name;
			array_push_back(&ctx->fields, &hdr_field);
			name = t_strcut(name, '.');
			array_push_back(&ctx->header_fields, &name);
		} else if (str_begins(name, "body.") ||
			   str_begins(name, "binary.")) {
			bool binary = str_begins(name, "binary.");
			body_field.name = t_strarray_join(t_strsplit(name, ","), " ");

			name += binary ? 7 : 5;
			if (imap_msgpart_parse(name, &msgpart) < 0) {
				print_fetch_fields();
				i_fatal("Unknown fetch section: %s", name);
			}
			array_push_back(&ctx->fields, &body_field);
			ctx->wanted_fields |= imap_msgpart_get_fetch_data(msgpart);
			imap_msgpart_free(&msgpart);
		} else {
			print_fetch_fields();
			i_fatal("Unknown fetch field: %s", name);
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
				mail->uid,
				ctx->print_error != NULL ? ctx->print_error :
				mailbox_get_last_internal_error(mail->box, NULL));
			doveadm_mail_failed_mailbox(&ctx->ctx, mail->box);
			ctx->print_error = NULL;
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
				   array_first(&ctx->header_fields),
				   FALSE,
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

static void cmd_fetch_init(struct doveadm_mail_cmd_context *_ctx,
			   const char *const args[])
{
	struct fetch_cmd_context *ctx = (struct fetch_cmd_context *)_ctx;
	const char *fetch_fields = args[0];

	if (fetch_fields == NULL || args[1] == NULL)
		doveadm_mail_help_name("fetch");

	parse_fetch_fields(ctx, fetch_fields);
	_ctx->search_args = doveadm_mail_build_search_args(args + 1);
}

static struct doveadm_mail_cmd_context *cmd_fetch_alloc(void)
{
	struct fetch_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct fetch_cmd_context);
	ctx->ctx.v.init = cmd_fetch_init;
	ctx->ctx.v.run = cmd_fetch_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_PAGER);
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_fetch_ver2 = {
	.name = "fetch",
	.mail_cmd = cmd_fetch_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"<fields> <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "field", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('\0', "fieldstr", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL | CMD_PARAM_FLAG_DO_NOT_EXPOSE) /* FIXME: horrible hack, remove me when possible */
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
