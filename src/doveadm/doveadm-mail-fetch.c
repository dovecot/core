/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "randgen.h"
#include "str.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "doveadm-mail.h"
#include "doveadm-mail-list-iter.h"

struct fetch_context {
	struct mail_search_args *search_args;
	struct ostream *output;

	string_t *prefix;
	unsigned int prefix_len;
};

static struct mail_search_args *build_search_args(const char *const args[])
{
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *error;

	parser = mail_search_parser_init_cmdline(args);
	if (mail_search_build(mail_search_register_human, parser, "UTF-8",
			      &sargs, &error) < 0)
		i_fatal("%s", error);
	mail_search_parser_deinit(&parser);
	return sargs;
}

static void
cmd_fetch_box(struct fetch_context *ctx, struct mailbox *box)
{
	struct mail_storage *storage = mailbox_get_storage(box);
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct istream *input;

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", mailbox_get_vname(box),
			mail_storage_get_last_error(storage, NULL));
		return;
	}

	mail_search_args_init(ctx->search_args, box, FALSE, NULL);
	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, ctx->search_args, NULL);
	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		if (mail_get_stream(mail, NULL, NULL, &input) < 0) {
			i_error("Couldn't open mail uid=%u: %s", mail->uid,
				mail_storage_get_last_error(storage, NULL));
			continue;
		}

		str_truncate(ctx->prefix, ctx->prefix_len);
		str_printfa(ctx->prefix, "seq=%u uid=%u\n",
			    mail->seq, mail->uid);
		if (o_stream_send(ctx->output, str_data(ctx->prefix),
				  str_len(ctx->prefix)) < 0)
			i_fatal("write(stdout) failed: %m");

		while (!i_stream_is_eof(input)) {
			if (o_stream_send_istream(ctx->output, input) <= 0)
				i_fatal("write(stdout) failed: %m");
		}
	}
	mail_free(&mail);
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_error("Search failed: %s",
			mail_storage_get_last_error(storage, NULL));
	}
	mail_search_args_deinit(ctx->search_args);
	(void)mailbox_transaction_commit(&t);
}

void cmd_fetch(struct mail_user *user, const char *const args[])
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct fetch_context ctx;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;
	struct mailbox *box;
	const char *storage_name;
	unsigned char prefix_buf[9];

	memset(&ctx, 0, sizeof(ctx));
	ctx.output = o_stream_create_fd(STDOUT_FILENO, 0, FALSE);

	random_fill_weak(prefix_buf, sizeof(prefix_buf));
	ctx.prefix = str_new(default_pool, 512);
	str_append(ctx.prefix, "===");
	base64_encode(prefix_buf, sizeof(prefix_buf), ctx.prefix);
	str_append_c(ctx.prefix, ' ');
	ctx.prefix_len = str_len(ctx.prefix);

	if (args[0] == NULL)
		doveadm_mail_help_name("fetch");
	ctx.search_args = build_search_args(args);

	iter = doveadm_mail_list_iter_init(user, ctx.search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) T_BEGIN {
		storage_name = mail_namespace_get_storage_name(info->ns,
							       info->name);
		box = mailbox_alloc(info->ns->list, storage_name,
				    MAILBOX_FLAG_KEEP_RECENT |
				    MAILBOX_FLAG_IGNORE_ACLS);
		(void)cmd_fetch_box(&ctx, box);
		mailbox_free(&box);
	} T_END;
	doveadm_mail_list_iter_deinit(&iter);
	o_stream_unref(&ctx.output);
	str_free(&ctx.prefix);
}
