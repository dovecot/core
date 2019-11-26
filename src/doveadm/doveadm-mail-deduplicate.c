/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

struct uidlist {
	struct uidlist *next;
	uint32_t uid;
};

struct deduplicate_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	bool by_msgid;
};

static int cmd_deduplicate_uidlist(struct doveadm_mail_cmd_context *_ctx,
				   struct mailbox *box, struct uidlist *uidlist)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;
	struct mail *mail;
	ARRAY_TYPE(seq_range) uids;
	int ret = 0;

	/* the uidlist is reversed with oldest mails at the end.
	   we'll delete everything but the oldest mail. */
	if (uidlist->next == NULL)
		return 0;

	t_array_init(&uids, 8);
	for (; uidlist->next != NULL; uidlist = uidlist->next)
		seq_range_array_add(&uids, uidlist->uid);

	search_args = mail_search_build_init();
	arg = mail_search_build_add(search_args, SEARCH_UIDSET);
	arg->value.seqset = uids;

	trans = mailbox_transaction_begin(box, _ctx->transaction_flags, __func__);
	search_ctx = mailbox_search_init(trans, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail))
		mail_expunge(mail);
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_error("Searching mailbox '%s' failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		ret = -1;
	}
	if (mailbox_transaction_commit(&trans) < 0) {
		i_error("Committing mailbox '%s' transaction failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		ret = -1;
	}
	return ret;
}

static int
cmd_deduplicate_box(struct doveadm_mail_cmd_context *_ctx,
		    const struct mailbox_info *info,
		    struct mail_search_args *search_args)
{
	struct deduplicate_cmd_context *ctx =
		(struct deduplicate_cmd_context *)_ctx;
	struct doveadm_mail_iter *iter;
	struct mailbox *box;
	struct mail *mail;
	enum mail_error error;
	pool_t pool;
	HASH_TABLE(const char *, struct uidlist *) hash;
	const char *key, *errstr;
	struct uidlist *value;
	int ret = 0;

	if (doveadm_mail_iter_init(_ctx, info, search_args, 0, NULL, FALSE,
				   &iter) < 0)
		return -1;

	pool = pool_alloconly_create("deduplicate", 10240);
	hash_table_create(&hash, pool, 0, str_hash, strcmp);
	while (doveadm_mail_iter_next(iter, &mail)) {
		if (ctx->by_msgid) {
			if (mail_get_first_header(mail, "Message-ID", &key) < 0) {
				errstr = mailbox_get_last_internal_error(mail->box, &error);
				if (error == MAIL_ERROR_NOTFOUND)
					continue;
				i_error("Couldn't lookup Message-ID: for UID=%u: %s",
					mail->uid, errstr);
				doveadm_mail_failed_error(_ctx, error);
				ret = -1;
				break;
			}
		} else {
			if (mail_get_special(mail, MAIL_FETCH_GUID, &key) < 0) {
				errstr = mailbox_get_last_internal_error(mail->box, &error);
				if (error == MAIL_ERROR_NOTFOUND)
					continue;
				i_error("Couldn't lookup GUID: for UID=%u: %s",
					mail->uid, errstr);
				doveadm_mail_failed_error(_ctx, error);
				ret = -1;
				break;
			}
		}
		if (key != NULL && *key != '\0') {
			value = p_new(pool, struct uidlist, 1);
			value->uid = mail->uid;
			value->next = hash_table_lookup(hash, key);

			if (value->next == NULL) {
				key = p_strdup(pool, key);
				hash_table_insert(hash, key, value);
			} else {
				hash_table_update(hash, key, value);
			}
		}
	}

	if (doveadm_mail_iter_deinit_keep_box(&iter, &box) < 0)
		ret = -1;

	if (ret == 0) {
		struct hash_iterate_context *iter;

		iter = hash_table_iterate_init(hash);
		while (hash_table_iterate(iter, hash, &key, &value)) {
			T_BEGIN {
				if (cmd_deduplicate_uidlist(_ctx, box, value) < 0)
					ret = -1;
			} T_END;
		}
		hash_table_iterate_deinit(&iter);
	}

	hash_table_destroy(&hash);
	pool_unref(&pool);

	if (mailbox_sync(box, 0) < 0) {
		i_error("Syncing mailbox '%s' failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int
cmd_deduplicate_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = doveadm_mailbox_list_iter_init(ctx, user, ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_deduplicate_box(ctx, info, ctx->search_args) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_deduplicate_init(struct doveadm_mail_cmd_context *ctx,
				 const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("deduplicate");

	ctx->search_args = doveadm_mail_build_search_args(args);
}

static bool
cmd_deduplicate_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct deduplicate_cmd_context *ctx =
		(struct deduplicate_cmd_context *)_ctx;

	switch (c) {
	case 'm':
		ctx->by_msgid = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_deduplicate_alloc(void)
{
	struct deduplicate_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct deduplicate_cmd_context);
	ctx->ctx.getopt_args = "m";
	ctx->ctx.v.parse_arg = cmd_deduplicate_parse_arg;
	ctx->ctx.v.init = cmd_deduplicate_init;
	ctx->ctx.v.run = cmd_deduplicate_run;
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_deduplicate_ver2 = {
	.name = "deduplicate",
	.mail_cmd = cmd_deduplicate_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-m] <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('m', "by-msgid", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
