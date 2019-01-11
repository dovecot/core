/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

struct altmove_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	bool reverse;
};

static int
cmd_altmove_box(struct doveadm_mail_cmd_context *ctx,
		const struct mailbox_info *info,
		struct mail_search_args *search_args, bool reverse)
{
	struct doveadm_mail_iter *iter;
	struct mail *mail;
	enum modify_type modify_type =
		!reverse ? MODIFY_ADD : MODIFY_REMOVE;

	if (doveadm_mail_iter_init(ctx, info, search_args, 0, NULL, FALSE,
				   &iter) < 0)
		return -1;

	while (doveadm_mail_iter_next(iter, &mail)) {
		if (doveadm_debug) {
			i_debug("altmove: box=%s uid=%u",
				info->vname, mail->uid);
		}
		mail_update_flags(mail, modify_type,
			(enum mail_flags)MAIL_INDEX_MAIL_FLAG_BACKEND);
	}
	return doveadm_mail_iter_deinit_sync(&iter);
}

static int
ns_purge(struct doveadm_mail_cmd_context *ctx, struct mail_namespace *ns,
	 struct mail_storage *storage)
{
	if (mail_storage_purge(storage) < 0) {
		i_error("Purging namespace '%s' failed: %s", ns->prefix,
			mail_storage_get_last_internal_error(storage, NULL));
		doveadm_mail_failed_storage(ctx, storage);
		return -1;
	}
	return 0;
}

static int
cmd_altmove_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct altmove_cmd_context *ctx = (struct altmove_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	struct mail_namespace *ns, *prev_ns = NULL;
	ARRAY(struct mail_storage *) purged_storages;
	struct mail_storage *const *storages, *ns_storage, *prev_storage = NULL;
	unsigned int i, count;
	int ret = 0;

	t_array_init(&purged_storages, 8);
	iter = doveadm_mailbox_list_iter_init(_ctx, user, _ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		ns_storage = mail_namespace_get_default_storage(info->ns);
		if (ns_storage != prev_storage) {
			if (prev_storage != NULL) {
				if (ns_purge(_ctx, prev_ns, prev_storage) < 0)
					ret = -1;
				array_push_back(&purged_storages,
						&prev_storage);
			}
			prev_storage = ns_storage;
			prev_ns = info->ns;
		}
		if (cmd_altmove_box(_ctx, info, _ctx->search_args, ctx->reverse) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;

	if (prev_storage != NULL) {
		if (ns_purge(_ctx, prev_ns, prev_storage) < 0)
			ret = -1;
		array_push_back(&purged_storages, &prev_storage);
	}

	/* make sure all private storages have been purged */
	storages = array_get(&purged_storages, &count);
	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != MAIL_NAMESPACE_TYPE_PRIVATE)
			continue;

		ns_storage = mail_namespace_get_default_storage(ns);
		for (i = 0; i < count; i++) {
			if (ns_storage == storages[i])
				break;
		}
		if (i == count) {
			if (ns_purge(_ctx, ns, ns_storage) < 0)
				ret = -1;
			array_push_back(&purged_storages, &ns_storage);
			storages = array_get(&purged_storages, &count);
		}
	}
	return ret;
}

static void cmd_altmove_init(struct doveadm_mail_cmd_context *ctx,
			     const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("altmove");
	ctx->search_args = doveadm_mail_build_search_args(args);
}

static bool
cmd_mailbox_altmove_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct altmove_cmd_context *ctx = (struct altmove_cmd_context *)_ctx;

	switch (c) {
	case 'r':
		ctx->reverse = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_altmove_alloc(void)
{
	struct altmove_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct altmove_cmd_context);
	ctx->ctx.getopt_args = "r";
	ctx->ctx.v.parse_arg = cmd_mailbox_altmove_parse_arg;
	ctx->ctx.v.init = cmd_altmove_init;
	ctx->ctx.v.run = cmd_altmove_run;
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_altmove_ver2 = {
	.name = "altmove",
	.mail_cmd = cmd_altmove_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-r] <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('r', "reverse", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
