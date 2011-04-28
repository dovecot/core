/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

static int
cmd_altmove_box(const struct mailbox_info *info,
		struct mail_search_args *search_args)
{
	struct doveadm_mail_iter *iter;
	struct mailbox_transaction_context *trans;
	struct mail *mail;

	if (doveadm_mail_iter_init(info, search_args, &trans, &iter) < 0)
		return -1;

	mail = mail_alloc(trans, 0, NULL);
	while (doveadm_mail_iter_next(iter, mail)) {
		if (doveadm_debug) {
			i_debug("altmove: box=%s uid=%u",
				info->name, mail->uid);
		}
		mail_update_flags(mail, MODIFY_ADD,
			(enum mail_flags)MAIL_INDEX_MAIL_FLAG_BACKEND);
	}
	mail_free(&mail);
	return doveadm_mail_iter_deinit_sync(&iter);
}

static void ns_purge(struct mail_namespace *ns)
{
	if (mail_storage_purge(ns->storage) < 0) {
		i_error("Purging namespace '%s' failed: %s", ns->prefix,
			mail_storage_get_last_error(ns->storage, NULL));
	}
}

static void
cmd_altmove_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;
	struct mail_namespace *ns, *prev_ns = NULL;
	ARRAY_DEFINE(purged_storages, struct mail_storage *);
	struct mail_storage *const *storages;
	unsigned int i, count;

	t_array_init(&purged_storages, 8);
	iter = doveadm_mail_list_iter_init(user, ctx->search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) T_BEGIN {
		if (info->ns != prev_ns) {
			if (prev_ns != NULL) {
				ns_purge(prev_ns);
				array_append(&purged_storages,
					     &prev_ns->storage, 1);
			}
			prev_ns = info->ns;
		}
		(void)cmd_altmove_box(info, ctx->search_args);
	} T_END;
	doveadm_mail_list_iter_deinit(&iter);

	/* make sure all private storages have been purged */
	storages = array_get(&purged_storages, &count);
	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != NAMESPACE_PRIVATE)
			continue;

		for (i = 0; i < count; i++) {
			if (ns->storage == storages[i])
				break;
		}
		if (i == count) {
			ns_purge(ns);
			array_append(&purged_storages, &ns->storage, 1);
		}
	}
}

static void cmd_altmove_init(struct doveadm_mail_cmd_context *ctx,
			     const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("altmove");
	ctx->search_args = doveadm_mail_build_search_args(args);
}

static struct doveadm_mail_cmd_context *cmd_altmove_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.init = cmd_altmove_init;
	ctx->v.run = cmd_altmove_run;
	return ctx;
}

struct doveadm_mail_cmd cmd_altmove = {
	cmd_altmove_alloc, "altmove", "<search query>"
};
