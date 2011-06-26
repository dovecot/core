/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mail.h"

static int
cmd_index_box(const struct mailbox_info *info)
{
	struct mailbox *box;
	const char *storage_name;
	int ret = 0;

	storage_name = mail_namespace_get_storage_name(info->ns, info->name);
	box = mailbox_alloc(info->ns->list, storage_name,
			    MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_IGNORE_ACLS);

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ |
			 MAILBOX_SYNC_FLAG_PRECACHE) < 0) {
		i_error("Syncing mailbox %s failed: %s", info->name,
			mail_storage_get_last_error(mailbox_get_storage(box), NULL));
		ret = -1;
	}

	mailbox_free(&box);
	return ret;
}

static void
cmd_index_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
		MAILBOX_LIST_ITER_STAR_WITHIN_NS;
	const enum namespace_type ns_mask =
		NAMESPACE_PRIVATE | NAMESPACE_SHARED | NAMESPACE_PUBLIC;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;

	iter = mailbox_list_iter_init_namespaces(user->namespaces, ctx->args,
						 ns_mask, iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) == 0) T_BEGIN {
			(void)cmd_index_box(info);
		} T_END;
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		i_error("Listing mailboxes failed");
}

static void cmd_index_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			   const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("index");
}

static struct doveadm_mail_cmd_context *cmd_index_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.init = cmd_index_init;
	ctx->v.run = cmd_index_run;
	return ctx;
}

struct doveadm_mail_cmd cmd_index = {
	cmd_index_alloc, "index", "<mailbox>"
};
