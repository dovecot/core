/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail.h"

static int
cmd_altmove_box(struct mailbox *box, struct mail_search_args *search_args)
{
	struct mail_storage *storage;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	const char *box_name;
	int ret = 0;

	box_name = mailbox_get_vname(box);
	storage = mailbox_get_storage(box);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", box_name,
			mail_storage_get_last_error(storage, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, search_args, NULL);
	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		if (doveadm_debug)
			i_debug("altmove: box=%s uid=%u", box_name, mail->uid);
		mail_update_flags(mail, MODIFY_ADD,
				  MAIL_INDEX_MAIL_FLAG_BACKEND);
	}
	mail_free(&mail);
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_error("Searching mailbox %s failed: %s", box_name,
			mail_storage_get_last_error(storage, NULL));
		ret = -1;
	}
	if (mailbox_transaction_commit(&t) < 0) {
		i_error("Commiting mailbox %s failed: %s", box_name,
			mail_storage_get_last_error(storage, NULL));
		ret = -1;
	}
	return ret;
}

static void ns_purge(struct mail_namespace *ns)
{
	if (mail_storage_purge(ns->storage) < 0) {
		i_error("Purging namespace '%s' failed: %s", ns->prefix,
			mail_storage_get_last_error(ns->storage, NULL));
	}
}

void cmd_altmove(struct mail_user *user, const char *const args[])
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mail_search_args *search_args;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;
	struct mail_namespace *ns, *prev_ns = NULL;
	struct mailbox *box;
	ARRAY_DEFINE(purged_storages, struct mail_storage *);
	const char *storage_name;
	struct mail_storage *const *storages;
	unsigned int i, count;

	if (args[0] == NULL)
		doveadm_mail_help_name("altmove");
	search_args = doveadm_mail_build_search_args(args);

	t_array_init(&purged_storages, 8);
	iter = doveadm_mail_list_iter_init(user, search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) T_BEGIN {
		if (info->ns != prev_ns) {
			if (prev_ns != NULL) {
				ns_purge(prev_ns);
				array_append(&purged_storages,
					     &prev_ns->storage, 1);
			}
			prev_ns = info->ns;
		}

		storage_name = mail_namespace_get_storage_name(info->ns,
							       info->name);
		box = mailbox_alloc(info->ns->list, storage_name,
				    MAILBOX_FLAG_KEEP_RECENT |
				    MAILBOX_FLAG_IGNORE_ACLS);
		(void)cmd_altmove_box(box, search_args);
		mailbox_free(&box);
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
