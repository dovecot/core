/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "doveadm-mail-iter.h"

struct doveadm_mail_iter {
	struct mail_search_args *search_args;

	struct mailbox *box;
	struct mail_storage *storage;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
};

int doveadm_mail_iter_init(const struct mailbox_info *info,
			   struct mail_search_args *search_args,
			   struct mailbox_transaction_context **trans_r,
			   struct doveadm_mail_iter **iter_r)
{
	struct doveadm_mail_iter *iter;
	const char *storage_name;

	storage_name = mail_namespace_get_storage_name(info->ns, info->name);

	iter = i_new(struct doveadm_mail_iter, 1);
	iter->box = mailbox_alloc(info->ns->list, storage_name,
				  MAILBOX_FLAG_KEEP_RECENT |
				  MAILBOX_FLAG_IGNORE_ACLS);
	iter->storage = mailbox_get_storage(iter->box);
	iter->search_args = search_args;

	if (mailbox_sync(iter->box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", info->name,
			mail_storage_get_last_error(iter->storage, NULL));
		mailbox_free(&iter->box);
		i_free(iter);
		return -1;
	}

	mail_search_args_init(search_args, iter->box, FALSE, NULL);
	iter->t = mailbox_transaction_begin(iter->box, 0);
	iter->search_ctx = mailbox_search_init(iter->t, search_args, NULL);

	*trans_r = iter->t;
	*iter_r = iter;
	return 0;
}

static int
doveadm_mail_iter_deinit_transaction(struct doveadm_mail_iter *iter,
				     bool commit)
{
	int ret = 0;

	if (mailbox_search_deinit(&iter->search_ctx) < 0) {
		i_error("Searching mailbox %s failed: %s",
			mailbox_get_vname(iter->box),
			mail_storage_get_last_error(iter->storage, NULL));
		ret = -1;
	}
	if (commit) {
		if (mailbox_transaction_commit(&iter->t) < 0) {
			i_error("Commiting mailbox %s failed: %s",
				mailbox_get_vname(iter->box),
				mail_storage_get_last_error(iter->storage, NULL));
			ret = -1;
		}
	} else {
		mailbox_transaction_rollback(&iter->t);
	}
	mail_search_args_deinit(iter->search_args);
	return ret;
}

static int
doveadm_mail_iter_deinit_full(struct doveadm_mail_iter **_iter,
			      bool sync, bool commit)
{
	struct doveadm_mail_iter *iter = *_iter;
	int ret;

	*_iter = NULL;

	ret = doveadm_mail_iter_deinit_transaction(iter, commit);
	if (ret == 0 && sync)
		ret = mailbox_sync(iter->box, 0);
	mailbox_free(&iter->box);
	i_free(iter);
	return ret;
}

int doveadm_mail_iter_deinit(struct doveadm_mail_iter **_iter)
{
	return doveadm_mail_iter_deinit_full(_iter, FALSE, TRUE);
}

int doveadm_mail_iter_deinit_sync(struct doveadm_mail_iter **_iter)
{
	return doveadm_mail_iter_deinit_full(_iter, TRUE, TRUE);
}

void doveadm_mail_iter_deinit_rollback(struct doveadm_mail_iter **_iter)
{
	(void)doveadm_mail_iter_deinit_full(_iter, FALSE, FALSE);
}

bool doveadm_mail_iter_next(struct doveadm_mail_iter *iter, struct mail *mail)
{
	return mailbox_search_next(iter->search_ctx, mail);
}
