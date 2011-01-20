/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "doveadm-mail-iter.h"

struct doveadm_mail_iter {
	struct mail_search_args *search_args;

	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
};

int doveadm_mail_iter_init(const struct mailbox_info *info,
			   struct mail_search_args *search_args,
			   struct mailbox_transaction_context **trans_r,
			   struct doveadm_mail_iter **iter_r)
{
	struct doveadm_mail_iter *iter;

	iter = i_new(struct doveadm_mail_iter, 1);
	iter->box = mailbox_alloc(info->ns->list, info->name,
				  MAILBOX_FLAG_KEEP_RECENT |
				  MAILBOX_FLAG_IGNORE_ACLS);
	iter->search_args = search_args;

	if (mailbox_sync(iter->box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", info->name,
			mailbox_get_last_error(iter->box, NULL));
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
doveadm_mail_iter_deinit_transaction(struct doveadm_mail_iter *iter)
{
	int ret = 0;

	if (mailbox_search_deinit(&iter->search_ctx) < 0) {
		i_error("Searching mailbox %s failed: %s",
			mailbox_get_vname(iter->box),
			mailbox_get_last_error(iter->box, NULL));
		ret = -1;
	}
	if (mailbox_transaction_commit(&iter->t) < 0) {
		i_error("Commiting mailbox %s failed: %s",
			mailbox_get_vname(iter->box),
			mailbox_get_last_error(iter->box, NULL));
		ret = -1;
	}
	mail_search_args_deinit(iter->search_args);
	return ret;
}

static int
doveadm_mail_iter_deinit_full(struct doveadm_mail_iter **_iter, bool sync)
{
	struct doveadm_mail_iter *iter = *_iter;
	int ret;

	*_iter = NULL;

	ret = doveadm_mail_iter_deinit_transaction(iter);
	if (ret == 0 && sync)
		ret = mailbox_sync(iter->box, 0);
	mailbox_free(&iter->box);
	i_free(iter);
	return ret;
}

int doveadm_mail_iter_deinit(struct doveadm_mail_iter **_iter)
{
	return doveadm_mail_iter_deinit_full(_iter, FALSE);
}

int doveadm_mail_iter_deinit_sync(struct doveadm_mail_iter **_iter)
{
	return doveadm_mail_iter_deinit_full(_iter, TRUE);
}

bool doveadm_mail_iter_next(struct doveadm_mail_iter *iter, struct mail *mail)
{
	return mailbox_search_next(iter->search_ctx, mail);
}
