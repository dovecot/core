/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "doveadm-mail.h"
#include "doveadm-mail-iter.h"

struct doveadm_mail_iter {
	struct doveadm_mail_cmd_context *ctx;
	struct mail_search_args *search_args;

	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
};

int doveadm_mail_iter_init(struct doveadm_mail_cmd_context *ctx,
			   const struct mailbox_info *info,
			   struct mail_search_args *search_args,
			   enum mail_fetch_field wanted_fields,
			   const char *const *wanted_headers,
			   struct doveadm_mail_iter **iter_r)
{
	struct doveadm_mail_iter *iter;
	struct mailbox_header_lookup_ctx *headers_ctx;
	const char *errstr;
	enum mail_error error;

	iter = i_new(struct doveadm_mail_iter, 1);
	iter->ctx = ctx;
	iter->box = mailbox_alloc(info->ns->list, info->vname,
				  MAILBOX_FLAG_IGNORE_ACLS);
	iter->search_args = search_args;

	if (mailbox_sync(iter->box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		errstr = mailbox_get_last_error(iter->box, &error);
		if (error == MAIL_ERROR_NOTFOUND) {
			/* just ignore this mailbox */
			*iter_r = iter;
			return 0;
		}
		i_error("Syncing mailbox %s failed: %s", info->vname, errstr);
		doveadm_mail_failed_mailbox(ctx, iter->box);
		mailbox_free(&iter->box);
		i_free(iter);
		return -1;
	}

	headers_ctx = wanted_headers == NULL || wanted_headers[0] == NULL ?
		NULL : mailbox_header_lookup_init(iter->box, wanted_headers);

	mail_search_args_init(search_args, iter->box, FALSE, NULL);
	iter->t = mailbox_transaction_begin(iter->box, 0);
	iter->search_ctx = mailbox_search_init(iter->t, search_args, NULL,
					       wanted_fields, headers_ctx);
	*iter_r = iter;
	return 0;
}

static int
doveadm_mail_iter_deinit_transaction(struct doveadm_mail_iter *iter,
				     bool commit)
{
	int ret = 0;

	if (iter->search_ctx != NULL) {
		if (mailbox_search_deinit(&iter->search_ctx) < 0) {
			i_error("Searching mailbox %s failed: %s",
				mailbox_get_vname(iter->box),
				mailbox_get_last_error(iter->box, NULL));
			ret = -1;
		}
	}
	if (iter->t == NULL)
		;
	else if (commit) {
		if (mailbox_transaction_commit(&iter->t) < 0) {
			i_error("Committing mailbox %s failed: %s",
				mailbox_get_vname(iter->box),
				mailbox_get_last_error(iter->box, NULL));
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
			      bool sync, bool commit, bool keep_box)
{
	struct doveadm_mail_iter *iter = *_iter;
	int ret;

	*_iter = NULL;

	ret = doveadm_mail_iter_deinit_transaction(iter, commit);
	if (ret == 0 && sync)
		ret = mailbox_sync(iter->box, 0);
	if (ret < 0)
		doveadm_mail_failed_mailbox(iter->ctx, iter->box);
	if (!keep_box)
		mailbox_free(&iter->box);
	i_free(iter);
	return ret;
}

int doveadm_mail_iter_deinit(struct doveadm_mail_iter **_iter)
{
	return doveadm_mail_iter_deinit_full(_iter, FALSE, TRUE, FALSE);
}

int doveadm_mail_iter_deinit_sync(struct doveadm_mail_iter **_iter)
{
	return doveadm_mail_iter_deinit_full(_iter, TRUE, TRUE, FALSE);
}

int doveadm_mail_iter_deinit_keep_box(struct doveadm_mail_iter **iter,
				      struct mailbox **box_r)
{
	*box_r = (*iter)->box;
	return doveadm_mail_iter_deinit_full(iter, FALSE, TRUE, TRUE);
}

void doveadm_mail_iter_deinit_rollback(struct doveadm_mail_iter **_iter)
{
	(void)doveadm_mail_iter_deinit_full(_iter, FALSE, FALSE, FALSE);
}

bool doveadm_mail_iter_next(struct doveadm_mail_iter *iter,
			    struct mail **mail_r)
{
	if (iter->search_ctx == NULL)
		return FALSE;
	return mailbox_search_next(iter->search_ctx, mail_r);
}

struct mailbox *doveadm_mail_iter_get_mailbox(struct doveadm_mail_iter *iter)
{
	return iter->box;
}
