/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "imap-expunge.h"

int imap_expunge(struct mailbox *box, struct mail_search_arg *next_search_arg)
{
	struct mail_search_context *ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
        struct mail_search_arg search_arg;
	int failed = FALSE;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_DELETED;
	search_arg.next = next_search_arg;

	t = mailbox_transaction_begin(box, FALSE);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL, 0, NULL);
	if (ctx == NULL)
		failed = TRUE;
	else {
		while ((mail = mailbox_search_next(ctx)) != NULL) {
			if (mail->expunge(mail) < 0) {
				failed = TRUE;
				break;
			}
		}
	}

	if (mailbox_search_deinit(ctx) < 0)
		return FALSE;

	if (failed)
		mailbox_transaction_rollback(t);
	else {
		if (mailbox_transaction_commit(t, MAILBOX_SYNC_FLAG_FULL) < 0)
			failed = TRUE;
	}

	return !failed;
}
