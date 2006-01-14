/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "imap-expunge.h"

bool imap_expunge(struct mailbox *box, struct mail_search_arg *next_search_arg)
{
	struct mail_search_context *ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
	struct mail_search_arg search_arg;
        enum mailbox_sync_flags flags;
	bool failed = FALSE;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_DELETED;
	search_arg.next = next_search_arg;

	t = mailbox_transaction_begin(box, 0);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL);
	if (ctx == NULL)
		failed = TRUE;
	else {
		mail = mail_alloc(t, 0, NULL);
		while (mailbox_search_next(ctx, mail) > 0) {
			if (mail_expunge(mail) < 0) {
				failed = TRUE;
				break;
			}
		}
		mail_free(&mail);
	}

	if (mailbox_search_deinit(&ctx) < 0)
		return FALSE;

	if (failed)
		mailbox_transaction_rollback(&t);
	else {
		flags = MAILBOX_SYNC_FLAG_FULL_READ |
			MAILBOX_SYNC_FLAG_FULL_WRITE;
		if (mailbox_transaction_commit(&t, flags) < 0)
			failed = TRUE;
	}

	return !failed;
}
