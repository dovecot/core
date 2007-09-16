/* Copyright (c) 2003-2007 Dovecot authors, see the included COPYING file */

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
	bool failed;

	if (mailbox_is_readonly(box)) {
		/* silently ignore */
		return TRUE;
	}

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_DELETED;
	search_arg.next = next_search_arg;

	t = mailbox_transaction_begin(box, 0);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(ctx, mail) > 0)
		mail_expunge(mail);
	mail_free(&mail);

	if (mailbox_search_deinit(&ctx) < 0) {
		failed = TRUE;
		mailbox_transaction_rollback(&t);
	} else {
		flags = MAILBOX_SYNC_FLAG_FULL_READ |
			MAILBOX_SYNC_FLAG_FULL_WRITE;
		failed = mailbox_transaction_commit(&t, flags) < 0;
	}

	return !failed;
}
