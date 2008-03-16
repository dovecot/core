/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

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
	bool expunges = FALSE;

	if (mailbox_is_readonly(box)) {
		/* silently ignore */
		return 0;
	}

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_FLAGS;
	search_arg.value.flags = MAIL_DELETED;
	search_arg.next = next_search_arg;

	t = mailbox_transaction_begin(box, 0);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(ctx, mail) > 0) {
		mail_expunge(mail);
		expunges = TRUE;
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&ctx) < 0) {
		mailbox_transaction_rollback(&t);
		return -1;
	} else {
		if (mailbox_transaction_commit(&t) < 0)
			return -1;
	}

	return expunges ? 1 : 0;
}
