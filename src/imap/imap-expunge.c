/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "mail-storage.h"
#include "imap-expunge.h"

int imap_expunge(struct mailbox *box, int notify)
{
	struct mail_expunge_context *ctx;
	struct mail *mail;
	int failed = FALSE;

	ctx = box->expunge_init(box, 0, FALSE);
	if (ctx == NULL)
		return FALSE;

	while ((mail = box->expunge_fetch_next(ctx)) != NULL) {
		if (!mail->expunge(mail, ctx, NULL, notify)) {
			failed = TRUE;
			break;
		}
	}

	if (!box->expunge_deinit(ctx))
		return FALSE;

	return !failed;
}

