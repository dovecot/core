/* Copyright (c) 2004-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "mail-storage-private.h"
#include "mail-copy.h"

int mail_storage_copy(struct mailbox_transaction_context *t, struct mail *mail,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      struct mail *dest_mail)
{
	struct mail_save_context *ctx;
	struct istream *input;
	const char *from_envelope, *guid;
	time_t received_date;

	if (mail_get_stream(mail, NULL, NULL, &input) < 0)
		return -1;
	if (mail_get_received_date(mail, &received_date) < 0)
		return -1;
	if (mail_get_special(mail, MAIL_FETCH_FROM_ENVELOPE,
			     &from_envelope) < 0)
		return -1;
	if (mail_get_special(mail, MAIL_FETCH_GUID, &guid) < 0)
		return -1;

	ctx = mailbox_save_alloc(t);
	mailbox_save_set_flags(ctx, flags, keywords);
	mailbox_save_set_received_date(ctx, received_date, 0);
	if (*from_envelope != '\0')
		mailbox_save_set_from_envelope(ctx, from_envelope);
	if (*guid != '\0')
		mailbox_save_set_guid(ctx, guid);
	mailbox_save_set_dest_mail(ctx, dest_mail);

	if (mailbox_save_begin(&ctx, input) < 0)
		return -1;

	do {
		if (mailbox_save_continue(ctx) < 0)
			break;
	} while (i_stream_read(input) != -1);

	if (input->stream_errno != 0) {
		mail_storage_set_critical(t->box->storage,
					  "copy: i_stream_read() failed: %m");
		mailbox_save_cancel(&ctx);
		return -1;
	}

	return mailbox_save_finish(&ctx);
}
