/* Copyright (C) 2004 Timo Sirainen */

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
	const char *from_envelope;

	input = mail_get_stream(mail, NULL, NULL);
	if (input == NULL)
		return -1;

	from_envelope = mail_get_special(mail, MAIL_FETCH_FROM_ENVELOPE);

	if (mailbox_save_init(t, flags, keywords,
			      mail_get_received_date(mail),
			      0, from_envelope, input, dest_mail, &ctx) < 0)
		return -1;

	while (i_stream_read(input) != -1) {
		if (mailbox_save_continue(ctx) < 0)
			break;
	}

	if (input->stream_errno != 0) {
		mail_storage_set_critical(t->box->storage,
					  "copy: i_stream_read() failed: %m");
		mailbox_save_cancel(&ctx);
		return -1;
	}

	return mailbox_save_finish(&ctx);
}
