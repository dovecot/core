/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mail-storage.h"
#include "mail-copy.h"

int mail_storage_copy(struct mailbox_transaction_context *t, struct mail *mail,
		      struct mail **dest_mail_r)
{
	struct mail_save_context *ctx;
	struct istream *input;
	const char *from_envelope;

	input = mail->get_stream(mail, NULL, NULL);
	if (input == NULL)
		return -1;

	from_envelope = mail->get_special(mail, MAIL_FETCH_FROM_ENVELOPE);

	ctx = mailbox_save_init(t, mail->get_flags(mail),
				mail->get_received_date(mail),
				0, from_envelope, input, dest_mail_r != NULL);
	while (i_stream_read(input) != -1) {
		if (mailbox_save_continue(ctx) < 0)
			break;
	}

	if (input->stream_errno != 0) {
		mailbox_save_cancel(ctx);
		return -1;
	}

	return mailbox_save_finish(ctx, dest_mail_r);
}
