/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "imap-sync.h"

int imap_sync(struct client *client, struct mailbox *box,
	      enum mailbox_sync_flags flags)
{
        struct mailbox_transaction_context *t;
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;
	struct mailbox_status status;
	struct mail *mail;
        const struct mail_full_flags *mail_flags;
	string_t *str;
	uint32_t seq;

	if (client->mailbox != box) {
		/* mailbox isn't selected - we only wish to sync the mailbox
		   without sending anything to client */
		ctx = mailbox_sync_init(box, flags);
		while (mailbox_sync_next(ctx, &sync_rec) > 0)
			;
		return mailbox_sync_deinit(ctx, &status);
	}

	t_push();
	str = t_str_new(256);

	t = mailbox_transaction_begin(box, FALSE);
	ctx = mailbox_sync_init(box, flags);
	while (mailbox_sync_next(ctx, &sync_rec) > 0) {
		switch (sync_rec.type) {
		case MAILBOX_SYNC_TYPE_FLAGS:
			for (seq = sync_rec.seq1; seq <= sync_rec.seq2; seq++) {
				mail = mailbox_fetch(t, seq, MAIL_FETCH_FLAGS);

				mail_flags = mail->get_flags(mail);
				if (mail_flags == NULL)
					continue;

				str_truncate(str, 0);
				str_printfa(str, "* %u FETCH (FLAGS (", seq);
				imap_write_flags(str, mail_flags);
				str_append(str, "))");
				client_send_line(client, str_c(str));
			}
			break;
		case MAILBOX_SYNC_TYPE_EXPUNGE:
			for (seq = sync_rec.seq2; seq >= sync_rec.seq1; seq--) {
				str_truncate(str, 0);
				str_printfa(str, "* %u EXPUNGE", seq);
				client_send_line(client, str_c(str));
			}
			break;
		}
	}

	if (mailbox_sync_deinit(ctx, &status) < 0) {
		mailbox_transaction_rollback(t);
		t_pop();
		return -1;
	}

	mailbox_transaction_commit(t);

	if (status.messages != client->messages_count) {
                client->messages_count = status.messages;
		str_truncate(str, 0);
		str_printfa(str, "* %u EXISTS", status.messages);
		client_send_line(client, str_c(str));
	}
	if (status.recent != client->recent_count) {
                client->recent_count = status.recent;
		str_truncate(str, 0);
		str_printfa(str, "* %u RECENT", status.recent);
		client_send_line(client, str_c(str));
	}

	/*FIXME:client_save_keywords(&client->keywords, keywords, keywords_count);
	client_send_mailbox_flags(client, mailbox, keywords, keywords_count);*/

	t_pop();
	return 0;
}
