/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "commands.h"
#include "imap-search.h"

static int fetch_and_copy(struct mailbox_transaction_context *t,
			  struct mailbox *srcbox,
			  struct mail_search_arg *search_args,
			  string_t *reply)
{
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans;
	struct mail *mail, *dest_mail;
        struct msgset_generator_context srcset_ctx, destset_ctx;
	string_t *dest_str;
	int ret;

	src_trans = mailbox_transaction_begin(srcbox, FALSE);
	search_ctx = mailbox_search_init(src_trans, NULL, search_args, NULL,
					 MAIL_FETCH_STREAM_HEADER |
					 MAIL_FETCH_STREAM_BODY, NULL);
	if (search_ctx == NULL) {
		mailbox_transaction_rollback(src_trans);
		return -1;
	}

	dest_str = t_str_new(128);
	msgset_generator_init(&srcset_ctx, reply);
	msgset_generator_init(&destset_ctx, dest_str);

	ret = 1;
	while ((mail = mailbox_search_next(search_ctx)) != NULL) {
		if (mail->expunged) {
			ret = 0;
			break;
		}
		if (mailbox_copy(t, mail, &dest_mail) < 0) {
			ret = -1;
			break;
		}

		msgset_generator_next(&srcset_ctx, mail->uid);
		msgset_generator_next(&destset_ctx, dest_mail->uid);

	}

	msgset_generator_finish(&srcset_ctx);
	msgset_generator_finish(&destset_ctx);

	if (str_len(dest_str) == 0)
		str_truncate(reply, 0);
	else {
		str_append_c(reply, ' ');
		str_append_str(reply, dest_str);
		str_append(reply, "] Copy completed.");
	}

	if (mailbox_search_deinit(search_ctx) < 0)
		ret = -1;

	if (mailbox_transaction_commit(src_trans) < 0)
		ret = -1;

	return ret;
}

int cmd_copy(struct client *client)
{
	struct mail_storage *storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
        struct mail_search_arg *search_arg;
	struct mailbox_status status;
	const char *messageset, *mailbox;
	string_t *reply;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(client, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	search_arg = imap_search_get_arg(client, messageset, client->cmd_uid);
	if (search_arg == NULL)
		return TRUE;

	storage = client_find_storage(client, mailbox);
	if (storage == NULL)
		return TRUE;

	if (mailbox_name_equals(mailbox_get_name(client->mailbox), mailbox))
		destbox = client->mailbox;
	else {
		destbox = mailbox_open(storage, mailbox, MAILBOX_OPEN_FAST |
				       MAILBOX_OPEN_KEEP_RECENT);
		if (destbox == NULL) {
			client_send_storage_error(client, storage);
			return TRUE;
		}
	}

	if (mailbox_get_status(destbox, STATUS_UIDVALIDITY, &status) < 0) {
		client_send_storage_error(client, storage);
		if (destbox != client->mailbox)
			mailbox_close(destbox);
		return TRUE;
	}

	reply = str_new(default_pool, 512);
	str_printfa(reply, "OK [COPYUID %u ", status.uidvalidity);

	t = mailbox_transaction_begin(destbox, FALSE);
	ret = fetch_and_copy(t, client->mailbox, search_arg, reply);

	if (ret <= 0)
		mailbox_transaction_rollback(t);
	else {
		if (mailbox_transaction_commit(t) < 0)
			ret = -1;
	}

	if (ret < 0)
		client_send_storage_error(client, storage);
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		client_sync_full(client);
		client_send_tagline(client,
			"NO Some of the requested messages no longer exist.");
	} else {
		if (destbox == client->mailbox)
			client_sync_full(client);
		else
			client_sync_full_fast(client);
		if (str_len(reply) > 0)
			client_send_tagline(client, str_c(reply));
		else {
			client_send_tagline(client,
				"OK Copy completed, no messages found.");
		}
	}

	if (destbox != client->mailbox)
		mailbox_close(destbox);
	return TRUE;
}
