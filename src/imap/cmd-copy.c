/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "commands.h"
#include "imap-search.h"

static int fetch_and_copy(struct mailbox_transaction_context *t,
			  struct mailbox *srcbox,
			  struct mail_search_arg *search_args)
{
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans;
	struct mail *mail;
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

	ret = 1;
	while ((mail = mailbox_search_next(search_ctx)) != NULL) {
		if (mail->expunged) {
			ret = 0;
			break;
		}
		if (mailbox_copy(t, mail, NULL) < 0) {
			ret = -1;
			break;
		}

	}

	if (mailbox_search_deinit(search_ctx) < 0)
		ret = -1;

	if (mailbox_transaction_commit(src_trans, 0) < 0)
		ret = -1;

	return ret;
}

int cmd_copy(struct client *client)
{
	struct mail_storage *storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
        struct mail_search_arg *search_arg;
	const char *messageset, *mailbox;
        enum mailbox_sync_flags sync_flags = 0;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(client, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	search_arg = imap_search_get_arg(client, messageset, client->cmd_uid);
	if (search_arg == NULL)
		return TRUE;

	storage = client_find_storage(client, &mailbox);
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

	t = mailbox_transaction_begin(destbox, FALSE);
	ret = fetch_and_copy(t, client->mailbox, search_arg);

	if (ret <= 0)
		mailbox_transaction_rollback(t);
	else {
		if (mailbox_transaction_commit(t, 0) < 0)
			ret = -1;
	}

	if (destbox != client->mailbox) {
		sync_flags |= MAILBOX_SYNC_FLAG_FAST;
		mailbox_close(destbox);
	}

	if (ret > 0)
		return cmd_sync(client, sync_flags, "OK Copy completed.");
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		return cmd_sync(client, 0,
			"NO Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(client, storage);
		return TRUE;
	}
}
