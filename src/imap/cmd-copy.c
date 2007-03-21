/* Copyright (C) 2002-2007 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "ostream.h"
#include "commands.h"
#include "imap-search.h"

#include <time.h>

#define COPY_CHECK_INTERVAL 100

static void client_send_sendalive_if_needed(struct client *client)
{
	time_t now;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	now = time(NULL);
	if (now - client->last_output > MAIL_STORAGE_STAYALIVE_SECS) {
		o_stream_send_str(client->output, "* OK Hang in there..\r\n");
		o_stream_flush(client->output);
		client->last_output = now;
	}
}

static int fetch_and_copy(struct client *client,
			  struct mailbox_transaction_context *t,
			  struct mail_search_arg *search_args)
{
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans;
	struct mail_keywords *keywords;
	const char *const *keywords_list;
	struct mail *mail;
	unsigned int copy_count = 0;
	int ret;

	src_trans = mailbox_transaction_begin(client->mailbox, 0);
	search_ctx = mailbox_search_init(src_trans, NULL, search_args, NULL);

	mail = mail_alloc(src_trans, MAIL_FETCH_STREAM_HEADER |
			  MAIL_FETCH_STREAM_BODY, NULL);
	ret = 1;
	while (mailbox_search_next(search_ctx, mail) > 0 && ret > 0) {
		if (mail->expunged) {
			ret = 0;
			break;
		}

		if ((++copy_count % COPY_CHECK_INTERVAL) != 0)
			client_send_sendalive_if_needed(client);

		keywords_list = mail_get_keywords(mail);
		keywords = strarray_length(keywords_list) == 0 ? NULL :
			mailbox_keywords_create(t, keywords_list);
		if (mailbox_copy(t, mail, mail_get_flags(mail),
				 keywords, NULL) < 0)
			ret = mail->expunged ? 0 : -1;
		mailbox_keywords_free(t, &keywords);
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (mailbox_transaction_commit(&src_trans, 0) < 0)
		ret = -1;

	return ret;
}

bool cmd_copy(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
        struct mail_search_arg *search_arg;
	const char *messageset, *mailbox;
        enum mailbox_sync_flags sync_flags = 0;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(cmd, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(cmd, mailbox, TRUE, FALSE))
		return TRUE;

	search_arg = imap_search_get_arg(cmd, messageset, cmd->uid);
	if (search_arg == NULL)
		return TRUE;

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	if (mailbox_equals(client->mailbox, storage, mailbox))
		destbox = client->mailbox;
	else {
		destbox = mailbox_open(storage, mailbox, NULL,
				       MAILBOX_OPEN_SAVEONLY |
				       MAILBOX_OPEN_FAST |
				       MAILBOX_OPEN_KEEP_RECENT);
		if (destbox == NULL) {
			client_send_storage_error(cmd, storage);
			return TRUE;
		}
	}

	t = mailbox_transaction_begin(destbox,
				      MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	ret = fetch_and_copy(client, t, search_arg);

	if (ret <= 0)
		mailbox_transaction_rollback(&t);
	else {
		if (mailbox_transaction_commit(&t, 0) < 0)
			ret = -1;
	}

	if (destbox != client->mailbox) {
		sync_flags |= MAILBOX_SYNC_FLAG_FAST;
		mailbox_close(&destbox);
	}

	if (ret > 0)
		return cmd_sync(cmd, sync_flags, 0, "OK Copy completed.");
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		return cmd_sync(cmd, 0, 0,
			"NO Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}
}
