/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "ostream.h"
#include "imap-resp-code.h"
#include "commands.h"
#include "imap-search-args.h"

#include <time.h>

#define COPY_CHECK_INTERVAL 100

static void client_send_sendalive_if_needed(struct client *client)
{
	time_t now, last_io;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	now = time(NULL);
	last_io = I_MAX(client->last_input, client->last_output);
	if (now - last_io > MAIL_STORAGE_STAYALIVE_SECS) {
		o_stream_send_str(client->output, "* OK Hang in there..\r\n");
		o_stream_flush(client->output);
		client->last_output = now;
	}
}

static int fetch_and_copy(struct client *client, struct mailbox *destbox,
			  struct mailbox_transaction_context *t,
			  struct mail_search_args *search_args,
			  const char **src_uidset_r,
			  unsigned int *copy_count_r)
{
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans;
	struct mail_keywords *keywords;
	const char *const *keywords_list;
	struct mail *mail;
	unsigned int copy_count = 0;
	struct msgset_generator_context srcset_ctx;
	string_t *src_uidset;
	int ret;

	src_uidset = t_str_new(256);
	msgset_generator_init(&srcset_ctx, src_uidset);

	src_trans = mailbox_transaction_begin(client->mailbox, 0);
	search_ctx = mailbox_search_init(src_trans, search_args, NULL);

	mail = mail_alloc(src_trans, MAIL_FETCH_STREAM_HEADER |
			  MAIL_FETCH_STREAM_BODY, NULL);
	ret = 1;
	while (mailbox_search_next(search_ctx, mail) > 0 && ret > 0) {
		if (mail->expunged) {
			ret = 0;
			break;
		}

		if ((++copy_count % COPY_CHECK_INTERVAL) == 0)
			client_send_sendalive_if_needed(client);

		keywords_list = mail_get_keywords(mail);
		keywords = str_array_length(keywords_list) == 0 ? NULL :
			mailbox_keywords_create_valid(destbox, keywords_list);
		if (mailbox_copy(t, mail, mail_get_flags(mail),
				 keywords, NULL) < 0)
			ret = mail->expunged ? 0 : -1;
		mailbox_keywords_free(destbox, &keywords);

		msgset_generator_next(&srcset_ctx, mail->uid);
	}
	mail_free(&mail);
	msgset_generator_finish(&srcset_ctx);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (mailbox_transaction_commit(&src_trans) < 0)
		ret = -1;

	*src_uidset_r = str_c(src_uidset);
	*copy_count_r = copy_count;
	return ret;
}

bool cmd_copy(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
        struct mail_search_args *search_args;
	const char *messageset, *mailbox, *src_uidset, *msg = NULL;
	enum mailbox_sync_flags sync_flags = 0;
	enum imap_sync_flags imap_flags = 0;
	unsigned int copy_count;
	uint32_t uid_validity, uid1, uid2;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(cmd, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(cmd, mailbox, TRUE, FALSE))
		return TRUE;

	ret = imap_search_get_seqset(cmd, messageset, cmd->uid, &search_args);
	if (ret <= 0)
		return ret < 0;

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	if (mailbox_equals(client->mailbox, storage, mailbox))
		destbox = client->mailbox;
	else {
		destbox = mailbox_open(&storage, mailbox, NULL,
				       MAILBOX_OPEN_SAVEONLY |
				       MAILBOX_OPEN_FAST |
				       MAILBOX_OPEN_KEEP_RECENT);
		if (destbox == NULL) {
			client_send_storage_error(cmd, storage);
			return TRUE;
		}
		if (client->enabled_features != 0)
			mailbox_enable(destbox, client->enabled_features);
	}

	t = mailbox_transaction_begin(destbox,
				      MAILBOX_TRANSACTION_FLAG_EXTERNAL |
				      MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS);
	ret = fetch_and_copy(client, destbox, t, search_args,
			     &src_uidset, &copy_count);
	mail_search_args_unref(&search_args);

	if (ret <= 0)
		mailbox_transaction_rollback(&t);
	else if (mailbox_transaction_commit_get_uids(&t, &uid_validity,
						     &uid1, &uid2) < 0)
		ret = -1;
	else if (copy_count == 0)
		msg = "OK No messages copied.";
	else {
		i_assert(copy_count == uid2 - uid1 + 1);

		if (uid1 == uid2) {
			msg = t_strdup_printf("OK [COPYUID %u %s %u] "
					      "Copy completed.",
					      uid_validity, src_uidset, uid1);
		} else {
			msg = t_strdup_printf("OK [COPYUID %u %s %u:%u] "
					      "Copy completed.",
					      uid_validity, src_uidset,
					      uid1, uid2);
		}
	}

	if (destbox != client->mailbox) {
		sync_flags |= MAILBOX_SYNC_FLAG_FAST;
		imap_flags |= IMAP_SYNC_FLAG_SAFE;
		mailbox_close(&destbox);
	}

	if (ret > 0)
		return cmd_sync(cmd, sync_flags, imap_flags, msg);
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		return cmd_sync(cmd, 0, 0,
			"NO ["IMAP_RESP_CODE_EXPUNGEISSUED"] "
			"Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}
}
