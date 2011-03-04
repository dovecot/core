/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-resp-code.h"
#include "imap-util.h"
#include "imap-commands.h"
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

static int fetch_and_copy(struct client *client,
			  struct mailbox_transaction_context *t,
			  struct mail_search_args *search_args,
			  const char **src_uidset_r,
			  unsigned int *copy_count_r)
{
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	unsigned int copy_count = 0;
	struct msgset_generator_context srcset_ctx;
	string_t *src_uidset;
	int ret;

	src_uidset = t_str_new(256);
	msgset_generator_init(&srcset_ctx, src_uidset);

	src_trans = mailbox_transaction_begin(client->mailbox, 0);
	search_ctx = mailbox_search_init(src_trans, search_args, NULL);

	mail = mail_alloc(src_trans, 0, NULL);
	ret = 1;
	while (mailbox_search_next(search_ctx, mail) && ret > 0) {
		if (mail->expunged) {
			ret = 0;
			break;
		}

		if ((++copy_count % COPY_CHECK_INTERVAL) == 0)
			client_send_sendalive_if_needed(client);

		save_ctx = mailbox_save_alloc(t);
		mailbox_save_copy_flags(save_ctx, mail);

		if (mailbox_copy(&save_ctx, mail) < 0)
			ret = mail->expunged ? 0 : -1;

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
	struct mail_namespace *dest_ns;
	struct mail_storage *dest_storage;
	struct mailbox *destbox;
	struct mailbox_transaction_context *t;
        struct mail_search_args *search_args;
	const char *messageset, *mailbox, *storage_name, *src_uidset;
	enum mailbox_name_status status;
	enum mailbox_sync_flags sync_flags = 0;
	enum imap_sync_flags imap_flags = 0;
	struct mail_transaction_commit_changes changes;
	unsigned int copy_count;
	string_t *msg;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(cmd, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	ret = imap_search_get_seqset(cmd, messageset, cmd->uid, &search_args);
	if (ret <= 0)
		return ret < 0;

	/* open the destination mailbox */
	dest_ns = client_find_namespace(cmd, mailbox, &storage_name, &status);
	if (dest_ns == NULL)
		return TRUE;

	switch (status) {
	case MAILBOX_NAME_EXISTS_MAILBOX:
		break;
	case MAILBOX_NAME_EXISTS_DIR:
		status = MAILBOX_NAME_VALID;
		/* fall through */
	case MAILBOX_NAME_VALID:
	case MAILBOX_NAME_INVALID:
	case MAILBOX_NAME_NOINFERIORS:
		client_fail_mailbox_name_status(cmd, mailbox,
						"TRYCREATE", status);
		return TRUE;
	}

	if (mailbox_equals(client->mailbox, dest_ns, storage_name))
		destbox = client->mailbox;
	else {
		destbox = mailbox_alloc(dest_ns->list, storage_name,
					MAILBOX_FLAG_SAVEONLY |
					MAILBOX_FLAG_KEEP_RECENT);
		if (mailbox_open(destbox) < 0) {
			client_send_storage_error(cmd,
				mailbox_get_storage(destbox));
			mailbox_free(&destbox);
			return TRUE;
		}
		if (client->enabled_features != 0)
			mailbox_enable(destbox, client->enabled_features);
	}

	t = mailbox_transaction_begin(destbox,
				      MAILBOX_TRANSACTION_FLAG_EXTERNAL |
				      MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS);
	ret = fetch_and_copy(client, t, search_args, &src_uidset, &copy_count);
	mail_search_args_unref(&search_args);

	msg = t_str_new(256);
	if (ret <= 0)
		mailbox_transaction_rollback(&t);
	else if (mailbox_transaction_commit_get_changes(&t, &changes) < 0)
		ret = -1;
	else if (copy_count == 0) {
		str_append(msg, "OK No messages copied.");
		pool_unref(&changes.pool);
	} else if (seq_range_count(&changes.saved_uids) == 0) {
		/* not supported by backend (virtual) */
		str_append(msg, "OK Copy completed.");
		pool_unref(&changes.pool);
	} else {
		i_assert(copy_count == seq_range_count(&changes.saved_uids));

		str_printfa(msg, "OK [COPYUID %u %s ", changes.uid_validity,
			    src_uidset);
		imap_write_seq_range(msg, &changes.saved_uids);
		str_append(msg, "] Copy completed.");
		pool_unref(&changes.pool);
	}

	dest_storage = mailbox_get_storage(destbox);
	if (destbox != client->mailbox) {
		sync_flags |= MAILBOX_SYNC_FLAG_FAST;
		imap_flags |= IMAP_SYNC_FLAG_SAFE;
		mailbox_free(&destbox);
	}

	if (ret > 0)
		return cmd_sync(cmd, sync_flags, imap_flags, str_c(msg));
	else if (ret == 0) {
		/* some messages were expunged, sync them */
		return cmd_sync(cmd, 0, 0,
			"NO ["IMAP_RESP_CODE_EXPUNGEISSUED"] "
			"Some of the requested messages no longer exist.");
	} else {
		client_send_storage_error(cmd, dest_storage);
		return TRUE;
	}
}
