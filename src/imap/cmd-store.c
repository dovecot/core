/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-util.h"

static int get_modify_type(struct client *client, const char *item,
			   enum modify_type *modify_type, int *silent)
{
	if (*item == '+') {
		*modify_type = MODIFY_ADD;
		item++;
	} else if (*item == '-') {
		*modify_type = MODIFY_REMOVE;
		item++;
	} else {
		*modify_type = MODIFY_REPLACE;
	}

	if (strncasecmp(item, "FLAGS", 5) != 0) {
		client_send_tagline(client, t_strconcat(
			"NO Invalid item ", item, NULL));
		return FALSE;
	}

	*silent = strcasecmp(item+5, ".SILENT") == 0;
	if (!*silent && item[5] != '\0') {
		client_send_tagline(client, t_strconcat(
			"NO Invalid item ", item, NULL));
		return FALSE;
	}

	return TRUE;
}

static int mail_send_flags(struct client *client, struct mail *mail)
{
	const struct mail_full_flags *flags;
	const char *str;

	flags = mail->get_flags(mail);
	if (flags == NULL)
		return FALSE;

	t_push();
	str = imap_write_flags(flags);
	str = t_strdup_printf(client->cmd_uid ?
			      "* %u FETCH (FLAGS (%s) UID %u)" :
			      "* %u FETCH (FLAGS (%s))",
			      mail->seq, str, mail->uid);
	client_send_line(client, str);
	t_pop();

	return TRUE;
}

int cmd_store(struct client *client)
{
	struct imap_arg *args;
	struct mail_full_flags flags;
	enum modify_type modify_type;
	struct mailbox *box;
	struct mail_search_arg *search_arg;
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
	const char *messageset, *item;
	int silent, modify, failed = FALSE;

	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	/* validate arguments */
	messageset = imap_arg_string(&args[0]);
	item = imap_arg_string(&args[1]);

	if (messageset == NULL || item == NULL) {
		client_send_command_error(client, "Invalid arguments.");
		return TRUE;
	}

	if (!get_modify_type(client, item, &modify_type, &silent))
		return TRUE;

	if (args[2].type == IMAP_ARG_LIST) {
		if (!client_parse_mail_flags(client,
					     IMAP_ARG_LIST(&args[2])->args,
					     &client->keywords, &flags))
			return TRUE;
	} else {
		if (!client_parse_mail_flags(client, args+2,
					     &client->keywords, &flags))
			return TRUE;
	}

	box = client->mailbox;
	search_arg = imap_search_get_arg(client, messageset, client->cmd_uid);
	if (search_arg == NULL)
		return TRUE;

	t = mailbox_transaction_begin(box, silent);
	if (!mailbox_is_readonly(box))
		modify = TRUE;
	else {
		/* flag changes will fail, notify client about them */
		modify = FALSE;
	}

	search_ctx = failed ? NULL :
		mailbox_search_init(t, NULL, search_arg, NULL,
				    MAIL_FETCH_FLAGS, NULL);

	if (search_ctx == NULL)
		failed = TRUE;
	else {
		failed = FALSE;
		while ((mail = mailbox_search_next(search_ctx)) != NULL) {
			if (modify) {
				if (mail->update_flags(mail, &flags,
						       modify_type) < 0) {
					failed = TRUE;
					break;
				}
			} else {
				if (!mail_send_flags(client, mail)) {
					failed = TRUE;
					break;
				}
			}
		}
	}

	if (mailbox_search_deinit(search_ctx) < 0)
		failed = TRUE;

	if (failed)
		mailbox_transaction_rollback(t);
	else {
		if (mailbox_transaction_commit(t) < 0)
			failed = TRUE;
	}

	if (!failed) {
		if (client->cmd_uid)
			client_sync_full_fast(client);
		else
			client_sync_without_expunges(client);
		client_send_tagline(client, "OK Store completed.");
	} else {
		client_send_storage_error(client, mailbox_get_storage(box));
	}

	return TRUE;
}
