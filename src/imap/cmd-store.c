/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

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
	struct mail_fetch_context *fetch_ctx;
	struct mail *mail;
	const char *messageset, *item;
	int silent, all_found, failed;

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
					     &client->mailbox_flags, &flags))
			return TRUE;
	} else {
		if (!client_parse_mail_flags(client, args+2,
					     &client->mailbox_flags, &flags))
			return TRUE;
	}

	/* and update the flags */
	box = client->mailbox;

	if (box->is_readonly(box)) {
		/* read-only, don't every try to get write locking */
		failed = FALSE;
	} else {
		failed = !box->lock(box, MAILBOX_LOCK_FLAGS |
				    MAILBOX_LOCK_READ);
	}

	fetch_ctx = failed ? NULL :
		box->fetch_init(box, MAIL_FETCH_FLAGS, NULL,
				messageset, client->cmd_uid);
	if (fetch_ctx == NULL)
		failed = TRUE;
	else {
		failed = FALSE;
		while ((mail = box->fetch_next(fetch_ctx)) != NULL) {
			if (!mail->update_flags(mail, &flags, modify_type)) {
				failed = TRUE;
				break;
			}

			if (!silent) {
				if (!mail_send_flags(client, mail)) {
					failed = TRUE;
					break;
				}
			}
		}
	}

	if (!box->fetch_deinit(fetch_ctx, &all_found))
		failed = TRUE;

	(void)box->lock(box, MAILBOX_LOCK_UNLOCK);

	if (!failed) {
		if (client->cmd_uid)
			client_sync_full_fast(client);
		else
			client_sync_without_expunges(client);
		client_send_tagline(client, all_found ? "OK Store completed." :
				    "NO Some of the messages no longer exist.");
	} else {
		client_send_storage_error(client, client->mailbox->storage);
	}

	return TRUE;
}
