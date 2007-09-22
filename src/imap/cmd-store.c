/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-util.h"

static bool
get_modify_type(struct client_command_context *cmd, const char *item,
		enum modify_type *modify_type, bool *silent)
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
		client_send_tagline(cmd, t_strconcat(
			"NO Invalid item ", item, NULL));
		return FALSE;
	}

	*silent = strcasecmp(item+5, ".SILENT") == 0;
	if (!*silent && item[5] != '\0') {
		client_send_tagline(cmd, t_strconcat(
			"NO Invalid item ", item, NULL));
		return FALSE;
	}

	return TRUE;
}

bool cmd_store(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	enum mail_flags flags;
	const char *const *keywords_list;
	struct mail_keywords *keywords;
	enum modify_type modify_type;
	struct mailbox *box;
	struct mail_search_arg *search_arg;
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
	const char *messageset, *item;
	bool silent, failed;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* validate arguments */
	messageset = imap_arg_string(&args[0]);
	item = imap_arg_string(&args[1]);

	if (messageset == NULL || item == NULL) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	if (!get_modify_type(cmd, item, &modify_type, &silent))
		return TRUE;

	if (args[2].type == IMAP_ARG_LIST) {
		if (!client_parse_mail_flags(cmd,
					     IMAP_ARG_LIST_ARGS(&args[2]),
					     &flags, &keywords_list))
			return TRUE;
	} else {
		if (!client_parse_mail_flags(cmd, args+2,
					     &flags, &keywords_list))
			return TRUE;
	}

	box = client->mailbox;
	search_arg = imap_search_get_arg(cmd, messageset, cmd->uid);
	if (search_arg == NULL)
		return TRUE;

	t = mailbox_transaction_begin(box, !silent ? 0 :
				      MAILBOX_TRANSACTION_FLAG_HIDE);
	if (keywords_list == NULL && modify_type != MODIFY_REPLACE)
		keywords = NULL;
	else if (mailbox_keywords_create(box, keywords_list, &keywords) < 0) {
		/* invalid keywords */
		mailbox_transaction_rollback(&t);
		client_send_storage_error(cmd, mailbox_get_storage(box));
		return TRUE;
	}
	search_ctx = mailbox_search_init(t, NULL, search_arg, NULL);

	mail = mail_alloc(t, MAIL_FETCH_FLAGS, NULL);
	while (mailbox_search_next(search_ctx, mail) > 0) {
		if (modify_type == MODIFY_REPLACE || flags != 0)
			mail_update_flags(mail, modify_type, flags);
		if (modify_type == MODIFY_REPLACE || keywords != NULL)
			mail_update_keywords(mail, modify_type, keywords);
	}
	mail_free(&mail);

	if (keywords != NULL)
		mailbox_keywords_free(box, &keywords);

	if (mailbox_search_deinit(&search_ctx) < 0) {
		failed = TRUE;
		mailbox_transaction_rollback(&t);
	} else {
		failed = mailbox_transaction_commit(&t, 0) < 0;
	}

	if (!failed) {
		/* With UID STORE we have to return UID for the flags as well.
		   Unfortunately we don't have the ability to separate those
		   flag changes that were caused by UID STORE and those that
		   came externally, so we'll just send the UID for all flag
		   changes that we see. */
		return cmd_sync(cmd,
				(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
				cmd->uid && !silent ?
				IMAP_SYNC_FLAG_SEND_UID : 0,
				"OK Store completed.");
	} else {
		client_send_storage_error(cmd, mailbox_get_storage(box));
		return TRUE;
	}
}
