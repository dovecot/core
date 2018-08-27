/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "hex-binary.h"
#include "str.h"
#include "imap-quote.h"
#include "imap-status.h"

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    struct imap_status_items *items_r)
{
	enum imap_status_item_flags flags = 0;
	const char *item;

	if (IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Empty status list.");
		return -1;
	}

	i_zero(items_r);
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (!imap_arg_get_atom(args, &item)) {
			/* list may contain only atoms */
			client_send_command_error(cmd,
				"Status list contains non-atoms.");
			return -1;
		}

		item = t_str_ucase(item);
		if (strcmp(item, "MESSAGES") == 0)
			flags |= IMAP_STATUS_ITEM_MESSAGES;
		else if (strcmp(item, "RECENT") == 0)
			flags |= IMAP_STATUS_ITEM_RECENT;
		else if (strcmp(item, "UIDNEXT") == 0)
			flags |= IMAP_STATUS_ITEM_UIDNEXT;
		else if (strcmp(item, "UIDVALIDITY") == 0)
			flags |= IMAP_STATUS_ITEM_UIDVALIDITY;
		else if (strcmp(item, "UNSEEN") == 0)
			flags |= IMAP_STATUS_ITEM_UNSEEN;
		else if (strcmp(item, "HIGHESTMODSEQ") == 0)
			flags |= IMAP_STATUS_ITEM_HIGHESTMODSEQ;
		else if (strcmp(item, "SIZE") == 0)
			flags |= IMAP_STATUS_ITEM_SIZE;
		else if (strcmp(item, "X-SIZE") == 0)
			flags |= IMAP_STATUS_ITEM_X_SIZE;
		else if (strcmp(item, "X-GUID") == 0)
			flags |= IMAP_STATUS_ITEM_X_GUID;
		else {
			client_send_command_error(cmd, t_strconcat(
				"Invalid status item ", item, NULL));
			return -1;
		}
	}

	items_r->flags = flags;
	return 0;
}

int imap_status_get_result(struct client *client, struct mailbox *box,
			   const struct imap_status_items *items,
			   struct imap_status_result *result_r)
{
	enum mailbox_status_items status = 0;
	enum mailbox_metadata_items metadata = 0;
	int ret;

	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_MESSAGES))
		status |= STATUS_MESSAGES;
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_RECENT))
		status |= STATUS_RECENT;
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_UIDNEXT))
		status |= STATUS_UIDNEXT;
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_UIDVALIDITY))
		status |= STATUS_UIDVALIDITY;
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_UNSEEN))
		status |= STATUS_UNSEEN;
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_HIGHESTMODSEQ)) {
		client_enable(client, imap_feature_condstore);
		status |= STATUS_HIGHESTMODSEQ;
	}
	if (HAS_ANY_BITS(items->flags, IMAP_STATUS_ITEM_SIZE |
				       IMAP_STATUS_ITEM_X_SIZE))
		metadata |= MAILBOX_METADATA_VIRTUAL_SIZE;
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_X_GUID))
		metadata |= MAILBOX_METADATA_GUID;

	ret = mailbox_get_status(box, status, &result_r->status);
	if (metadata != 0 && ret == 0)
		ret = mailbox_get_metadata(box, metadata, &result_r->metadata);

	return ret;
}

int imap_status_get(struct client_command_context *cmd,
		    struct mail_namespace *ns, const char *mailbox,
		    const struct imap_status_items *items,
		    struct imap_status_result *result_r)
{
	struct client *client = cmd->client;
	struct mailbox *box;
	const char *errstr;
	int ret = 0;

	if (client->mailbox != NULL &&
	    mailbox_equals(client->mailbox, ns, mailbox)) {
		/* this mailbox is selected */
		box = client->mailbox;
	} else {
		/* open the mailbox */
		box = mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_READONLY);
		mailbox_set_reason(box, "STATUS");
		(void)mailbox_enable(box, client_enabled_mailbox_features(client));
	}

	ret = imap_status_get_result(client, box, items, result_r);
	if (ret < 0) {
		errstr = mailbox_get_last_error(box, &result_r->error);
		result_r->errstr = imap_get_error_string(cmd, errstr,
							 result_r->error);
	}
	if (box != client->mailbox)
		mailbox_free(&box);
	return ret;
}

int imap_status_send(struct client *client, const char *mailbox_mutf7,
		     const struct imap_status_items *items,
		     const struct imap_status_result *result)
{
	const struct mailbox_status *status = &result->status;
	string_t *str;
	size_t prefix_len;

	str = t_str_new(128);
	str_append(str, "* STATUS ");
        imap_append_astring(str, mailbox_mutf7);
	str_append(str, " (");

	prefix_len = str_len(str);
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_MESSAGES))
		str_printfa(str, "MESSAGES %u ", status->messages);
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_RECENT))
		str_printfa(str, "RECENT %u ", status->recent);
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_UIDNEXT))
		str_printfa(str, "UIDNEXT %u ", status->uidnext);
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_UIDVALIDITY))
		str_printfa(str, "UIDVALIDITY %u ", status->uidvalidity);
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_UNSEEN))
		str_printfa(str, "UNSEEN %u ", status->unseen);
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_HIGHESTMODSEQ)) {
		str_printfa(str, "HIGHESTMODSEQ %"PRIu64" ",
			    status->highest_modseq);
	}
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_SIZE)) {
		str_printfa(str, "SIZE %"PRIu64" ",
			    result->metadata.virtual_size);
	}
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_X_SIZE)) {
		str_printfa(str, "X-SIZE %"PRIu64" ",
			    result->metadata.virtual_size);
	}
	if (HAS_ALL_BITS(items->flags, IMAP_STATUS_ITEM_X_GUID)) {
		str_printfa(str, "X-GUID %s ",
			    guid_128_to_string(result->metadata.guid));
	}

	if (str_len(str) != prefix_len)
		str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	return client_send_line_next(client, str_c(str));
}
