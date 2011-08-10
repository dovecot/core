/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "hex-binary.h"
#include "str.h"
#include "imap-quote.h"
#include "imap-status.h"

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    struct imap_status_items *items_r)
{
	const char *item;
	enum mailbox_status_items status = 0;
	enum mailbox_metadata_items metadata = 0;

	if (IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Empty status list.");
		return -1;
	}

	memset(items_r, 0, sizeof(*items_r));
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (!imap_arg_get_atom(args, &item)) {
			/* list may contain only atoms */
			client_send_command_error(cmd,
				"Status list contains non-atoms.");
			return -1;
		}

		item = t_str_ucase(item);
		if (strcmp(item, "MESSAGES") == 0)
			status |= STATUS_MESSAGES;
		else if (strcmp(item, "RECENT") == 0)
			status |= STATUS_RECENT;
		else if (strcmp(item, "UIDNEXT") == 0)
			status |= STATUS_UIDNEXT;
		else if (strcmp(item, "UIDVALIDITY") == 0)
			status |= STATUS_UIDVALIDITY;
		else if (strcmp(item, "UNSEEN") == 0)
			status |= STATUS_UNSEEN;
		else if (strcmp(item, "HIGHESTMODSEQ") == 0)
			status |= STATUS_HIGHESTMODSEQ;
		else if (strcmp(item, "X-SIZE") == 0)
			metadata |= MAILBOX_METADATA_VIRTUAL_SIZE;
		else if (strcmp(item, "X-GUID") == 0)
			metadata |= MAILBOX_METADATA_GUID;
		else {
			client_send_tagline(cmd, t_strconcat(
				"BAD Invalid status item ", item, NULL));
			return -1;
		}
	}

	items_r->status = status;
	items_r->metadata = metadata;
	return 0;
}

int imap_status_get(struct client_command_context *cmd,
		    struct mail_namespace *ns,
		    const char *mailbox, const struct imap_status_items *items,
		    struct imap_status_result *result_r, const char **error_r)
{
	struct client *client = cmd->client;
	struct mailbox *box;
	enum mail_error error;
	int ret = 0;

	if (client->mailbox != NULL &&
	    mailbox_equals(client->mailbox, ns, mailbox)) {
		/* this mailbox is selected */
		box = client->mailbox;
	} else {
		/* open the mailbox */
		box = mailbox_alloc(ns->list, mailbox,
				    MAILBOX_FLAG_READONLY |
				    MAILBOX_FLAG_KEEP_RECENT);
		if (client->enabled_features != 0)
			(void)mailbox_enable(box, client->enabled_features);
	}

	if ((items->status & STATUS_HIGHESTMODSEQ) != 0)
		(void)client_enable(client, MAILBOX_FEATURE_CONDSTORE);

	ret = mailbox_get_status(box, items->status, &result_r->status);
	if (items->metadata != 0 && ret == 0) {
		ret = mailbox_get_metadata(box, items->metadata,
					   &result_r->metadata);
	}

	if (ret < 0) {
		*error_r = mailbox_get_last_error(box, &error);
		*error_r = imap_get_error_string(cmd, *error_r, error);
	}
	if (box != client->mailbox)
		mailbox_free(&box);
	return ret;
}

void imap_status_send(struct client *client, const char *mailbox,
		      const struct imap_status_items *items,
		      const struct imap_status_result *result)
{
	const struct mailbox_status *status = &result->status;
	string_t *str;
	unsigned int prefix_len;

	str = t_str_new(128);
	str_append(str, "* STATUS ");
        imap_quote_append_string(str, mailbox, FALSE);
	str_append(str, " (");

	prefix_len = str_len(str);
	if ((items->status & STATUS_MESSAGES) != 0)
		str_printfa(str, "MESSAGES %u ", status->messages);
	if ((items->status & STATUS_RECENT) != 0)
		str_printfa(str, "RECENT %u ", status->recent);
	if ((items->status & STATUS_UIDNEXT) != 0)
		str_printfa(str, "UIDNEXT %u ", status->uidnext);
	if ((items->status & STATUS_UIDVALIDITY) != 0)
		str_printfa(str, "UIDVALIDITY %u ", status->uidvalidity);
	if ((items->status & STATUS_UNSEEN) != 0)
		str_printfa(str, "UNSEEN %u ", status->unseen);
	if ((items->status & STATUS_HIGHESTMODSEQ) != 0) {
		str_printfa(str, "HIGHESTMODSEQ %llu ",
			    (unsigned long long)status->highest_modseq);
	}
	if ((items->metadata & MAILBOX_METADATA_VIRTUAL_SIZE) != 0) {
		str_printfa(str, "X-SIZE %llu ",
			    (unsigned long long)result->metadata.virtual_size);
	}
	if ((items->metadata & MAILBOX_METADATA_GUID) != 0) {
		str_printfa(str, "X-GUID %s ",
			    mail_guid_128_to_string(result->metadata.guid));
	}

	if (str_len(str) != prefix_len)
		str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	client_send_line(client, str_c(str));
}
