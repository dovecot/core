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
	enum mailbox_status_items items;

	if (IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Empty status list.");
		return -1;
	}

	memset(items_r, 0, sizeof(*items_r));
	items = 0;
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (!imap_arg_get_atom(args, &item)) {
			/* list may contain only atoms */
			client_send_command_error(cmd,
				"Status list contains non-atoms.");
			return -1;
		}

		item = t_str_ucase(item);
		if (strcmp(item, "MESSAGES") == 0)
			items |= STATUS_MESSAGES;
		else if (strcmp(item, "RECENT") == 0)
			items |= STATUS_RECENT;
		else if (strcmp(item, "UIDNEXT") == 0)
			items |= STATUS_UIDNEXT;
		else if (strcmp(item, "UIDVALIDITY") == 0)
			items |= STATUS_UIDVALIDITY;
		else if (strcmp(item, "UNSEEN") == 0)
			items |= STATUS_UNSEEN;
		else if (strcmp(item, "HIGHESTMODSEQ") == 0)
			items |= STATUS_HIGHESTMODSEQ;
		else if (strcmp(item, "X-SIZE") == 0)
			items |= STATUS_VIRTUAL_SIZE;
		else if (strcmp(item, "X-GUID") == 0)
			items_r->guid = TRUE;
		else {
			client_send_tagline(cmd, t_strconcat(
				"BAD Invalid status item ", item, NULL));
			return -1;
		}
	}

	items_r->mailbox_items = items;
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
	int ret;

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
			mailbox_enable(box, client->enabled_features);
	}

	if ((items->mailbox_items & STATUS_HIGHESTMODSEQ) != 0)
		client_enable(client, MAILBOX_FEATURE_CONDSTORE);

	ret = box == client->mailbox ? 0 : mailbox_sync(box, 0);
	if (ret == 0) {
		mailbox_get_status(box, items->mailbox_items,
				   &result_r->status);
		if (items->guid)
			ret = mailbox_get_guid(box, result_r->mailbox_guid);
	}

	if (ret < 0) {
		struct mail_storage *storage = mailbox_get_storage(box);

		*error_r = mail_storage_get_last_error(storage, &error);
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
	if ((items->mailbox_items & STATUS_MESSAGES) != 0)
		str_printfa(str, "MESSAGES %u ", status->messages);
	if ((items->mailbox_items & STATUS_RECENT) != 0)
		str_printfa(str, "RECENT %u ", status->recent);
	if ((items->mailbox_items & STATUS_UIDNEXT) != 0)
		str_printfa(str, "UIDNEXT %u ", status->uidnext);
	if ((items->mailbox_items & STATUS_UIDVALIDITY) != 0)
		str_printfa(str, "UIDVALIDITY %u ", status->uidvalidity);
	if ((items->mailbox_items & STATUS_UNSEEN) != 0)
		str_printfa(str, "UNSEEN %u ", status->unseen);
	if ((items->mailbox_items & STATUS_HIGHESTMODSEQ) != 0) {
		str_printfa(str, "HIGHESTMODSEQ %llu ",
			    (unsigned long long)status->highest_modseq);
	}
	if ((items->mailbox_items & STATUS_VIRTUAL_SIZE) != 0) {
		str_printfa(str, "X-SIZE %llu ",
			    (unsigned long long)status->virtual_size);
	}
	if (items->guid) {
		str_printfa(str, "X-GUID %s ",
			    mail_guid_128_to_string(result->mailbox_guid));
	}

	if (str_len(str) != prefix_len)
		str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	client_send_line(client, str_c(str));
}
