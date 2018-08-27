#ifndef IMAP_STATUS_H
#define IMAP_STATUS_H

enum imap_status_item_flags {
	IMAP_STATUS_ITEM_MESSAGES = BIT(0),
	IMAP_STATUS_ITEM_RECENT = BIT(1),
	IMAP_STATUS_ITEM_UIDNEXT = BIT(2),
	IMAP_STATUS_ITEM_UIDVALIDITY = BIT(3),
	IMAP_STATUS_ITEM_UNSEEN = BIT(4),
	IMAP_STATUS_ITEM_HIGHESTMODSEQ = BIT(5),
	IMAP_STATUS_ITEM_SIZE = BIT(6),

	IMAP_STATUS_ITEM_X_SIZE = BIT(16), /* to be deprecated */
	IMAP_STATUS_ITEM_X_GUID = BIT(17),
};

struct imap_status_items {
	enum imap_status_item_flags flags;
};

struct imap_status_result {
	struct mailbox_status status;
	struct mailbox_metadata metadata;
	enum mail_error error;
	const char *errstr;
};

static inline bool
imap_status_items_is_empty(const struct imap_status_items *items)
{
	return (items->flags == 0);
}

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    struct imap_status_items *items_r);

int imap_status_get_result(struct client *client, struct mailbox *box,
			   const struct imap_status_items *items,
			   struct imap_status_result *result_r);
int imap_status_get(struct client_command_context *cmd,
		    struct mail_namespace *ns, const char *mailbox,
		    const struct imap_status_items *items,
		    struct imap_status_result *result_r);

int imap_status_send(struct client *client, const char *mailbox_mutf7,
		     const struct imap_status_items *items,
		     const struct imap_status_result *result)
	ATTR_NOWARN_UNUSED_RESULT;

#endif
