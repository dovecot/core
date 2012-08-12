#ifndef IMAP_STATUS_H
#define IMAP_STATUS_H

struct imap_status_items {
	enum mailbox_status_items status;
	enum mailbox_metadata_items metadata;
};

struct imap_status_result {
	struct mailbox_status status;
	struct mailbox_metadata metadata;
	enum mail_error error;
	const char *errstr;
};

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    struct imap_status_items *items_r);
int imap_status_get(struct client_command_context *cmd,
		    struct mail_namespace *ns, const char *mailbox,
		    const struct imap_status_items *items,
		    struct imap_status_result *result_r);
int imap_status_send(struct client *client, const char *mailbox_mutf7,
		     const struct imap_status_items *items,
		     const struct imap_status_result *result)
	ATTR_NOWARN_UNUSED_RESULT;

#endif
