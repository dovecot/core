#ifndef IMAP_STATUS_H
#define IMAP_STATUS_H

struct imap_status_items {
	enum mailbox_status_items mailbox_items;

	unsigned int guid:1;
};

struct imap_status_result {
	struct mailbox_status status;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
};

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    struct imap_status_items *items_r);
int imap_status_get(struct client_command_context *cmd,
		    struct mail_namespace *ns,
		    const char *mailbox, const struct imap_status_items *items,
		    struct imap_status_result *result_r, const char **error_r);
void imap_status_send(struct client *client, const char *mailbox,
		      const struct imap_status_items *items,
		      const struct imap_status_result *result);

#endif
