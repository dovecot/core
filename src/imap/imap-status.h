#ifndef IMAP_STATUS_H
#define IMAP_STATUS_H

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    enum mailbox_status_items *items_r);
int imap_status_get(struct client_command_context *cmd,
		    struct mail_namespace *ns,
		    const char *mailbox, enum mailbox_status_items items,
		    struct mailbox_status *status_r, const char **error_r);
void imap_status_send(struct client *client, const char *mailbox,
		      enum mailbox_status_items items,
		      const struct mailbox_status *status);

#endif
