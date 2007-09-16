#ifndef IMAP_STATUS_H
#define IMAP_STATUS_H

int imap_status_parse_items(struct client_command_context *cmd,
			    const struct imap_arg *args,
			    enum mailbox_status_items *items_r);
bool imap_status_get(struct client *client, struct mail_storage *storage,
		     const char *mailbox, enum mailbox_status_items items,
		     struct mailbox_status *status_r);
void imap_status_send(struct client *client, const char *mailbox,
		      enum mailbox_status_items items,
		      const struct mailbox_status *status);

#endif
