#ifndef __IMAP_SYNC_H
#define __IMAP_SYNC_H

struct imap_sync_context *
imap_sync_init(struct client *client, struct mailbox *box,
	       enum mailbox_sync_flags flags);
int imap_sync_deinit(struct imap_sync_context *ctx);
int imap_sync_more(struct imap_sync_context *ctx);

int imap_sync_nonselected(struct mailbox *box, enum mailbox_sync_flags flags);

int cmd_sync(struct client *client, enum mailbox_sync_flags flags,
	     const char *tagline);

#endif
