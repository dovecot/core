#ifndef __IMAP_SYNC_H
#define __IMAP_SYNC_H

int imap_sync(struct client *client, struct mailbox *box,
	      enum mailbox_sync_flags flags);

#endif
