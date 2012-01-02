#ifndef POP3C_SYNC_H
#define POP3C_SYNC_H

struct mailbox;
struct pop3c_mailbox;

struct mailbox_sync_context *
pop3c_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
int pop3c_sync(struct pop3c_mailbox *mbox);

int pop3c_sync_get_sizes(struct pop3c_mailbox *mbox);
int pop3c_sync_get_uidls(struct pop3c_mailbox *mbox);

#endif
