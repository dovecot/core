#ifndef RAW_SYNC_H
#define RAW_SYNC_H

struct mailbox;

struct mailbox_sync_context *
raw_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
