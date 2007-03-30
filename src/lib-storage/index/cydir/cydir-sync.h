#ifndef __CYDIR_SYNC_H
#define __CYDIR_SYNC_H

enum mailbox_sync_flags;
struct mailbox;

struct cydir_sync_context {
	struct cydir_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
};

int cydir_sync_begin(struct cydir_mailbox *mbox,
		     struct cydir_sync_context **ctx_r);
int cydir_sync_finish(struct cydir_sync_context **ctx, bool success);
int cydir_sync(struct cydir_mailbox *mbox);

struct mailbox_sync_context *
cydir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
