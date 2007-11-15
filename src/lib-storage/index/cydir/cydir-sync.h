#ifndef CYDIR_SYNC_H
#define CYDIR_SYNC_H

struct mailbox;

struct cydir_sync_context {
	struct cydir_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;

	string_t *path;
	unsigned int path_dir_prefix_len;
	uint32_t uid_validity;
};

int cydir_sync_begin(struct cydir_mailbox *mbox,
		     struct cydir_sync_context **ctx_r, bool force);
int cydir_sync_finish(struct cydir_sync_context **ctx, bool success);

struct mailbox_sync_context *
cydir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
