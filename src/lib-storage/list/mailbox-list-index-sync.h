#ifndef MAILBOX_LIST_INDEX_SYNC_H
#define MAILBOX_LIST_INDEX_SYNC_H

#include "mailbox-list-index.h"

struct mailbox_list_index_sync_context {
	struct mailbox_list *list;
	struct mailbox_list_index *ilist;
	char sep[2];
	uint32_t next_uid;
	uint32_t orig_highest_name_id;

	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	unsigned int syncing_list:1;
};

int mailbox_list_index_sync_begin(struct mailbox_list *list,
				  struct mailbox_list_index_sync_context **sync_ctx_r);
int mailbox_list_index_sync_end(struct mailbox_list_index_sync_context **_sync_ctx,
				bool success);
int mailbox_list_index_sync(struct mailbox_list *list);

/* Add name to index, return seq in index. */
uint32_t mailbox_list_index_sync_name(struct mailbox_list_index_sync_context *ctx,
				      const char *name,
				      struct mailbox_list_index_node **node_r,
				      bool *created_r);

#endif
