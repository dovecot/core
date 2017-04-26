#ifndef IMAP_SYNC_PRIVATE_H
#define IMAP_SYNC_PRIVATE_H

#include "imap-sync.h"

struct imap_sync_context {
	struct client *client;
	struct mailbox *box;
        enum imap_sync_flags imap_flags;

	struct mailbox_transaction_context *t;
	struct mailbox_sync_context *sync_ctx;
	struct mail *mail;

	struct mailbox_status status;
	struct mailbox_sync_status sync_status;

	struct mailbox_sync_rec sync_rec;
	ARRAY_TYPE(keywords) tmp_keywords;
	ARRAY_TYPE(seq_range) expunges;
	uint32_t seq;

	ARRAY_TYPE(seq_range) search_adds, search_removes;
	unsigned int search_update_idx;

	unsigned int messages_count;

	bool failed:1;
	bool finished:1;
	bool no_newmail:1;
	bool have_new_mails:1;
	bool search_update_notifying:1;
};

#endif
