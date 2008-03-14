#ifndef VIRTUAL_STORAGE_H
#define VIRTUAL_STORAGE_H

#include "seq-range-array.h"
#include "index-storage.h"
#include "mailbox-list-private.h"

#define VIRTUAL_STORAGE_NAME "virtual"
#define VIRTUAL_SUBSCRIPTION_FILE_NAME ".virtual-subscriptions"
#define VIRTUAL_CONFIG_FNAME "dovecot-virtual"
#define VIRTUAL_INDEX_PREFIX "dovecot.index"

struct virtual_mail_index_record {
	uint32_t mailbox_id;
	uint32_t real_uid;
};

struct virtual_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;
};

struct virtual_backend_box {
	uint32_t mailbox_id;
	const char *name;
	struct mail_search_arg *search_args;

	struct mailbox *box;
	/* Sorted list of UIDs currently included in the virtual mailbox */
	ARRAY_TYPE(seq_range) uids;

	struct mail *sync_mail;
	unsigned int sync_iter_idx;
	unsigned int sync_iter_prev_real_uid;
};

struct virtual_mailbox {
	struct index_mailbox ibox;
	struct virtual_storage *storage;

	const char *path;
	uint32_t virtual_ext_id;

	/* Mailboxes this virtual mailbox consists of, sorted by mailbox_id */
	ARRAY_DEFINE(backend_boxes, struct virtual_backend_box *);
};

extern struct mail_storage virtual_storage;
extern struct mail_vfuncs virtual_mail_vfuncs;

int virtual_config_read(struct virtual_mailbox *mbox);

struct virtual_backend_box *
virtual_backend_box_lookup(struct virtual_mailbox *mbox, uint32_t mailbox_id);
struct mailbox_transaction_context *
virtual_transaction_get(struct mailbox_transaction_context *trans,
			struct mailbox *backend_box);

struct mail *
virtual_mail_alloc(struct mailbox_transaction_context *t,
		   enum mail_fetch_field wanted_fields,
		   struct mailbox_header_lookup_ctx *wanted_headers);

struct mailbox_sync_context *
virtual_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

void virtual_transaction_class_init(void);
void virtual_transaction_class_deinit(void);

#endif
