#ifndef VIRTUAL_STORAGE_H
#define VIRTUAL_STORAGE_H

#include "seq-range-array.h"
#include "index-storage.h"
#include "mailbox-list-private.h"

#define VIRTUAL_STORAGE_NAME "virtual"
#define VIRTUAL_SUBSCRIPTION_FILE_NAME ".virtual-subscriptions"
#define VIRTUAL_CONFIG_FNAME "dovecot-virtual"
#define VIRTUAL_INDEX_PREFIX "dovecot.index"

#define VIRTUAL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, virtual_storage_module)

struct virtual_mail_index_header {
	/* Increased by one each time the header is modified */
	uint32_t change_counter;
	/* Number of mailbox records following this header. Mailbox names
	   follow the mailbox records - they have neither NUL terminator nor
	   padding. */
	uint32_t mailbox_count;
	/* Highest used mailbox ID. IDs are never reused. */
	uint32_t highest_mailbox_id;
	/* CRC32 of all the search parameters. If it changes, the mailbox is
	   rebuilt. */
	uint32_t search_args_crc32;
};

struct virtual_mail_index_mailbox_record {
	/* Unique mailbox ID used as mailbox_id in records. */
	uint32_t id;
	/* Length of this mailbox's name. */
	uint32_t name_len;
	/* Synced UID validity value */
	uint32_t uid_validity;
	/* Next unseen UID */
	uint32_t next_uid;
	/* Synced highest modseq value */
	uint64_t highest_modseq;
};

struct virtual_mail_index_record {
	uint32_t mailbox_id;
	uint32_t real_uid;
};

struct virtual_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;

	/* List of mailboxes while a virtual mailbox is being opened.
	   Used to track loops. */
	ARRAY_TYPE(const_string) open_stack;
};

struct virtual_backend_uidmap {
	uint32_t real_uid;
	/* can be 0 temporarily while syncing before the UID is assigned */
	uint32_t virtual_uid;
};

struct virtual_backend_box {
	/* Initially zero, updated by syncing */
	uint32_t mailbox_id;
	const char *name;

	unsigned int sync_mailbox_idx;
	uint32_t sync_uid_validity;
	uint32_t sync_next_uid;
	uint64_t sync_highest_modseq;

	struct mail_search_args *search_args;
	struct mail_search_result *search_result;

	struct mailbox *box;
	/* Messages currently included in the virtual mailbox,
	   sorted by real_uid */
	ARRAY_DEFINE(uids, struct virtual_backend_uidmap);

	/* temporary mail used while syncing */
	struct mail *sync_mail;
	/* pending removed UIDs */
	ARRAY_TYPE(seq_range) sync_pending_removes;

	/* name contains a wildcard, this is a glob for it */
	struct imap_match_glob *glob;
	struct mail_namespace *ns;

	unsigned int sync_seen:1;
};
ARRAY_DEFINE_TYPE(virtual_backend_box, struct virtual_backend_box *);

struct virtual_mailbox {
	struct index_mailbox ibox;
	struct virtual_storage *storage;

	const char *path;
	uint32_t virtual_ext_id;

	uint32_t prev_uid_validity;
	uint32_t prev_change_counter;
	uint32_t highest_mailbox_id;
	uint32_t search_args_crc32;

	char *vseq_lookup_prev_mailbox;
	struct virtual_backend_box *vseq_lookup_prev_bbox;

	/* Mailboxes this virtual mailbox consists of, sorted by mailbox_id */
	ARRAY_TYPE(virtual_backend_box) backend_boxes;

	unsigned int uids_mapped:1;
	unsigned int sync_initialized:1;
};

extern MODULE_CONTEXT_DEFINE(virtual_storage_module,
			     &mail_storage_module_register);

extern struct mail_storage virtual_storage;
extern struct mail_vfuncs virtual_mail_vfuncs;

int virtual_config_read(struct virtual_mailbox *mbox);
void virtual_config_free(struct virtual_mailbox *mbox);

struct virtual_backend_box *
virtual_backend_box_lookup_name(struct virtual_mailbox *mbox, const char *name);
struct virtual_backend_box *
virtual_backend_box_lookup(struct virtual_mailbox *mbox, uint32_t mailbox_id);
struct mailbox_transaction_context *
virtual_transaction_get(struct mailbox_transaction_context *trans,
			struct mailbox *backend_box);

struct mail_search_context *
virtual_search_init(struct mailbox_transaction_context *t,
		    struct mail_search_args *args,
		    const enum mail_sort_type *sort_program);
int virtual_search_deinit(struct mail_search_context *ctx);
int virtual_search_next_nonblock(struct mail_search_context *ctx,
				 struct mail *mail, bool *tryagain_r);
bool virtual_search_next_update_seq(struct mail_search_context *ctx);

struct mail *
virtual_mail_alloc(struct mailbox_transaction_context *t,
		   enum mail_fetch_field wanted_fields,
		   struct mailbox_header_lookup_ctx *wanted_headers);

struct mailbox_sync_context *
virtual_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

void virtual_copy_error(struct mail_storage *dest, struct mail_storage *src);
void virtual_box_copy_error(struct mailbox *dest, struct mailbox *src);

void virtual_transaction_class_init(void);
void virtual_transaction_class_deinit(void);

#endif
