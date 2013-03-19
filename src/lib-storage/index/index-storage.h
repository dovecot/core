#ifndef INDEX_STORAGE_H
#define INDEX_STORAGE_H

#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "mail-index-private.h"

#define MAILBOX_FULL_SYNC_INTERVAL 5

enum mailbox_lock_notify_type {
	MAILBOX_LOCK_NOTIFY_NONE,

	/* Mailbox is locked, will abort in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
	/* Mailbox lock looks stale, will override in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE
};

struct index_vsize_header {
	uint64_t vsize;
	uint32_t highest_uid;
	uint32_t message_count;
};

struct index_mailbox_context {
	union mailbox_module_context module_ctx;
	enum mail_index_open_flags index_flags;

	struct timeout *notify_to, *notify_delay_to;
	struct index_notify_file *notify_files;
        struct index_notify_io *notify_ios;

	time_t next_lock_notify; /* temporary */
	enum mailbox_lock_notify_type last_notify_type;

	const ARRAY_TYPE(keywords) *keyword_names;
	struct mail_cache_field *cache_fields;

	ARRAY_TYPE(seq_range) recent_flags;
	uint32_t recent_flags_prev_uid, recent_flags_last_check_nextuid;
	uint32_t recent_flags_count;
	uint32_t vsize_hdr_ext_id;

	time_t sync_last_check;
	uint32_t list_index_sync_ext_id;
};

#define INDEX_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, index_storage_module)
extern MODULE_CONTEXT_DEFINE(index_storage_module,
			     &mail_storage_module_register);

void index_storage_lock_notify(struct mailbox *box,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left);
void index_storage_lock_notify_reset(struct mailbox *box);

int index_storage_mailbox_alloc_index(struct mailbox *box);
void index_storage_mailbox_alloc(struct mailbox *box, const char *vname,
				 enum mailbox_flags flags,
				 const char *index_prefix);
int index_storage_mailbox_exists(struct mailbox *box, bool auto_boxes,
				 enum mailbox_existence *existence_r);
int index_storage_mailbox_exists_full(struct mailbox *box, const char *subdir,
				      enum mailbox_existence *existence_r)
	ATTR_NULL(2);
int index_storage_mailbox_open(struct mailbox *box, bool move_to_memory);
int index_storage_mailbox_enable(struct mailbox *box,
				 enum mailbox_feature feature);
void index_storage_mailbox_close(struct mailbox *box);
void index_storage_mailbox_free(struct mailbox *box);
int index_storage_mailbox_update(struct mailbox *box,
				 const struct mailbox_update *update);
int index_storage_mailbox_update_common(struct mailbox *box,
					const struct mailbox_update *update);
int index_storage_mailbox_create(struct mailbox *box, bool directory);
int index_storage_mailbox_delete(struct mailbox *box);
int index_storage_mailbox_delete_dir(struct mailbox *box, bool mailbox_deleted);
int index_storage_mailbox_rename(struct mailbox *src, struct mailbox *dest);

bool index_storage_is_readonly(struct mailbox *box);
bool index_storage_is_inconsistent(struct mailbox *box);

void index_mailbox_set_recent_uid(struct mailbox *box, uint32_t uid);
void index_mailbox_set_recent_seq(struct mailbox *box,
				  struct mail_index_view *view,
				  uint32_t seq1, uint32_t seq2);
bool index_mailbox_is_recent(struct mailbox *box, uint32_t uid);
unsigned int index_mailbox_get_recent_count(struct mailbox *box);
void index_mailbox_reset_uidvalidity(struct mailbox *box);

void index_mailbox_check_add(struct mailbox *box, const char *path);
void index_mailbox_check_remove_all(struct mailbox *box);

enum mail_index_sync_flags index_storage_get_sync_flags(struct mailbox *box);
bool index_mailbox_want_full_sync(struct mailbox *box,
				  enum mailbox_sync_flags flags);
struct mailbox_sync_context *
index_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags,
			bool failed);
bool index_mailbox_sync_next(struct mailbox_sync_context *ctx,
			     struct mailbox_sync_rec *sync_rec_r);
int index_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      struct mailbox_sync_status *status_r);

int index_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags);
enum mailbox_sync_type index_sync_type_convert(enum mail_index_sync_type type);
void index_sync_update_recent_count(struct mailbox *box);
int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status_r);
void index_storage_get_open_status(struct mailbox *box,
				   enum mailbox_status_items items,
				   struct mailbox_status *status_r);
int index_mailbox_get_metadata(struct mailbox *box,
			       enum mailbox_metadata_items items,
			       struct mailbox_metadata *metadata_r);

int index_storage_attribute_set(struct mailbox_transaction_context *t,
				enum mail_attribute_type type, const char *key,
				const struct mail_attribute_value *value);
int index_storage_attribute_get(struct mailbox_transaction_context *t,
				enum mail_attribute_type type, const char *key,
				struct mail_attribute_value *value_r);
struct mailbox_attribute_iter *
index_storage_attribute_iter_init(struct mailbox *box,
				  enum mail_attribute_type type,
				  const char *prefix);
const char *
index_storage_attribute_iter_next(struct mailbox_attribute_iter *iter);
int index_storage_attribute_iter_deinit(struct mailbox_attribute_iter *iter);

struct mail_search_context *
index_storage_search_init(struct mailbox_transaction_context *t,
			  struct mail_search_args *args,
			  const enum mail_sort_type *sort_program,
			  enum mail_fetch_field wanted_fields,
			  struct mailbox_header_lookup_ctx *wanted_headers);
int index_storage_search_deinit(struct mail_search_context *ctx);
bool index_storage_search_next_nonblock(struct mail_search_context *ctx,
					struct mail **mail_r, bool *tryagain_r);
bool index_storage_search_next_update_seq(struct mail_search_context *ctx);

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags);
void index_transaction_init(struct mailbox_transaction_context *t,
			    struct mailbox *box,
			    enum mailbox_transaction_flags flags);
void index_transaction_init_pvt(struct mailbox_transaction_context *t);
int index_transaction_commit(struct mailbox_transaction_context *t,
			     struct mail_transaction_commit_changes *changes_r);
void index_transaction_rollback(struct mailbox_transaction_context *t);
void index_save_context_free(struct mail_save_context *ctx);
void index_copy_cache_fields(struct mail_save_context *ctx,
			     struct mail *src_mail, uint32_t dest_seq);
int index_storage_set_subscribed(struct mailbox *box, bool set);
void index_storage_destroy(struct mail_storage *storage);

bool index_keyword_array_cmp(const ARRAY_TYPE(keyword_indexes) *k1,
			     const ARRAY_TYPE(keyword_indexes) *k2);

int index_storage_list_index_has_changed(struct mailbox *box,
					 struct mail_index_view *list_view,
					 uint32_t seq);
void index_storage_list_index_update_sync(struct mailbox *box,
					  struct mail_index_transaction *trans,
					  uint32_t seq);

#endif
