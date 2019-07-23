#ifndef INDEX_STORAGE_H
#define INDEX_STORAGE_H

#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "mail-index-private.h"
#include "mailbox-watch.h"

#define MAILBOX_FULL_SYNC_INTERVAL 5

enum mailbox_lock_notify_type {
	MAILBOX_LOCK_NOTIFY_NONE,

	/* Mailbox is locked, will abort in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
	/* Mailbox lock looks stale, will override in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE
};

enum index_storage_list_change {
	INDEX_STORAGE_LIST_CHANGE_ERROR = -1,
	INDEX_STORAGE_LIST_CHANGE_NONE = 0,
	INDEX_STORAGE_LIST_CHANGE_INMEMORY,
	INDEX_STORAGE_LIST_CHANGE_NORECORD,
	INDEX_STORAGE_LIST_CHANGE_NOT_IN_FS,
	INDEX_STORAGE_LIST_CHANGE_SIZE_CHANGED,
	INDEX_STORAGE_LIST_CHANGE_MTIME_CHANGED
};

struct index_mailbox_context {
	union mailbox_module_context module_ctx;
	enum mail_index_open_flags index_flags;

	time_t next_lock_notify; /* temporary */
	enum mailbox_lock_notify_type last_notify_type;

	const ARRAY_TYPE(keywords) *keyword_names;
	struct mail_cache_field *cache_fields;

	struct mailbox_vsize_update *vsize_update;

	uint32_t recent_flags_prev_first_recent_uid;
	uint32_t recent_flags_last_check_nextuid;

	time_t sync_last_check;
	uint32_t list_index_sync_ext_id;
};

#define INDEX_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, index_storage_module)
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
int index_storage_mailbox_delete_pre(struct mailbox *box);
int index_storage_mailbox_delete_post(struct mailbox *box);
int index_storage_mailbox_delete(struct mailbox *box);
int index_storage_mailbox_delete_dir(struct mailbox *box, bool mailbox_deleted);
int index_storage_mailbox_rename(struct mailbox *src, struct mailbox *dest);

int index_mailbox_update_last_temp_file_scan(struct mailbox *box);
int index_mailbox_fix_inconsistent_existence(struct mailbox *box,
					     const char *path);

bool index_storage_is_readonly(struct mailbox *box);
bool index_storage_is_inconsistent(struct mailbox *box);

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
int index_mailbox_get_virtual_size(struct mailbox *box,
				   struct mailbox_metadata *metadata_r);
int index_mailbox_get_physical_size(struct mailbox *box,
				    struct mailbox_metadata *metadata_r);

int index_storage_attribute_set(struct mailbox_transaction_context *t,
				enum mail_attribute_type type_flags,
				const char *key,
				const struct mail_attribute_value *value);
int index_storage_attribute_get(struct mailbox *box,
				enum mail_attribute_type type_flags,
				const char *key,
				struct mail_attribute_value *value_r);
struct mailbox_attribute_iter *
index_storage_attribute_iter_init(struct mailbox *box,
				  enum mail_attribute_type type_flags,
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
			enum mailbox_transaction_flags flags,
			const char *reason);
void index_transaction_init(struct mailbox_transaction_context *t,
			    struct mailbox *box,
			    enum mailbox_transaction_flags flags,
			    const char *reason);
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
					 uint32_t seq, bool quick);
enum index_storage_list_change
index_storage_list_index_has_changed_full(struct mailbox *box,
					  struct mail_index_view *list_view,
					  uint32_t seq);
void index_storage_list_index_update_sync(struct mailbox *box,
					  struct mail_index_transaction *trans,
					  uint32_t seq);

int index_storage_expunged_sync_begin(struct mailbox *box,
				      struct mail_index_sync_ctx **ctx_r,
				      struct mail_index_view **view_r,
				      struct mail_index_transaction **trans_r,
				      enum mail_index_sync_flags flags);
void index_storage_expunging_deinit(struct mailbox *box);

int index_storage_save_continue(struct mail_save_context *ctx,
				struct istream *input,
				struct mail *cache_dest_mail);
void index_storage_save_abort_last(struct mail_save_context *ctx, uint32_t seq);

#endif
