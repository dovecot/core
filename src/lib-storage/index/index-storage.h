#ifndef INDEX_STORAGE_H
#define INDEX_STORAGE_H

#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "mail-index-private.h"

/* Max. mmap()ed size for a message */
#define MAIL_MMAP_BLOCK_SIZE (1024*256)
/* Block size when read()ing message. */
#define MAIL_READ_BLOCK_SIZE (1024*8)

#define MAILBOX_FULL_SYNC_INTERVAL 5

enum mailbox_lock_notify_type {
	MAILBOX_LOCK_NOTIFY_NONE,

	/* Mailbox is locked, will abort in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
	/* Mailbox lock looks stale, will override in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE
};

struct index_mailbox {
	struct mailbox box;
	union mail_index_view_module_context view_module_ctx;

	struct mail_storage *storage;
	enum mailbox_open_flags open_flags;

	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_cache *cache;
	struct mail_vfuncs *mail_vfuncs;

	uint32_t md5hdr_ext_idx;

	struct timeout *notify_to;
	struct index_notify_file *notify_files;
        struct index_notify_io *notify_ios;
	time_t notify_last_check, notify_last_sent;

	time_t next_lock_notify; /* temporary */
	enum mailbox_lock_notify_type last_notify_type;

	uint32_t commit_log_file_seq;
	uoff_t commit_log_file_offset;

	const ARRAY_TYPE(keywords) *keyword_names;
	struct mail_cache_field *cache_fields;
	unsigned int mail_cache_min_mail_count;

	ARRAY_TYPE(seq_range) recent_flags;
	uint32_t recent_flags_prev_uid;
	uint32_t recent_flags_count;

	time_t sync_last_check;

	unsigned int readonly:1;
	unsigned int keep_recent:1;
	unsigned int keep_locked:1;
	unsigned int sent_diskspace_warning:1;
	unsigned int sent_readonly_flags_warning:1;
	unsigned int notify_pending:1;
	unsigned int move_to_memory:1;
	unsigned int fsync_disable:1;
};

struct index_transaction_context {
	struct mailbox_transaction_context mailbox_ctx;
	struct mail_index_transaction_vfuncs super;

	struct index_mailbox *ibox;
	enum mailbox_transaction_flags flags;
	int mail_ref_count;

	struct mail_index_transaction *trans;
	struct mail_index_view *trans_view;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;

	uint32_t *saved_uid_validity;
	uint32_t *first_saved_uid, *last_saved_uid;

	unsigned int cache_trans_failed:1;
};

void mail_storage_set_index_error(struct index_mailbox *ibox);

void index_storage_lock_notify(struct index_mailbox *ibox,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left);
void index_storage_lock_notify_reset(struct index_mailbox *ibox);

struct mail_index *
index_storage_alloc(struct mail_storage *storage, const char *name,
		    enum mailbox_open_flags flags, const char *prefix);
void index_storage_unref(struct mail_index *index);
void index_storage_destroy_unrefed(void);
void index_storage_destroy(struct mail_storage *storage ATTR_UNUSED);

void index_storage_mailbox_init(struct index_mailbox *ibox, const char *name,
				enum mailbox_open_flags flags,
				bool move_to_memory);
void index_storage_mailbox_open(struct index_mailbox *ibox);
int index_storage_mailbox_enable(struct mailbox *box,
				 enum mailbox_feature feature);
int index_storage_mailbox_close(struct mailbox *box);

bool index_storage_is_readonly(struct mailbox *box);
bool index_storage_allow_new_keywords(struct mailbox *box);
bool index_storage_is_inconsistent(struct mailbox *box);

int index_keywords_create(struct mailbox *box, const char *const keywords[],
			  struct mail_keywords **keywords_r, bool skip_invalid);
void index_keywords_free(struct mail_keywords *keywords);
bool index_keyword_is_valid(struct mailbox *box, const char *keyword,
			    const char **error_r);

void index_mailbox_set_recent_uid(struct index_mailbox *ibox, uint32_t uid);
void index_mailbox_set_recent_seq(struct index_mailbox *ibox,
				  struct mail_index_view *view,
				  uint32_t seq1, uint32_t seq2);
bool index_mailbox_is_recent(struct index_mailbox *ibox, uint32_t uid);
unsigned int index_mailbox_get_recent_count(struct index_mailbox *ibox);
void index_mailbox_reset_uidvalidity(struct index_mailbox *ibox);

void index_mailbox_check_add(struct index_mailbox *ibox,
			     const char *path);
void index_mailbox_check_remove_all(struct index_mailbox *ibox);

bool index_mailbox_want_full_sync(struct index_mailbox *ibox,
				  enum mailbox_sync_flags flags);
struct mailbox_sync_context *
index_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags,
			bool failed);
bool index_mailbox_sync_next(struct mailbox_sync_context *ctx,
			     struct mailbox_sync_rec *sync_rec_r);
int index_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      enum mailbox_status_items status_items,
			      struct mailbox_status *status_r);

int index_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags);
enum mailbox_sync_type index_sync_type_convert(enum mail_index_sync_type type);
void index_storage_get_status(struct mailbox *box,
			      enum mailbox_status_items items,
			      struct mailbox_status *status_r);
void index_storage_get_seq_range(struct mailbox *box,
				 uint32_t uid1, uint32_t uid2,
				 uint32_t *seq1_r, uint32_t *seq2_r);
void index_storage_get_uid_range(struct mailbox *box,
				 const ARRAY_TYPE(seq_range) *seqs,
				 ARRAY_TYPE(seq_range) *uids);
bool index_storage_get_expunged_uids(struct mailbox *box, uint64_t modseq,
				     const ARRAY_TYPE(seq_range) *uids,
				     ARRAY_TYPE(seq_range) *expunged_uids);

struct mailbox_header_lookup_ctx *
index_header_lookup_init(struct mailbox *box, const char *const headers[]);
void index_header_lookup_ref(struct mailbox_header_lookup_ctx *ctx);
void index_header_lookup_unref(struct mailbox_header_lookup_ctx *ctx);

struct mail_search_context *
index_storage_search_init(struct mailbox_transaction_context *t,
			  struct mail_search_args *args,
			  const enum mail_sort_type *sort_program);
int index_storage_search_deinit(struct mail_search_context *ctx);
int index_storage_search_next(struct mail_search_context *ctx,
			      struct mail *mail);
int index_storage_search_next_nonblock(struct mail_search_context *ctx,
				       struct mail *mail, bool *tryagain_r);
int index_storage_search_next_update_seq(struct mail_search_context *ctx);

void index_transaction_init(struct index_transaction_context *t,
			    struct index_mailbox *ibox);
int index_transaction_finish_commit(struct index_transaction_context *t,
				    uint32_t *log_file_seq_r,
				    uoff_t *log_file_offset_r);
void index_transaction_finish_rollback(struct index_transaction_context *t);
void index_transaction_set_max_modseq(struct mailbox_transaction_context *_t,
				      uint64_t max_modseq,
				      ARRAY_TYPE(seq_range) *seqs);

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags);
int index_transaction_commit(struct mailbox_transaction_context *t,
			     uint32_t *uid_validity_r,
			     uint32_t *first_saved_uid_r,
			     uint32_t *last_saved_uid_r);
void index_transaction_rollback(struct mailbox_transaction_context *t);

bool index_keyword_array_cmp(const ARRAY_TYPE(keyword_indexes) *k1,
			     const ARRAY_TYPE(keyword_indexes) *k2);

#endif
