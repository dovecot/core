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

struct index_transaction_context {
	struct mailbox_transaction_context mailbox_ctx;
	union mail_index_transaction_module_context module_ctx;

	struct mail_index_transaction_vfuncs super;
	int mail_ref_count;

	struct mail_index_transaction *trans;
	struct mail_index_view *trans_view;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
};

struct index_mailbox {
	struct mailbox box;
	union mail_index_view_module_context view_module_ctx;
	enum mail_index_open_flags index_flags;

	int (*save_commit_pre)(struct mail_save_context *save_ctx);
	void (*save_commit_post)(struct mail_save_context *save_ctx,
				 struct mail_index_transaction_commit_result *result_r);
	void (*save_rollback)(struct mail_save_context *save_ctx);

	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_cache *cache;
	struct mail_vfuncs *mail_vfuncs;

	struct timeout *notify_to, *notify_delay_to;
	struct index_notify_file *notify_files;
        struct index_notify_io *notify_ios;
	time_t notify_last_check;

	time_t next_lock_notify; /* temporary */
	enum mailbox_lock_notify_type last_notify_type;

	const ARRAY_TYPE(keywords) *keyword_names;
	struct mail_cache_field *cache_fields;

	ARRAY_TYPE(seq_range) recent_flags;
	uint32_t recent_flags_prev_uid;
	uint32_t recent_flags_count;

	time_t sync_last_check;

	/* we've discovered there aren't enough permissions to modify mailbox */
	unsigned int backend_readonly:1;
	unsigned int move_to_memory:1;
};

void mail_storage_set_index_error(struct index_mailbox *ibox);

void index_storage_lock_notify(struct index_mailbox *ibox,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left);
void index_storage_lock_notify_reset(struct index_mailbox *ibox);

void index_storage_mailbox_alloc(struct index_mailbox *ibox, const char *name,
				 struct istream *input,
				 enum mailbox_flags flags,
				 const char *index_prefix);
int index_storage_mailbox_open(struct mailbox *box);
int index_storage_mailbox_enable(struct mailbox *box,
				 enum mailbox_feature feature);
void index_storage_mailbox_close(struct mailbox *box);
int index_storage_mailbox_update(struct mailbox *box,
				 const struct mailbox_update *update);

bool index_storage_is_readonly(struct mailbox *box);
bool index_storage_allow_new_keywords(struct mailbox *box);
bool index_storage_is_inconsistent(struct mailbox *box);

int index_keywords_create(struct mailbox *box, const char *const keywords[],
			  struct mail_keywords **keywords_r, bool skip_invalid);
struct mail_keywords *
index_keywords_create_from_indexes(struct mailbox *box,
				   const ARRAY_TYPE(keyword_indexes) *idx);
void index_keywords_ref(struct mail_keywords *keywords);
void index_keywords_unref(struct mail_keywords *keywords);
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
			      struct mailbox_sync_status *status_r);

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
bool index_storage_get_expunges(struct mailbox *box, uint64_t prev_modseq,
				const ARRAY_TYPE(seq_range) *uids_filter,
				ARRAY_TYPE(mailbox_expunge_rec) *expunges);

struct mailbox_header_lookup_ctx *
index_header_lookup_init(struct mailbox *box, const char *const headers[]);
void index_header_lookup_deinit(struct mailbox_header_lookup_ctx *ctx);

struct mail_search_context *
index_storage_search_init(struct mailbox_transaction_context *t,
			  struct mail_search_args *args,
			  const enum mail_sort_type *sort_program);
int index_storage_search_deinit(struct mail_search_context *ctx);
bool index_storage_search_next_nonblock(struct mail_search_context *ctx,
					struct mail *mail, bool *tryagain_r);
bool index_storage_search_next_update_seq(struct mail_search_context *ctx);

void index_transaction_set_max_modseq(struct mailbox_transaction_context *_t,
				      uint64_t max_modseq,
				      ARRAY_TYPE(seq_range) *seqs);

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags);
void index_transaction_init(struct index_transaction_context *it,
			    struct mailbox *box,
			    enum mailbox_transaction_flags flags);
int index_transaction_commit(struct mailbox_transaction_context *t,
			     struct mail_transaction_commit_changes *changes_r);
void index_transaction_rollback(struct mailbox_transaction_context *t);
void index_save_context_free(struct mail_save_context *ctx);

bool index_keyword_array_cmp(const ARRAY_TYPE(keyword_indexes) *k1,
			     const ARRAY_TYPE(keyword_indexes) *k2);

int index_list_create_missing_index_dir(struct mailbox_list *list,
					const char *name);

#endif
