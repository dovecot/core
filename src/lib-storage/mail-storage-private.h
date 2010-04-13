#ifndef MAIL_STORAGE_PRIVATE_H
#define MAIL_STORAGE_PRIVATE_H

#include "module-context.h"
#include "file-lock.h"
#include "mail-storage.h"
#include "mail-storage-hooks.h"
#include "mail-storage-settings.h"
#include "mail-index-private.h"

/* Block size when read()ing message header. */
#define MAIL_READ_HDR_BLOCK_SIZE (1024*4)
/* Block size when read()ing message (header and) body. */
#define MAIL_READ_FULL_BLOCK_SIZE (1024*8)

struct mail_storage_module_register {
	unsigned int id;
};

struct mail_module_register {
	unsigned int id;
};

struct mail_storage_vfuncs {
	const struct setting_parser_info *(*get_setting_parser_info)(void);

	struct mail_storage *(*alloc)(void);
	int (*create)(struct mail_storage *storage, struct mail_namespace *ns,
		      const char **error_r);
	void (*destroy)(struct mail_storage *storage);
	void (*add_list)(struct mail_storage *storage,
			 struct mailbox_list *list);

	void (*get_list_settings)(const struct mail_namespace *ns,
				  struct mailbox_list_settings *set);
	bool (*autodetect)(const struct mail_namespace *ns,
			   struct mailbox_list_settings *set);

	struct mailbox *(*mailbox_alloc)(struct mail_storage *storage,
					 struct mailbox_list *list,
					 const char *name,
					 enum mailbox_flags flags);
	int (*purge)(struct mail_storage *storage);
};

union mail_storage_module_context {
	struct mail_storage_vfuncs super;
	struct mail_storage_module_register *reg;
};

enum mail_storage_class_flags {
	/* mailboxes are files, not directories */
	MAIL_STORAGE_CLASS_FLAG_MAILBOX_IS_FILE	= 0x01,
	/* root_dir points to a unique directory */
	MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT	= 0x02,
	/* mailbox_open_stream() is supported */
	MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS	= 0x04
};

struct mail_storage {
	const char *name;
	enum mail_storage_class_flags class_flags;

        struct mail_storage_vfuncs v;

/* private: */
	pool_t pool;
	struct mail_storage *prev, *next;
	/* counting number of times mail_storage_create() has returned this
	   same storage. */
	int refcount;
	/* counting number of objects (e.g. mailbox) that have a pointer
	   to this storage. */
	int obj_refcount;
	const char *unique_root_dir;

	char *error_string;
	enum mail_error error;

        const struct mail_storage *storage_class;
	struct mail_user *user;
	const char *temp_path_prefix;
	const struct mail_storage_settings *set;

	enum mail_storage_flags flags;

	struct mail_storage_callbacks callbacks;
	void *callback_context;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY_DEFINE(module_contexts, union mail_storage_module_context *);
};

struct mailbox_vfuncs {
	bool (*is_readonly)(struct mailbox *box);
	bool (*allow_new_keywords)(struct mailbox *box);

	int (*enable)(struct mailbox *box, enum mailbox_feature features);
	int (*open)(struct mailbox *box);
	void (*close)(struct mailbox *box);
	void (*free)(struct mailbox *box);

	int (*create)(struct mailbox *box, const struct mailbox_update *update,
		      bool directory);
	int (*update)(struct mailbox *box, const struct mailbox_update *update);
	int (*delete)(struct mailbox *box);
	int (*rename)(struct mailbox *src, struct mailbox *dest,
		      bool rename_children);

	void (*get_status)(struct mailbox *box, enum mailbox_status_items items,
			   struct mailbox_status *status_r);
	int (*get_guid)(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE]);

	/* Lookup sync extension record and figure out if it mailbox has
	   changed since. Returns 1 = yes, 0 = no, -1 = error. */
	int (*list_index_has_changed)(struct mailbox *box,
				      struct mail_index_view *list_view,
				      uint32_t seq);
	/* Update the sync extension record. Returns 0 = ok, -1 = error. */
	int (*list_index_update_sync)(struct mailbox *box,
				      struct mail_index_transaction *trans,
				      uint32_t seq);

	struct mailbox_sync_context *
		(*sync_init)(struct mailbox *box,
			     enum mailbox_sync_flags flags);
	bool (*sync_next)(struct mailbox_sync_context *ctx,
			  struct mailbox_sync_rec *sync_rec_r);
	int (*sync_deinit)(struct mailbox_sync_context *ctx,
			   struct mailbox_sync_status *status_r);

	/* Called once for each expunge. Called one or more times for
	   flag/keyword changes. Once the sync is finished, called with
	   uid=0 and sync_type=0. */
	void (*sync_notify)(struct mailbox *box, uint32_t uid,
			    enum mailbox_sync_type sync_type);

	void (*notify_changes)(struct mailbox *box);

	struct mailbox_transaction_context *
		(*transaction_begin)(struct mailbox *box,
				     enum mailbox_transaction_flags flags);
	int (*transaction_commit)(struct mailbox_transaction_context *t,
				  struct mail_transaction_commit_changes *changes_r);
	void (*transaction_rollback)(struct mailbox_transaction_context *t);
	void (*transaction_set_max_modseq)(struct mailbox_transaction_context *t,
					   uint64_t max_modseq,
					   ARRAY_TYPE(seq_range) *seqs);

	int (*keywords_create)(struct mailbox *box,
			       const char *const keywords[],
			       struct mail_keywords **keywords_r,
			       bool skip_invalid);
	struct mail_keywords *
		(*keywords_create_from_indexes)(struct mailbox *box,
						const ARRAY_TYPE(keyword_indexes) *idx);
	void (*keywords_ref)(struct mail_keywords *keywords);
	void (*keywords_unref)(struct mail_keywords *keywords);
	bool (*keyword_is_valid)(struct mailbox *box, const char *keyword,
				 const char **error_r);

	void (*get_seq_range)(struct mailbox *box, uint32_t uid1, uint32_t uid2,
			      uint32_t *seq1_r, uint32_t *seq2_r);
	void (*get_uid_range)(struct mailbox *box,
			      const ARRAY_TYPE(seq_range) *seqs,
			      ARRAY_TYPE(seq_range) *uids);
	bool (*get_expunges)(struct mailbox *box, uint64_t prev_modseq,
			     const ARRAY_TYPE(seq_range) *uids_filter,
			     ARRAY_TYPE(mailbox_expunge_rec) *expunges);
	bool (*get_virtual_uid)(struct mailbox *box,
				const char *backend_mailbox,
				uint32_t backend_uidvalidity,
				uint32_t backend_uid, uint32_t *uid_r);
	void (*get_virtual_backend_boxes)(struct mailbox *box,
					  ARRAY_TYPE(mailboxes) *mailboxes,
					  bool only_with_msgs);
	void (*get_virtual_box_patterns)(struct mailbox *box,
				ARRAY_TYPE(mailbox_virtual_patterns) *includes,
				ARRAY_TYPE(mailbox_virtual_patterns) *excludes);

	struct mail *
		(*mail_alloc)(struct mailbox_transaction_context *t,
			      enum mail_fetch_field wanted_fields,
			      struct mailbox_header_lookup_ctx *wanted_headers);

	struct mailbox_header_lookup_ctx *
		(*header_lookup_init)(struct mailbox *box,
				      const char *const headers[]);
	void (*header_lookup_deinit)(struct mailbox_header_lookup_ctx *ctx);

	struct mail_search_context *
	(*search_init)(struct mailbox_transaction_context *t,
		       struct mail_search_args *args,
		       const enum mail_sort_type *sort_program);
	int (*search_deinit)(struct mail_search_context *ctx);
	bool (*search_next_nonblock)(struct mail_search_context *ctx,
				     struct mail *mail, bool *tryagain_r);
	/* Internal search function which updates ctx->seq */
	bool (*search_next_update_seq)(struct mail_search_context *ctx);

	struct mail_save_context *
		(*save_alloc)(struct mailbox_transaction_context *t);
	int (*save_begin)(struct mail_save_context *ctx, struct istream *input);
	int (*save_continue)(struct mail_save_context *ctx);
	int (*save_finish)(struct mail_save_context *ctx);
	void (*save_cancel)(struct mail_save_context *ctx);
	int (*copy)(struct mail_save_context *ctx, struct mail *mail);

	bool (*is_inconsistent)(struct mailbox *box);
};

union mailbox_module_context {
        struct mailbox_vfuncs super;
	struct mail_storage_module_register *reg;
};

struct mailbox {
	const char *name;
	struct mail_storage *storage;
	struct mailbox_list *list;

        struct mailbox_vfuncs v;
/* private: */
	pool_t pool;

	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_cache *cache;

	/* default vfuncs for new struct mails. */
	const struct mail_vfuncs *mail_vfuncs;

	/* mailbox's MAILBOX_LIST_PATH_TYPE_MAILBOX */
	const char *path;
	/* mailbox's virtual name (from mail_namespace_get_vname()) */
	const char *vname;
	struct istream *input;
	enum mailbox_flags flags;
	unsigned int transaction_count;
	enum mailbox_feature enabled_features;

	/* User's private flags if this is a shared mailbox */
	enum mail_flags private_flags_mask;

	/* mode and GID to use for newly created files/dirs */
	mode_t file_create_mode, dir_create_mode;
	gid_t file_create_gid;
	/* origin (e.g. path) where the file_create_gid was got from */
	const char *file_create_gid_origin;

	/* Mailbox notification settings: */
	unsigned int notify_min_interval;
	mailbox_notify_callback_t *notify_callback;
	void *notify_context;

	/* Saved search results */
	ARRAY_DEFINE(search_results, struct mail_search_result *);

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY_DEFINE(module_contexts, union mailbox_module_context *);

	/* When FAST open flag is used, the mailbox isn't actually opened until
	   it's synced for the first time. */
	unsigned int opened:1;
	/* Mailbox was deleted while we had it open. */
	unsigned int mailbox_deleted:1;
	/* we've discovered there aren't enough permissions to modify mailbox */
	unsigned int backend_readonly:1;
	/* Mailbox is being deleted */
	unsigned int deleting:1;
	/* TRUE if this is the INBOX */
	unsigned int inbox:1;
};

struct mail_vfuncs {
	void (*close)(struct mail *mail);
	void (*free)(struct mail *mail);
	void (*set_seq)(struct mail *mail, uint32_t seq);
	bool (*set_uid)(struct mail *mail, uint32_t uid);
	void (*set_uid_cache_updates)(struct mail *mail, bool set);

	enum mail_flags (*get_flags)(struct mail *mail);
	const char *const *(*get_keywords)(struct mail *mail);
	const ARRAY_TYPE(keyword_indexes) *
		(*get_keyword_indexes)(struct mail *mail);
	uint64_t (*get_modseq)(struct mail *mail);

	int (*get_parts)(struct mail *mail,
			 struct message_part **parts_r);
	int (*get_date)(struct mail *mail, time_t *date_r, int *timezone_r);
	int (*get_received_date)(struct mail *mail, time_t *date_r);
	int (*get_save_date)(struct mail *mail, time_t *date_r);
	int (*get_virtual_size)(struct mail *mail, uoff_t *size_r);
	int (*get_physical_size)(struct mail *mail, uoff_t *size_r);

	int (*get_first_header)(struct mail *mail, const char *field,
				bool decode_to_utf8, const char **value_r);
	int (*get_headers)(struct mail *mail, const char *field,
			   bool decode_to_utf8, const char *const **value_r);
	int (*get_header_stream)(struct mail *mail,
				 struct mailbox_header_lookup_ctx *headers,
				 struct istream **stream_r);
	int (*get_stream)(struct mail *mail, struct message_size *hdr_size,
			  struct message_size *body_size,
			  struct istream **stream_r);

	int (*get_special)(struct mail *mail, enum mail_fetch_field field,
			   const char **value_r);

	void (*update_flags)(struct mail *mail, enum modify_type modify_type,
			     enum mail_flags flags);
	void (*update_keywords)(struct mail *mail, enum modify_type modify_type,
				struct mail_keywords *keywords);
	void (*update_modseq)(struct mail *mail, uint64_t min_modseq);
	void (*update_uid)(struct mail *mail, uint32_t new_uid);
	void (*update_pop3_uidl)(struct mail *mail, const char *uidl);
	void (*expunge)(struct mail *mail);
	void (*set_cache_corrupted)(struct mail *mail,
				    enum mail_fetch_field field);

	struct index_mail *(*get_index_mail)(struct mail *mail);
};

union mail_module_context {
	struct mail_vfuncs super;
	struct mail_module_register *reg;
};

struct mail_private {
	struct mail mail;
	struct mail_vfuncs v;

	enum mail_fetch_field wanted_fields;
	struct mailbox_header_lookup_ctx *wanted_headers;

	pool_t pool;
	ARRAY_DEFINE(module_contexts, union mail_module_context *);

	/* these statistics are never reset by mail-storage API: */

	unsigned long stats_open_lookup_count;
	unsigned long stats_stat_lookup_count;
	unsigned long stats_fstat_lookup_count;
	/* number of files we've opened and read */
	unsigned long stats_files_read_count;
	/* number of bytes we've had to read from files */
	unsigned long long stats_files_read_bytes;
	/* number of cache lookup hits */
	unsigned long stats_cache_hit_count;

	/* Set to TRUE to update stats_* fields */
	unsigned int stats_track:1;
};

struct mailbox_list_context {
	struct mail_storage *storage;
	enum mailbox_list_flags flags;
	bool failed;
};

union mailbox_transaction_module_context {
	struct mail_storage_module_register *reg;
};

struct mailbox_transaction_context {
	struct mailbox *box;
	enum mailbox_transaction_flags flags;

	struct mail_index_transaction *itrans;
	/* view contains all changes done within this transaction */
	struct mail_index_view *view;

	struct mail_transaction_commit_changes *changes;
	ARRAY_DEFINE(module_contexts,
		     union mailbox_transaction_module_context *);

	struct mail_save_context *save_ctx;
};

union mail_search_module_context {
	struct mail_storage_module_register *reg;
};

struct mail_search_context {
	struct mailbox_transaction_context *transaction;

	struct mail_search_args *args;
	struct mail_search_sort_program *sort_program;

	/* if non-NULL, specifies that a search resulting is being updated.
	   this can be used as a search optimization: if searched message
	   already exists in search result, it's not necessary to check if
	   static data matches. */
	struct mail_search_result *update_result;
	/* add matches to these search results */
	ARRAY_DEFINE(results, struct mail_search_result *);

	uint32_t seq;
	uint32_t progress_cur, progress_max;

	ARRAY_DEFINE(module_contexts, union mail_search_module_context *);

	unsigned int seen_lost_data:1;
	unsigned int progress_hidden:1;
};

struct mail_save_context {
	struct mailbox_transaction_context *transaction;
	struct mail *dest_mail;

	enum mail_flags flags;
	struct mail_keywords *keywords;
	uint64_t min_modseq;

	time_t received_date, save_date;
	int received_tz_offset;

	uint32_t uid;
	char *guid, *pop3_uidl, *from_envelope;
	struct ostream *output;

	/* if non-zero, overrides the physical size that should be saved.
	   for example when using zlib plugin, this would contain the mail's
	   uncompressed size. */
	uoff_t saved_physical_size;

	/* we came here from mailbox_copy() */
	unsigned int copying:1;
};

struct mailbox_sync_context {
	struct mailbox *box;
};

struct mailbox_header_lookup_ctx {
	struct mailbox *box;
	const char *const *headers;
	int refcount;
};

/* Modules should use do "my_id = mail_storage_module_id++" and
   use objects' module_contexts[id] for their own purposes. */
extern struct mail_storage_module_register mail_storage_module_register;

/* Storage's module_id for mail_index. */
extern struct mail_module_register mail_module_register;

#define MAIL_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_storage_mail_index_module)
extern MODULE_CONTEXT_DEFINE(mail_storage_mail_index_module,
			     &mail_index_module_register);

void mail_storage_obj_ref(struct mail_storage *storage);
void mail_storage_obj_unref(struct mail_storage *storage);

/* Set error message in storage. Critical errors are logged with i_error(),
   but user sees only "internal error" message. */
void mail_storage_clear_error(struct mail_storage *storage);
void mail_storage_set_error(struct mail_storage *storage,
			    enum mail_error error, const char *string);
void mail_storage_set_critical(struct mail_storage *storage,
			       const char *fmt, ...) ATTR_FORMAT(2, 3);
void mail_storage_set_internal_error(struct mail_storage *storage);
void mail_storage_set_index_error(struct mailbox *box);
bool mail_storage_set_error_from_errno(struct mail_storage *storage);
void mail_storage_copy_list_error(struct mail_storage *storage,
				  struct mailbox_list *list);

int mail_set_aborted(struct mail *mail);
void mail_set_expunged(struct mail *mail);
void mailbox_set_deleted(struct mailbox *box);
void mailbox_refresh_permissions(struct mailbox *box);

/* Returns -1 if error, 0 if failed with EEXIST, 1 if ok */
int mailbox_create_fd(struct mailbox *box, const char *path, int flags,
		      int *fd_r);

#endif
