#ifndef MAIL_STORAGE_PRIVATE_H
#define MAIL_STORAGE_PRIVATE_H

#include "module-context.h"
#include "unichar.h"
#include "file-lock.h"
#include "mail-storage.h"
#include "mail-storage-hooks.h"
#include "mail-storage-settings.h"
#include "mailbox-attribute-private.h"
#include "mail-index-private.h"

struct file_lock;
struct file_create_settings;

/* Default prefix for indexes */
#define MAIL_INDEX_PREFIX "dovecot.index"

/* Block size when read()ing message header. */
#define MAIL_READ_HDR_BLOCK_SIZE (1024*4)
/* Block size when read()ing message (header and) body. */
#define MAIL_READ_FULL_BLOCK_SIZE IO_BLOCK_SIZE

#define MAIL_SHARED_STORAGE_NAME "shared"

enum mail_storage_list_index_rebuild_reason {
	/* Mailbox list index was found to be corrupted. */
	MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_CORRUPTED,
	/* Mailbox list index doesn't have INBOX in an inbox=yes namespace.
	   Rebuild is done to verify whether the user really is an empty new
	   user, or if an existing user's mailbox list index was lost. Because
	   this is called in non-error conditions, the callback shouldn't log
	   any errors or warnings if it didn't find any missing mailboxes. */
	MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_NO_INBOX,
	/* MAILBOX_SYNC_FLAG_FORCE_RESYNC is run. This is called only once
	   per list, so that doveadm force-resync '*' won't cause it to run for
	   every mailbox. */
	MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_FORCE_RESYNC,
};

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
					 const char *vname,
					 enum mailbox_flags flags);
	int (*purge)(struct mail_storage *storage);
	/* Called when mailbox list index rebuild is requested.
	   The callback should add any missing mailboxes to the list index.
	   Returns 0 on success, -1 on temporary failure that didn't properly
	   rebuild the index. */
	int (*list_index_rebuild)(struct mail_storage *storage,
				  enum mail_storage_list_index_rebuild_reason reason);
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
	MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS	= 0x04,
	/* never use quota for this storage (e.g. virtual mailboxes) */
	MAIL_STORAGE_CLASS_FLAG_NOQUOTA		= 0x08,
	/* Storage doesn't need a mail root directory */
	MAIL_STORAGE_CLASS_FLAG_NO_ROOT		= 0x10,
	/* Storage uses one file per message */
	MAIL_STORAGE_CLASS_FLAG_FILE_PER_MSG	= 0x20,
	/* Messages have GUIDs (always set mailbox_status.have_guids=TRUE) */
	MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS	= 0x40,
	/* mailbox_save_set_guid() works (always set
	   mailbox_status.have_save_guids=TRUE) */
	MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS	= 0x80,
	/* message content can be unstructured binary data
	   (e.g. zlib plugin is allowed to compress/decompress mails) */
	MAIL_STORAGE_CLASS_FLAG_BINARY_DATA	= 0x100,
	/* Message GUIDs can only be 128bit (always set
	   mailbox_status.have_only_guid128) */
	MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUID128 = 0x200,
	/* Storage deletes all files internally - mailbox list's
	   delete_mailbox() shouldn't delete anything itself. */
	MAIL_STORAGE_CLASS_FLAG_NO_LIST_DELETES	= 0x400,
	/* Storage supports stubs (used for caching purposes). */
	MAIL_STORAGE_CLASS_FLAG_STUBS = 0x800,
};

struct mail_binary_cache {
	struct timeout *to;
	struct mailbox *box;
	uint32_t uid;

	uoff_t orig_physical_pos;
	bool include_hdr;
	struct istream *input;
	uoff_t size;
};

struct mail_storage_error {
	char *error_string;
	enum mail_error error;
	char *last_internal_error;
	bool last_error_is_internal;
};

struct mail_storage {
	const char *name;
	enum mail_storage_class_flags class_flags;
	/* Fields that the storage backend can get by other means than parsing
	   the message header/body. For example the imapc backend can lookup
	   MAIL_FETCH_IMAP_BODYSTRUCTURE from the remote server. Adding fields
	   here avoids adding them to index_mail_data.access_part. */
	enum mail_fetch_field nonbody_access_fields;
	struct event_category *event_category;

        struct mail_storage_vfuncs v, *vlast;

/* private: */
	pool_t pool;
	struct mail_storage *prev, *next;
	/* counting number of times mail_storage_create() has returned this
	   same storage. */
	int refcount;
	/* counting number of objects (e.g. mailbox) that have a pointer
	   to this storage. */
	int obj_refcount;
	/* Linked list of all mailboxes in the storage */
	struct mailbox *mailboxes;
	/* A "root dir" to enable storage sharing.  It is only ever used for
	 * uniqueness checking (via strcmp) and never used as a path. */
	const char *unique_root_dir;

	/* Last error set in mail_storage_set_critical(). */
	char *last_internal_error;

	char *error_string;
	enum mail_error error;
	ARRAY(struct mail_storage_error) error_stack;
	struct event *event;

        const struct mail_storage *storage_class;
	struct mail_user *user;
	const char *temp_path_prefix;
	const struct mail_storage_settings *set;

	enum mail_storage_flags flags;

	struct mail_storage_callbacks callbacks;
	void *callback_context;

	struct mail_binary_cache binary_cache;
	/* Filled lazily by mailbox_attribute_*() when accessing shared
	   attributes. */
	struct dict *_shared_attr_dict;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY(union mail_storage_module_context *) module_contexts;

	/* Failed to create shared attribute dict, don't try again */
	bool shared_attr_dict_failed:1;
	bool last_error_is_internal:1;
};

struct mail_attachment_part {
	struct message_part *part;
	const char *content_type, *content_disposition;
};

struct virtual_mailbox_vfuncs {
	/* convert backend UIDs to virtual UIDs. if some backend UID doesn't
	   exist in mailbox, it's simply ignored */
	void (*get_virtual_uids)(struct mailbox *box,
				 struct mailbox *backend_mailbox,
				 const ARRAY_TYPE(seq_range) *backend_uids,
				 ARRAY_TYPE(seq_range) *virtual_uids_r);
	/* like get_virtual_uids(), but if a backend UID doesn't exist,
	   convert it to 0. */
	void (*get_virtual_uid_map)(struct mailbox *box,
				    struct mailbox *backend_mailbox,
				    const ARRAY_TYPE(seq_range) *backend_uids,
				    ARRAY_TYPE(uint32_t) *virtual_uids_r);
	void (*get_virtual_backend_boxes)(struct mailbox *box,
					  ARRAY_TYPE(mailboxes) *mailboxes,
					  bool only_with_msgs);
};

struct mailbox_vfuncs {
	bool (*is_readonly)(struct mailbox *box);

	int (*enable)(struct mailbox *box, enum mailbox_feature features);
	int (*exists)(struct mailbox *box, bool auto_boxes,
		      enum mailbox_existence *existence_r);
	int (*open)(struct mailbox *box);
	void (*close)(struct mailbox *box);
	void (*free)(struct mailbox *box);

	int (*create_box)(struct mailbox *box,
			  const struct mailbox_update *update, bool directory);
	int (*update_box)(struct mailbox *box,
			  const struct mailbox_update *update);
	int (*delete_box)(struct mailbox *box);
	int (*rename_box)(struct mailbox *src, struct mailbox *dest);

	int (*get_status)(struct mailbox *box, enum mailbox_status_items items,
			  struct mailbox_status *status_r);
	int (*get_metadata)(struct mailbox *box,
			    enum mailbox_metadata_items items,
			    struct mailbox_metadata *metadata_r);
	int (*set_subscribed)(struct mailbox *box, bool set);

	int (*attribute_set)(struct mailbox_transaction_context *t,
			     enum mail_attribute_type type_flags,
			     const char *key,
			     const struct mail_attribute_value *value);
	int (*attribute_get)(struct mailbox *box,
			     enum mail_attribute_type type_flags,
			     const char *key,
			     struct mail_attribute_value *value_r);
	struct mailbox_attribute_iter *
		(*attribute_iter_init)(struct mailbox *box,
				       enum mail_attribute_type type_flags,
				       const char *prefix);
	const char *(*attribute_iter_next)(struct mailbox_attribute_iter *iter);
	int (*attribute_iter_deinit)(struct mailbox_attribute_iter *iter);

	/* Lookup sync extension record and figure out if it mailbox has
	   changed since. Returns 1 = yes, 0 = no, -1 = error. if quick==TRUE,
	   return 1 if it's too costly to find out exactly. */
	int (*list_index_has_changed)(struct mailbox *box,
				      struct mail_index_view *list_view,
				      uint32_t seq, bool quick);
	/* Update the sync extension record. */
	void (*list_index_update_sync)(struct mailbox *box,
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
				     enum mailbox_transaction_flags flags,
				     const char *reason);
	int (*transaction_commit)(struct mailbox_transaction_context *t,
				  struct mail_transaction_commit_changes *changes_r);
	void (*transaction_rollback)(struct mailbox_transaction_context *t);

	enum mail_flags (*get_private_flags_mask)(struct mailbox *box);

	struct mail *
		(*mail_alloc)(struct mailbox_transaction_context *t,
			      enum mail_fetch_field wanted_fields,
			      struct mailbox_header_lookup_ctx *wanted_headers);

	struct mail_search_context *
	(*search_init)(struct mailbox_transaction_context *t,
		       struct mail_search_args *args,
		       const enum mail_sort_type *sort_program,
		       enum mail_fetch_field wanted_fields,
		       struct mailbox_header_lookup_ctx *wanted_headers);
	int (*search_deinit)(struct mail_search_context *ctx);
	bool (*search_next_nonblock)(struct mail_search_context *ctx,
				     struct mail **mail_r, bool *tryagain_r);
	/* Internal search function which updates ctx->seq */
	bool (*search_next_update_seq)(struct mail_search_context *ctx);

	struct mail_save_context *
		(*save_alloc)(struct mailbox_transaction_context *t);
	int (*save_begin)(struct mail_save_context *ctx, struct istream *input);
	int (*save_continue)(struct mail_save_context *ctx);
	int (*save_finish)(struct mail_save_context *ctx);
	void (*save_cancel)(struct mail_save_context *ctx);
	int (*copy)(struct mail_save_context *ctx, struct mail *mail);

	/* Called during transaction commit/rollback if saving was done */
	int (*transaction_save_commit_pre)(struct mail_save_context *save_ctx);
	void (*transaction_save_commit_post)
		(struct mail_save_context *save_ctx,
		 struct mail_index_transaction_commit_result *result_r);
	void (*transaction_save_rollback)(struct mail_save_context *save_ctx);

	bool (*is_inconsistent)(struct mailbox *box);
};

union mailbox_module_context {
        struct mailbox_vfuncs super;
	struct mail_storage_module_register *reg;
};

struct mail_msgpart_partial_cache {
	uint32_t uid;
	uoff_t physical_start;
	uoff_t physical_pos, virtual_pos;
};

struct mailbox_index_vsize {
	uint64_t vsize;
	uint32_t highest_uid;
	uint32_t message_count;
};

struct mailbox_index_pop3_uidl {
	uint32_t max_uid_with_pop3_uidl;
};

struct mailbox_index_first_saved {
	uint32_t uid;
	uint32_t timestamp;
};

struct mailbox {
	const char *name;
	/* mailbox's virtual name (from mail_namespace_get_vname()) */
	const char *vname;
	struct mail_storage *storage;
	struct mailbox_list *list;
	struct event *event;

	struct mailbox_vfuncs v, *vlast;
	/* virtual mailboxes: */
	const struct virtual_mailbox_vfuncs *virtual_vfuncs;
/* private: */
	pool_t pool, metadata_pool;
	/* Linked list of all mailboxes in this storage */
	struct mailbox *prev, *next;

	/* these won't be set until mailbox is opened: */
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_cache *cache;
	/* Private per-user index/view for shared mailboxes. These are synced
	   against the primary index and used to store per-user flags.
	   These are non-NULL only when mailbox has per-user flags. */
	struct mail_index *index_pvt;
	struct mail_index_view *view_pvt;
	/* Filled lazily by mailbox_get_permissions() */
	struct mailbox_permissions _perm;
	/* Filled lazily when mailbox is opened, use mailbox_get_path()
	   to access it */
	const char *_path;
	/* Filled lazily when mailbox is opened, use mailbox_get_index_path()
	   to access it */
	const char *_index_path;
	/* Reason for why mailbox is being accessed or NULL if unknown. */
	const char *reason;

	/* default vfuncs for new struct mails. */
	const struct mail_vfuncs *mail_vfuncs;
	/* Mailbox settings, or NULL if defaults */
	const struct mailbox_settings *set;

	/* If non-zero, fail mailbox_open() with this error. mailbox_alloc()
	   can set this to force open to fail. */
	enum mail_error open_error;

	struct istream *input;
	const char *index_prefix;
	enum mailbox_flags flags;
	unsigned int transaction_count;
	unsigned int attribute_iter_count;
	enum mailbox_feature enabled_features;
	struct mail_msgpart_partial_cache partial_cache;
	uint32_t vsize_hdr_ext_id;
	uint32_t pop3_uidl_hdr_ext_id;
	uint32_t box_name_hdr_ext_id;
	uint32_t box_last_rename_stamp_ext_id;
	uint32_t mail_vsize_ext_id;

	/* MAIL_RECENT flags handling */
	ARRAY_TYPE(seq_range) recent_flags;
	uint32_t recent_flags_prev_uid;
	uint32_t recent_flags_count;

	struct mail_index_view *tmp_sync_view;

	/* Mailbox notification settings: */
	mailbox_notify_callback_t *notify_callback;
	void *notify_context;
	struct timeout *to_notify, *to_notify_delay;
	struct mailbox_notify_file *notify_files;

	/* Increased by one for each new struct mailbox. */
	unsigned int generation_sequence;

	/* Saved search results */
	ARRAY(struct mail_search_result *) search_results;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY(union mailbox_module_context *) module_contexts;

	/* When FAST open flag is used, the mailbox isn't actually opened until
	   it's synced for the first time. */
	bool opened:1;
	/* Mailbox was deleted while we had it open. */
	bool mailbox_deleted:1;
	/* Mailbox is being created */
	bool creating:1;
	/* Mailbox is being deleted */
	bool deleting:1;
	/* Mailbox is being undeleted */
	bool mailbox_undeleting:1;
	/* Don't use MAIL_INDEX_SYNC_FLAG_DELETING_INDEX for sync flag */
	bool delete_sync_check:1;
	/* Delete mailbox only if it's empty */
	bool deleting_must_be_empty:1;
	/* The backend wants to skip checking if there are 0 messages before
	   calling mailbox_list.delete_mailbox() */
	bool delete_skip_empty_check:1;
	/* Mailbox was already marked as deleted within this allocation. */
	bool marked_deleted:1;
	/* TRUE if this is an INBOX for this user */
	bool inbox_user:1;
	/* TRUE if this is an INBOX for this namespace (user or shared) */
	bool inbox_any:1;
	/* When copying to this mailbox, require that mailbox_copy() uses
	   mailbox_save_*() to actually save a new physical copy rather than
	   simply incrementing a reference count (e.g. via hard link) */
	bool disable_reflink_copy_to:1;
	/* Don't allow creating any new keywords */
	bool disallow_new_keywords:1;
	/* Mailbox has been synced at least once */
	bool synced:1;
	/* Updating cache file is disabled */
	bool mail_cache_disabled:1;
	/* Update first_saved field to mailbox list index. */
	bool update_first_saved:1;
	/* mailbox_verify_create_name() only checks for mailbox_verify_name() */
	bool skip_create_name_restrictions:1;
	/* Using LAYOUT=index and mailbox is being opened with a corrupted
	   mailbox name. Try to revert to the previously known good name. */
	bool corrupted_mailbox_name:1;
};

struct mail_vfuncs {
	void (*close)(struct mail *mail);
	void (*free)(struct mail *mail);
	void (*set_seq)(struct mail *mail, uint32_t seq, bool saving);
	bool (*set_uid)(struct mail *mail, uint32_t uid);
	void (*set_uid_cache_updates)(struct mail *mail, bool set);
	bool (*prefetch)(struct mail *mail);
	void (*precache)(struct mail *mail);
	void (*add_temp_wanted_fields)(struct mail *mail,
				       enum mail_fetch_field fields,
				       struct mailbox_header_lookup_ctx *headers);

	enum mail_flags (*get_flags)(struct mail *mail);
	const char *const *(*get_keywords)(struct mail *mail);
	const ARRAY_TYPE(keyword_indexes) *
		(*get_keyword_indexes)(struct mail *mail);
	uint64_t (*get_modseq)(struct mail *mail);
	uint64_t (*get_pvt_modseq)(struct mail *mail);

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
	int (*get_stream)(struct mail *mail, bool get_body,
			  struct message_size *hdr_size,
			  struct message_size *body_size,
			  struct istream **stream_r);
	int (*get_binary_stream)(struct mail *mail,
				 const struct message_part *part,
				 bool include_hdr, uoff_t *size_r,
				 unsigned int *lines_r, bool *binary_r,
				 struct istream **stream_r);

	int (*get_special)(struct mail *mail, enum mail_fetch_field field,
			   const char **value_r);
	int (*get_backend_mail)(struct mail *mail, struct mail **real_mail_r);

	void (*update_flags)(struct mail *mail, enum modify_type modify_type,
			     enum mail_flags flags);
	void (*update_keywords)(struct mail *mail, enum modify_type modify_type,
				struct mail_keywords *keywords);
	void (*update_modseq)(struct mail *mail, uint64_t min_modseq);
	void (*update_pvt_modseq)(struct mail *mail, uint64_t min_pvt_modseq);
	void (*update_pop3_uidl)(struct mail *mail, const char *uidl);
	void (*expunge)(struct mail *mail);
	void (*set_cache_corrupted)(struct mail *mail,
				    enum mail_fetch_field field,
				    const char *reason);
	int (*istream_opened)(struct mail *mail, struct istream **input);
};

union mail_module_context {
	struct mail_vfuncs super;
	struct mail_module_register *reg;
};

struct mail_private {
	struct mail mail;
	struct mail_vfuncs v, *vlast;
	/* normally NULL, but in case this is a "backend mail" for a mail
	   created by virtual storage, this points back to the original virtual
	   mail. at least mailbox_copy() bypasses the virtual storage, so this
	   allows mail_log plugin to log the copy operation using the original
	   mailbox name. */
	struct mail *vmail;

	uint32_t seq_pvt;

	/* initial wanted fields/headers, set by mail_alloc(): */
	enum mail_fetch_field wanted_fields;
	struct mailbox_header_lookup_ctx *wanted_headers;

	pool_t pool, data_pool;
	ARRAY(union mail_module_context *) module_contexts;

	const char *get_stream_reason;

	bool autoexpunged:1;
	/* mail created by mailbox_search_*() */
	bool search_mail:1;
};

struct mailbox_list_context {
	struct mail_storage *storage;
	enum mailbox_list_flags flags;
	bool failed;
};

union mailbox_transaction_module_context {
	struct mail_storage_module_register *reg;
};

struct mailbox_transaction_stats {
	unsigned long open_lookup_count;
	unsigned long stat_lookup_count;
	unsigned long fstat_lookup_count;
	/* number of files we've opened and read */
	unsigned long files_read_count;
	/* number of bytes we've had to read from files */
	unsigned long long files_read_bytes;
	/* number of cache lookup hits */
	unsigned long cache_hit_count;
};

struct mail_save_private_changes {
	/* first saved mail is 0, second is 1, etc. we'll map these to UIDs
	   using struct mail_transaction_commit_changes. */
	unsigned int mailnum;
	enum mail_flags flags;
};

struct mailbox_transaction_context {
	struct mailbox *box;
	enum mailbox_transaction_flags flags;
	char *reason;

	union mail_index_transaction_module_context module_ctx;
	struct mail_index_transaction_vfuncs super;
	int mail_ref_count;

	struct mail_index_transaction *itrans;
	struct dict_transaction_context *attr_pvt_trans, *attr_shared_trans;
	/* view contains all changes done within this transaction */
	struct mail_index_view *view;

	/* for private index updates: */
	struct mail_index_transaction *itrans_pvt;
	struct mail_index_view *view_pvt;

	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;

	struct mail_transaction_commit_changes *changes;
	ARRAY(union mailbox_transaction_module_context *) module_contexts;

	uint32_t prev_pop3_uidl_tracking_seq;
	uint32_t highest_pop3_uidl_uid;

	struct mail_save_context *save_ctx;
	/* number of mails saved/copied within this transaction. */
	unsigned int save_count;
	/* List of private flags added with save/copy. These are added to the
	   private index after committing the mails to the shared index. */
	ARRAY(struct mail_save_private_changes) pvt_saves;

	/* these statistics are never reset by mail-storage API: */
	struct mailbox_transaction_stats stats;
	/* Set to TRUE to update stats_* fields */
	bool stats_track:1;
};

union mail_search_module_context {
	struct mail_storage_module_register *reg;
};

struct mail_search_context {
	struct mailbox_transaction_context *transaction;

	struct mail_search_args *args;
	struct mail_search_sort_program *sort_program;
	enum mail_fetch_field wanted_fields;
	struct mailbox_header_lookup_ctx *wanted_headers;
	normalizer_func_t *normalizer;

	/* if non-NULL, specifies that a search resulting is being updated.
	   this can be used as a search optimization: if searched message
	   already exists in search result, it's not necessary to check if
	   static data matches. */
	struct mail_search_result *update_result;
	/* add matches to these search results */
	ARRAY(struct mail_search_result *) results;

	uint32_t seq;
	uint32_t progress_cur, progress_max;

	ARRAY(struct mail *) mails;
	unsigned int unused_mail_idx;
	unsigned int max_mails;

	ARRAY(union mail_search_module_context *) module_contexts;

	bool seen_lost_data:1;
	bool progress_hidden:1;
};

struct mail_save_data {
	enum mail_flags flags;
	enum mail_flags pvt_flags;
	struct mail_keywords *keywords;
	uint64_t min_modseq;

	time_t received_date, save_date;
	int received_tz_offset;

	uint32_t uid, stub_seq;
	char *guid, *pop3_uidl, *from_envelope;
	uint32_t pop3_order;

	struct ostream *output;
	struct mail_save_attachment *attach;
};

struct mail_save_context {
	struct mailbox_transaction_context *transaction;
	struct mail *dest_mail;
	/* Set during mailbox_copy(). This is useful when copying is
	   implemented via save, and the save_*() methods want to access the
	   source mail. */
	struct mail *copy_src_mail;

	/* data that changes for each saved mail */
	struct mail_save_data data;

	/* returns TRUE if message part is an attachment. */
	bool (*part_is_attachment)(struct mail_save_context *ctx,
				   const struct mail_attachment_part *part);

	/* mailbox_save_alloc() called, but finish/cancel not.
	   the same context is usually returned by the backends for reuse. */
	bool unfinished:1;
	/* mailbox_save_finish() or mailbox_copy() is being called. */
	bool finishing:1;
	/* mail was copied or moved using saving (requires:
	   copying_or_moving==TRUE). */
	bool copying_via_save:1;
	/* mail is being saved, not copied. However, this is set also with
	   mailbox_save_using_mail() and then copying_or_moving==TRUE. */
	bool saving:1;
	/* mail is being moved - ignore quota (requires:
	   copying_or_moving==TRUE && saving==FALSE). */
	bool moving:1;
	/* mail is being copied or moved. However, this is set also with
	   mailbox_save_using_mail() and then saving==TRUE. */
	bool copying_or_moving:1;
};

struct mailbox_sync_context {
	struct mailbox *box;
	enum mailbox_sync_flags flags;
	bool open_failed;
};

struct mailbox_header_lookup_ctx {
	struct mailbox *box;
	pool_t pool;
	int refcount;

	unsigned int count;
	const char *const *name;
	unsigned int *idx;
};

/* Modules should use do "my_id = mail_storage_module_id++" and
   use objects' module_contexts[id] for their own purposes. */
extern struct mail_storage_module_register mail_storage_module_register;

/* Storage's module_id for mail_index. */
extern struct mail_module_register mail_module_register;

extern struct event_category event_category_storage;
extern struct event_category event_category_mailbox;
extern struct event_category event_category_mail;

#define MAIL_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_storage_mail_index_module)
#define MAIL_STORAGE_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_storage_mail_index_module)
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
void mailbox_set_critical(struct mailbox *box,
			  const char *fmt, ...) ATTR_FORMAT(2, 3);
void mail_set_critical(struct mail *mail,
		       const char *fmt, ...) ATTR_FORMAT(2, 3);
void mail_storage_set_internal_error(struct mail_storage *storage);
void mailbox_set_index_error(struct mailbox *box);
void mail_storage_set_index_error(struct mail_storage *storage,
				  struct mail_index *index);
bool mail_storage_set_error_from_errno(struct mail_storage *storage);
void mail_storage_copy_list_error(struct mail_storage *storage,
				  struct mailbox_list *list);
void mail_storage_copy_error(struct mail_storage *dest,
			     struct mail_storage *src);
/* set record in mail cache corrupted */
void mail_set_mail_cache_corrupted(struct mail *mail, const char *fmt, ...)
	ATTR_FORMAT(2, 3);

/* Indicate mail being expunged by autoexpunge */
void mail_autoexpunge(struct mail *mail);

/* Returns TRUE if everything should already be in memory after this call
   or if prefetching is not supported, i.e. the caller shouldn't do more
   prefetching before this message is handled. */
bool mail_prefetch(struct mail *mail);
void mail_set_aborted(struct mail *mail);
void mail_set_expunged(struct mail *mail);
void mail_set_seq_saving(struct mail *mail, uint32_t seq);
/* Returns true IF and only IF the mail has EITHER one of the
   attachment keywords set. If it has both, or none, it will return FALSE. */
bool mail_has_attachment_keywords(struct mail *mail);
/* Sets attachment keywords. Returns -1 on error, 0 when no attachment(s) found,
   and 1 if attachment was found. */
int mail_set_attachment_keywords(struct mail *mail);

void mailbox_set_deleted(struct mailbox *box);
int mailbox_mark_index_deleted(struct mailbox *box, bool del);
/* Easy wrapper for getting mailbox's MAILBOX_LIST_PATH_TYPE_MAILBOX.
   The mailbox must already be opened and the caller must know that the
   storage has mailbox files (i.e. NULL/empty path is never returned). */
const char *mailbox_get_path(struct mailbox *box) ATTR_PURE;
/* Similar to mailbox_get_path() but for MAILBOX_LIST_PATH_TYPE_INDEX. */
const char *mailbox_get_index_path(struct mailbox *box) ATTR_PURE;
/* Wrapper to mailbox_list_get_path() */
int mailbox_get_path_to(struct mailbox *box, enum mailbox_list_path_type type,
			const char **path_r);
/* Get mailbox permissions. */
const struct mailbox_permissions *mailbox_get_permissions(struct mailbox *box);
/* Force permissions to be refreshed on next lookup */
void mailbox_refresh_permissions(struct mailbox *box);

/* Open private index files for mailbox. Returns 1 if opened, 0 if there
   are no private indexes (or flags) in this mailbox, -1 if error. */
int mailbox_open_index_pvt(struct mailbox *box);
/* Create path's directory with proper permissions. The root directory is also
   created if necessary. Returns 1 if created, 0 if it already existed,
   -1 if error. */
int mailbox_mkdir(struct mailbox *box, const char *path,
		  enum mailbox_list_path_type type);
/* Create a non-mailbox type directory for mailbox if it's missing (e.g. index).
   Optimized for case where the directory usually exists. */
int mailbox_create_missing_dir(struct mailbox *box,
			       enum mailbox_list_path_type type);
/* Returns TRUE if mailbox is autocreated. */
bool mailbox_is_autocreated(struct mailbox *box);
/* Returns TRUE if mailbox is autosubscribed. */
bool mailbox_is_autosubscribed(struct mailbox *box);

/* Returns -1 if error, 0 if failed with EEXIST, 1 if ok */
int mailbox_create_fd(struct mailbox *box, const char *path, int flags,
		      int *fd_r);
/* Create a lock file with the given path and settings. If it succeeds,
   returns 1 and lock_r, which needs to be freed once finished with the lock.
   If lock_set->lock_timeout_secs is reached, returns 0 and error_r. Returns
   -1 and sets error_r on other errors. */
int mail_storage_lock_create(const char *lock_path,
			     const struct file_create_settings *lock_set,
			     const struct mail_storage_settings *mail_set,
			     struct file_lock **lock_r, const char **error_r);
/* Create a lock file to the mailbox with the given filename. Returns the same
   as mail_storage_lock_create(). */
int mailbox_lock_file_create(struct mailbox *box, const char *lock_fname,
			     unsigned int lock_secs, struct file_lock **lock_r,
			     const char **error_r);
unsigned int mail_storage_get_lock_timeout(struct mail_storage *storage,
					   unsigned int secs);
void mail_storage_free_binary_cache(struct mail_storage *storage);

enum mail_index_open_flags
mail_storage_settings_to_index_flags(const struct mail_storage_settings *set);
void mailbox_save_context_deinit(struct mail_save_context *ctx);

/* for unit testing */
int mailbox_verify_name(struct mailbox *box);

#endif
