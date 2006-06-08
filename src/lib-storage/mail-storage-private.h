#ifndef __MAIL_STORAGE_PRIVATE_H
#define __MAIL_STORAGE_PRIVATE_H

#include "mail-storage.h"

/* Some error strings that should be used everywhere to avoid
   permissions checks from revealing mailbox's existence */
#define MAIL_STORAGE_ERR_MAILBOX_NOT_FOUND "Mailbox doesn't exist: %s"
#define MAIL_STORAGE_ERR_NO_PERMISSION "Permission denied"

/* Modules should use do "my_id = mail_storage_module_id++" and
   use objects' module_contexts[id] for their own purposes. */
extern unsigned int mail_storage_module_id;

struct mail_storage_vfuncs {
	struct mail_storage *
		(*create)(const char *data, const char *user,
			  enum mail_storage_flags flags,
			  enum mail_storage_lock_method lock_method);
	void (*destroy)(struct mail_storage *storage);

	bool (*autodetect)(const char *data, enum mail_storage_flags flags);

	void (*set_callbacks)(struct mail_storage *storage,
			      struct mail_storage_callbacks *callbacks,
			      void *context);

	const char *(*get_mailbox_path)(struct mail_storage *storage,
					const char *name, bool *is_file_r);
	const char *(*get_mailbox_control_dir)(struct mail_storage *storage,
					       const char *name);

	struct mailbox *(*mailbox_open)(struct mail_storage *storage,
					const char *name,
					struct istream *input,
					enum mailbox_open_flags flags);

	int (*mailbox_create)(struct mail_storage *storage, const char *name,
			      bool directory);
	int (*mailbox_delete)(struct mail_storage *storage, const char *name);
	int (*mailbox_rename)(struct mail_storage *storage, const char *oldname,
			      const char *newname);

	struct mailbox_list_context *
		(*mailbox_list_init)(struct mail_storage *storage,
				     const char *ref, const char *mask,
				     enum mailbox_list_flags flags);
	struct mailbox_list *
		(*mailbox_list_next)(struct mailbox_list_context *ctx);
	int (*mailbox_list_deinit)(struct mailbox_list_context *ctx);

	int (*set_subscribed)(struct mail_storage *storage,
			      const char *name, bool set);

	int (*get_mailbox_name_status)(struct mail_storage *storage,
				       const char *name,
				       enum mailbox_name_status *status);

	const char *(*get_last_error)(struct mail_storage *storage,
				      bool *syntax_error_r,
				      bool *temporary_error_r);
};

struct mail_storage {
	char *name;
	char hierarchy_sep;

        struct mail_storage_vfuncs v;

/* private: */
	pool_t pool;

	char *error;
	enum mail_storage_flags flags;
        enum mail_storage_lock_method lock_method;

	/* Module-specific contexts. See mail_storage_module_id. */
	array_t ARRAY_DEFINE(module_contexts, void);

	/* IMAP: Give a BAD reply instead of NO */
	unsigned int syntax_error:1;
	/* Internal temporary error, as opposed to visible user errors like
	   "permission denied" or "out of disk space" */
	unsigned int temporary_error:1;
};

struct mailbox_vfuncs {
	bool (*is_readonly)(struct mailbox *box);
	bool (*allow_new_keywords)(struct mailbox *box);

	int (*close)(struct mailbox *box);

	int (*get_status)(struct mailbox *box, enum mailbox_status_items items,
			  struct mailbox_status *status);

	struct mailbox_sync_context *
		(*sync_init)(struct mailbox *box,
			     enum mailbox_sync_flags flags);
	int (*sync_next)(struct mailbox_sync_context *ctx,
			 struct mailbox_sync_rec *sync_rec_r);
	int (*sync_deinit)(struct mailbox_sync_context *ctx,
			   struct mailbox_status *status_r);

	void (*notify_changes)(struct mailbox *box, unsigned int min_interval,
			       mailbox_notify_callback_t *callback,
			       void *context);

	struct mailbox_transaction_context *
		(*transaction_begin)(struct mailbox *box,
				     enum mailbox_transaction_flags flags);
	int (*transaction_commit)(struct mailbox_transaction_context *t,
				  enum mailbox_sync_flags flags);
	void (*transaction_rollback)(struct mailbox_transaction_context *t);

	struct mail_keywords *
		(*keywords_create)(struct mailbox_transaction_context *t,
				   const char *const keywords[]);
	void (*keywords_free)(struct mailbox_transaction_context *t,
			      struct mail_keywords *keywords);

	int (*get_uids)(struct mailbox *box, uint32_t uid1, uint32_t uid2,
			uint32_t *seq1_r, uint32_t *seq2_r);

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
		       const char *charset, struct mail_search_arg *args,
		       const enum mail_sort_type *sort_program);
	int (*search_deinit)(struct mail_search_context *ctx);
	int (*search_next)(struct mail_search_context *ctx, struct mail *mail);
	/* Internal search function which updates ctx->seq */
	int (*search_next_update_seq)(struct mail_search_context *ctx);

	int (*save_init)(struct mailbox_transaction_context *t,
			 enum mail_flags flags,
			 struct mail_keywords *keywords,
			 time_t received_date, int timezone_offset,
			 const char *from_envelope, struct istream *input,
			 struct mail *dest_mail,
			 struct mail_save_context **ctx_r);
	int (*save_continue)(struct mail_save_context *ctx);
	int (*save_finish)(struct mail_save_context *ctx);
	void (*save_cancel)(struct mail_save_context *ctx);

	int (*copy)(struct mailbox_transaction_context *t, struct mail *mail,
		    enum mail_flags flags, struct mail_keywords *keywords,
		    struct mail *dest_mail);

	bool (*is_inconsistent)(struct mailbox *box);
};

struct mailbox {
	char *name;
	struct mail_storage *storage;

        struct mailbox_vfuncs v;
/* private: */
	pool_t pool;

	/* Module-specific contexts. See mail_storage_module_id. */
	array_t ARRAY_DEFINE(module_contexts, void);
};

struct mail_vfuncs {
	void (*free)(struct mail *mail);
	int (*set_seq)(struct mail *mail, uint32_t seq);
	int (*set_uid)(struct mail *mail, uint32_t uid);

	enum mail_flags (*get_flags)(struct mail *mail);
	const char *const *(*get_keywords)(struct mail *mail);
	const struct message_part *(*get_parts)(struct mail *mail);

	time_t (*get_received_date)(struct mail *mail);
	time_t (*get_date)(struct mail *mail, int *timezone);
	uoff_t (*get_virtual_size)(struct mail *mail);
	uoff_t (*get_physical_size)(struct mail *mail);

	const char *(*get_first_header)(struct mail *mail, const char *field);
	const char *const *(*get_headers)(struct mail *mail, const char *field);
	struct istream *
		(*get_header_stream)(struct mail *mail,
				     struct mailbox_header_lookup_ctx *headers);
	struct istream *(*get_stream)(struct mail *mail,
				      struct message_size *hdr_size,
				      struct message_size *body_size);

	const char *(*get_special)(struct mail *mail,
				   enum mail_fetch_field field);

	int (*update_flags)(struct mail *mail, enum modify_type modify_type,
			    enum mail_flags flags);
	int (*update_keywords)(struct mail *mail, enum modify_type modify_type,
			       struct mail_keywords *keywords);

	int (*expunge)(struct mail *mail);
};

struct mail_private {
	struct mail mail;
	struct mail_vfuncs v;

	pool_t pool;
	array_t ARRAY_DEFINE(module_contexts, void);
};

struct mailbox_list_context {
	struct mail_storage *storage;
	enum mailbox_list_flags flags;
	bool failed;
};

struct mailbox_transaction_context {
	struct mailbox *box;
	array_t ARRAY_DEFINE(module_contexts, void);
};

struct mail_search_context {
	struct mailbox_transaction_context *transaction;
	uint32_t seq;
};

struct mail_save_context {
	struct mailbox_transaction_context *transaction;
	struct mail *dest_mail;
};

struct mailbox_sync_context {
	struct mailbox *box;
};

struct mailbox_header_lookup_ctx {
	struct mailbox *box;
};

/* Set error message in storage. Critical errors are logged with i_error(),
   but user sees only "internal error" message. */
void mail_storage_clear_error(struct mail_storage *storage);
void mail_storage_set_error(struct mail_storage *storage,
			    const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_syntax_error(struct mail_storage *storage,
				   const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_critical(struct mail_storage *storage,
			       const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_internal_error(struct mail_storage *storage);

const char *mail_storage_class_get_last_error(struct mail_storage *storage,
					      bool *syntax_error_r);

#endif
