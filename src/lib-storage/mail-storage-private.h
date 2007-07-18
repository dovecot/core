#ifndef __MAIL_STORAGE_PRIVATE_H
#define __MAIL_STORAGE_PRIVATE_H

#include "module-context.h"
#include "file-lock.h"
#include "mail-storage.h"
#include "mail-index-private.h"

/* Called after mail storage has been created */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);
/* Called after mailbox has been opened */
extern void (*hook_mailbox_opened)(struct mailbox *box);

struct mail_storage_module_register {
	unsigned int id;
};

struct mail_module_register {
	unsigned int id;
};

struct mail_storage_vfuncs {
	void (*class_init)(void);
	void (*class_deinit)(void);

	struct mail_storage *(*alloc)(void);
	int (*create)(struct mail_storage *storage, const char *data,
		      const char **error_r);
	void (*destroy)(struct mail_storage *storage);

	bool (*autodetect)(const char *data, enum mail_storage_flags flags);

	struct mailbox *(*mailbox_open)(struct mail_storage *storage,
					const char *name,
					struct istream *input,
					enum mailbox_open_flags flags);

	int (*mailbox_create)(struct mail_storage *storage, const char *name,
			      bool directory);
};

union mail_storage_module_context {
	struct mail_storage_vfuncs super;
	struct mail_storage_module_register *reg;
};

struct mail_storage {
	const char *name;
	bool mailbox_is_file;

        struct mail_storage_vfuncs v;

/* private: */
	pool_t pool;

	char *error_string;
	enum mail_error error;

	struct mail_namespace *ns;
	struct mailbox_list *list;

	const char *user; /* name of user accessing the storage */
	enum mail_storage_flags flags;
        enum file_lock_method lock_method;

	struct mail_storage_callbacks *callbacks;
	void *callback_context;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY_DEFINE(module_contexts, union mail_storage_module_context *);
};

struct mailbox_vfuncs {
	bool (*is_readonly)(struct mailbox *box);
	bool (*allow_new_keywords)(struct mailbox *box);

	int (*close)(struct mailbox *box);

	int (*get_status)(struct mailbox *box, enum mailbox_status_items items,
			  struct mailbox_status *status);

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
	int (*sync_next)(struct mailbox_sync_context *ctx,
			 struct mailbox_sync_rec *sync_rec_r);
	int (*sync_deinit)(struct mailbox_sync_context *ctx,
			   enum mailbox_status_items status_items,
			   struct mailbox_status *status_r);

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
				  enum mailbox_sync_flags flags,
				  uint32_t *first_saved_uid_r,
				  uint32_t *last_saved_uid_r);
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
	int (*search_next_nonblock)(struct mail_search_context *ctx,
				    struct mail *mail, bool *tryagain_r);
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

union mailbox_module_context {
        struct mailbox_vfuncs super;
	struct mail_storage_module_register *reg;
};

struct mailbox {
	char *name;
	struct mail_storage *storage;

        struct mailbox_vfuncs v;
/* private: */
	pool_t pool;

	unsigned int transaction_count;

	/* User's private flags if this is a shared mailbox */
	enum mail_flags private_flags_mask;

	/* Mailbox notification settings: */
	unsigned int notify_min_interval;
	mailbox_notify_callback_t *notify_callback;
	void *notify_context;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY_DEFINE(module_contexts, union mailbox_module_context *);

	/* When FAST open flag is used, the mailbox isn't actually opened until
	   it's synced for the first time. */
	unsigned int opened:1;
};

struct mail_vfuncs {
	void (*free)(struct mail *mail);
	int (*set_seq)(struct mail *mail, uint32_t seq);
	int (*set_uid)(struct mail *mail, uint32_t uid);

	enum mail_flags (*get_flags)(struct mail *mail);
	const char *const *(*get_keywords)(struct mail *mail);
	const struct message_part *(*get_parts)(struct mail *mail);

	time_t (*get_date)(struct mail *mail, int *timezone);
	time_t (*get_received_date)(struct mail *mail);
	time_t (*get_save_date)(struct mail *mail);
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

union mail_module_context {
	struct mail_vfuncs super;
	struct mail_module_register *reg;
};

struct mail_private {
	struct mail mail;
	struct mail_vfuncs v;

	pool_t pool;
	ARRAY_DEFINE(module_contexts, union mail_module_context *);
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
	ARRAY_DEFINE(module_contexts,
		     union mailbox_transaction_module_context *);
};

union mail_search_module_context {
	struct mail_storage_module_register *reg;
};

struct mail_search_context {
	struct mailbox_transaction_context *transaction;

	char *charset;
	struct mail_search_arg *args;
	struct mail_search_sort_program *sort_program;

	uint32_t seq;
	ARRAY_DEFINE(module_contexts, union mail_search_module_context *);
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

/* Modules should use do "my_id = mail_storage_module_id++" and
   use objects' module_contexts[id] for their own purposes. */
extern struct mail_storage_module_register mail_storage_module_register;

/* Storage's module_id for mail_index. */
extern struct mail_module_register mail_module_register;

#define MAIL_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_storage_mail_index_module)
extern MODULE_CONTEXT_DEFINE(mail_storage_mail_index_module,
			     &mail_index_module_register);

/* Set error message in storage. Critical errors are logged with i_error(),
   but user sees only "internal error" message. */
void mail_storage_clear_error(struct mail_storage *storage);
void mail_storage_set_error(struct mail_storage *storage,
			    enum mail_error error, const char *string);
void mail_storage_set_critical(struct mail_storage *storage,
			       const char *fmt, ...) __attr_format__(2, 3);
void mail_storage_set_internal_error(struct mail_storage *storage);
bool mail_storage_set_error_from_errno(struct mail_storage *storage);

void mail_set_expunged(struct mail *mail);

enum mailbox_list_flags
mail_storage_get_list_flags(enum mail_storage_flags storage_flags);

#endif
