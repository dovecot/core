#ifndef __MAIL_STORAGE_PRIVATE_H
#define __MAIL_STORAGE_PRIVATE_H

#include "mail-storage.h"

struct mail_storage {
	char *name;
	char *namespace;
	char hierarchy_sep;

	struct mail_storage *(*create)(const char *data, const char *user,
				       const char *namespace,
				       char hierarchy_sep);
	void (*destroy)(struct mail_storage *storage);

	int (*autodetect)(const char *data);

	void (*set_callbacks)(struct mail_storage *storage,
			      struct mail_storage_callbacks *callbacks,
			      void *context);

	struct mailbox *(*mailbox_open)(struct mail_storage *storage,
					const char *name,
					enum mailbox_open_flags flags);

	int (*mailbox_create)(struct mail_storage *storage, const char *name,
			      int directory);
	int (*mailbox_delete)(struct mail_storage *storage, const char *name);
	int (*mailbox_rename)(struct mail_storage *storage, const char *oldname,
			      const char *newname);

	struct mailbox_list_context *
		(*mailbox_list_init)(struct mail_storage *storage,
				     const char *mask,
				     enum mailbox_list_flags flags);
	struct mailbox_list *
		(*mailbox_list_next)(struct mailbox_list_context *ctx);
	int (*mailbox_list_deinit)(struct mailbox_list_context *ctx);

	int (*set_subscribed)(struct mail_storage *storage,
			      const char *name, int set);

	int (*get_mailbox_name_status)(struct mail_storage *storage,
				       const char *name,
				       enum mailbox_name_status *status);

	const char *(*get_last_error)(struct mail_storage *storage,
				      int *syntax_error_r);

/* private: */
	char *error;

	unsigned int syntax_error:1; /* Give a BAD reply instead of NO */
};

struct mailbox {
	char *name;

	struct mail_storage *storage;

	int (*is_readonly)(struct mailbox *box);
	int (*allow_new_keywords)(struct mailbox *box);

	int (*close)(struct mailbox *box);

	int (*get_status)(struct mailbox *box, enum mailbox_status_items items,
			  struct mailbox_status *status);

	int (*sync)(struct mailbox *box, enum mailbox_sync_flags flags);
	void (*auto_sync)(struct mailbox *box, enum mailbox_sync_flags flags,
			  unsigned int min_newmail_notify_interval);

	struct mailbox_transaction_context *
		(*transaction_begin)(struct mailbox *box, int hide);
	int (*transaction_commit)(struct mailbox_transaction_context *t);
	void (*transaction_rollback)(struct mailbox_transaction_context *t);

	struct mail *(*fetch)(struct mailbox_transaction_context *t,
			      uint32_t seq,
			      enum mail_fetch_field wanted_fields);
	int (*get_uids)(struct mailbox *box, uint32_t uid1, uint32_t uid2,
			uint32_t *seq1_r, uint32_t *seq2_r);

	int (*search_get_sorting)(struct mailbox *box,
				  enum mail_sort_type *sort_program);
	struct mail_search_context *
		(*search_init)(struct mailbox_transaction_context *t,
			       const char *charset,
			       struct mail_search_arg *args,
			       const enum mail_sort_type *sort_program,
			       enum mail_fetch_field wanted_fields,
			       const char *const wanted_headers[]);
	int (*search_deinit)(struct mail_search_context *ctx);
	struct mail *(*search_next)(struct mail_search_context *ctx);

	int (*save)(struct mailbox_transaction_context *t,
		    const struct mail_full_flags *flags,
		    time_t received_date, int timezone_offset,
		    const char *from_envelope, struct istream *data);
	int (*copy)(struct mailbox_transaction_context *t, struct mail *mail);

	int (*is_inconsistent)(struct mailbox *box);
};

struct mailbox_list_context {
	struct mail_storage *storage;
};

struct mailbox_transaction_context {
	struct mailbox *box;
};

struct mail_search_context {
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

#endif
