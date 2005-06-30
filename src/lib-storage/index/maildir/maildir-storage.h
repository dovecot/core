#ifndef __MAILDIR_STORAGE_H
#define __MAILDIR_STORAGE_H

/* Hierarchy separator in Maildir++ filenames - shouldn't be changed */
#define MAILDIR_FS_SEP '.'
#define MAILDIR_FS_SEP_S "."

#define SUBSCRIPTION_FILE_NAME "subscriptions"
#define MAILDIR_INDEX_PREFIX "dovecot.index"

/* "base,S=123:2," means:
   <base> [<extra sep> <extra data> [..]] <info sep> 2 <flags sep> */
#define MAILDIR_INFO_SEP ':'
#define MAILDIR_EXTRA_SEP ','
#define MAILDIR_FLAGS_SEP ','

#define MAILDIR_INFO_SEP_S ":"
#define MAILDIR_EXTRA_SEP_S ","
#define MAILDIR_FLAGS_SEP_S ","

/* ":2," is the standard flags separator */
#define MAILDIR_FLAGS_FULL_SEP MAILDIR_INFO_SEP_S "2" MAILDIR_FLAGS_SEP_S

#define MAILDIR_KEYWORD_FIRST 'a'
#define MAILDIR_KEYWORD_LAST 'z'
#define MAILDIR_MAX_KEYWORDS (MAILDIR_KEYWORD_LAST - MAILDIR_KEYWORD_FIRST + 1)

/* Maildir++ extension: include file size in the filename to avoid stat() */
#define MAILDIR_EXTRA_FILE_SIZE "S"
/* Something (can't remember what anymore) could use 'W' in filename to avoid
   calculating file's virtual size (added missing CRs). */
#define MAILDIR_EXTRA_VIRTUAL_SIZE "W"

#include "index-storage.h"

#define STORAGE(maildir_storage) \
	(&(maildir_storage)->storage.storage)
#define INDEX_STORAGE(maildir_storage) \
	(&(maildir_storage)->storage)

struct timeval;
struct maildir_save_context;
struct maildir_copy_context;

struct maildir_storage {
	struct index_storage storage;

	const char *control_dir;
};

struct maildir_mailbox {
	struct index_mailbox ibox;
	struct maildir_storage *storage;

	const char *path, *control_dir;

	/* maildir sync: */
	struct maildir_uidlist *uidlist;
	struct maildir_keywords *keywords;
	time_t last_new_mtime, last_cur_mtime, last_new_sync_time;
	time_t dirty_cur_time;

        mode_t mail_create_mode;
	unsigned int private_flags_mask;

	unsigned int syncing_commit:1;
};

struct maildir_transaction_context {
	struct index_transaction_context ictx;
	struct maildir_save_context *save_ctx;
	struct maildir_copy_context *copy_ctx;
};

extern struct mail_vfuncs maildir_mail_vfuncs;

/* Return -1 = error, 0 = file not found, 1 = ok */
typedef int maildir_file_do_func(struct maildir_mailbox *mbox,
				 const char *path, void *context);

int maildir_file_do(struct maildir_mailbox *mbox, uint32_t seq,
		    maildir_file_do_func *func, void *context);
const char *maildir_generate_tmp_filename(const struct timeval *tv);
int maildir_create_tmp(struct maildir_mailbox *mbox, const char *dir,
		       mode_t mode, const char **fname_r);

struct mailbox_list_context *
maildir_mailbox_list_init(struct mail_storage *storage,
			  const char *ref, const char *mask,
			  enum mailbox_list_flags flags);
int maildir_mailbox_list_deinit(struct mailbox_list_context *ctx);
struct mailbox_list *
maildir_mailbox_list_next(struct mailbox_list_context *ctx);

struct mailbox_sync_context *
maildir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
int maildir_storage_sync_force(struct maildir_mailbox *mbox);

struct maildir_index_sync_context *
maildir_sync_index_begin(struct maildir_mailbox *mbox);
void maildir_sync_index_abort(struct maildir_index_sync_context *sync_ctx);
int maildir_sync_index_finish(struct maildir_index_sync_context *sync_ctx,
			      int partial);

struct mailbox_transaction_context *
maildir_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags);
int maildir_transaction_commit(struct mailbox_transaction_context *t,
			       enum mailbox_sync_flags flags);
void maildir_transaction_rollback(struct mailbox_transaction_context *t);

struct mail_save_context *
maildir_save_init(struct mailbox_transaction_context *_t,
		  enum mail_flags flags, struct mail_keywords *keywords,
		  time_t received_date, int timezone_offset,
		  const char *from_envelope, struct istream *input,
		  int want_mail);
int maildir_save_continue(struct mail_save_context *ctx);
int maildir_save_finish(struct mail_save_context *ctx, struct mail *dest_mail);
void maildir_save_cancel(struct mail_save_context *ctx);

int maildir_transaction_save_commit_pre(struct maildir_save_context *ctx);
void maildir_transaction_save_commit_post(struct maildir_save_context *ctx);
void maildir_transaction_save_rollback(struct maildir_save_context *ctx);

int maildir_copy(struct mailbox_transaction_context *t, struct mail *mail,
		 struct mail *dest_mail);
int maildir_transaction_copy_commit(struct maildir_copy_context *ctx);
void maildir_transaction_copy_rollback(struct maildir_copy_context *ctx);

const char *maildir_get_path(struct index_storage *storage, const char *name);

int maildir_sync_last_commit(struct maildir_mailbox *mbox);

int maildir_filename_get_flags(struct maildir_index_sync_context *ctx,
			       const char *fname,
			       enum mail_flags *flags_r,
			       array_t *keywords);
const char *maildir_filename_set_flags(struct maildir_index_sync_context *ctx,
				       const char *fname, enum mail_flags flags,
				       array_t *keywords);

unsigned int maildir_hash(const void *p);
int maildir_cmp(const void *p1, const void *p2);

#endif
