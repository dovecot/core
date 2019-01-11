#ifndef MAILDIR_STORAGE_H
#define MAILDIR_STORAGE_H

#include "maildir-settings.h"

#define MAILDIR_STORAGE_NAME "maildir"
#define MAILDIR_SUBSCRIPTION_FILE_NAME "subscriptions"
#define MAILDIR_UIDVALIDITY_FNAME "dovecot-uidvalidity"

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
#define MAILDIR_EXTRA_FILE_SIZE 'S'
/* Something (can't remember what anymore) could use 'W' in filename to avoid
   calculating file's virtual size (added missing CRs). */
#define MAILDIR_EXTRA_VIRTUAL_SIZE 'W'

/* Delete files having ctime older than this from tmp/. 36h is standard. */
#define MAILDIR_TMP_DELETE_SECS (36*60*60)

/* How often to touch the uidlist lock file when it's locked.
   This is done both when using KEEP_LOCKED flag and when syncing a large
   maildir. */
#define MAILDIR_LOCK_TOUCH_SECS 10

/* If an operation fails with ENOENT, we'll check if the mailbox is deleted
   or if some directory is just missing. If it's missing, we'll create the
   directories and try again this many times before failing. */
#define MAILDIR_DELETE_RETRY_COUNT 3

#include "index-storage.h"

struct timeval;
struct maildir_save_context;
struct maildir_copy_context;

struct maildir_index_header {
	uint32_t new_check_time, new_mtime, new_mtime_nsecs;
	uint32_t cur_check_time, cur_mtime, cur_mtime_nsecs;
	uint32_t uidlist_mtime, uidlist_mtime_nsecs, uidlist_size;
};

struct maildir_list_index_record {
	uint32_t new_mtime, cur_mtime;
};

struct maildir_storage {
	struct mail_storage storage;

	const struct maildir_settings *set;
	const char *temp_prefix;
};

struct maildir_mailbox {
	struct mailbox box;
	struct maildir_storage *storage;
	struct mail_index_view *flags_view;

	struct timeout *keep_lock_to;

	/* Filled lazily by mailbox_get_private_flags_mask() */
	enum mail_flags _private_flags_mask;

	/* maildir sync: */
	struct maildir_uidlist *uidlist;
	struct maildir_keywords *keywords;

	struct maildir_index_header maildir_hdr;
	uint32_t maildir_ext_id;
	uint32_t maildir_list_index_ext_id;

	bool synced:1;
	bool syncing_commit:1;
	bool private_flags_mask_set:1;
	bool backend_readonly:1;
	bool backend_readonly_set:1;
	bool sync_uidlist_refreshed:1;
};

#define MAILDIR_STORAGE(s)	container_of(s, struct maildir_storage, storage)
#define MAILDIR_MAILBOX(s)	container_of(s, struct maildir_mailbox, box)

extern struct mail_vfuncs maildir_mail_vfuncs;

/* Return -1 = error, 0 = file not found, 1 = ok */
typedef int maildir_file_do_func(struct maildir_mailbox *mbox,
				 const char *path, void *context);

int maildir_file_do(struct maildir_mailbox *mbox, uint32_t uid,
		    maildir_file_do_func *callback, void *context);
#define maildir_file_do(mbox, seq, callback, context) \
	maildir_file_do(mbox, seq + \
		CALLBACK_TYPECHECK(callback, int (*)( \
			struct maildir_mailbox *, const char *, typeof(context))), \
		(maildir_file_do_func *)callback, context)

bool maildir_set_deleted(struct mailbox *box);
uint32_t maildir_get_uidvalidity_next(struct mailbox_list *list);
int maildir_lose_unexpected_dir(struct mail_storage *storage, const char *path);
bool maildir_is_backend_readonly(struct maildir_mailbox *mbox);

struct mail_save_context *
maildir_save_alloc(struct mailbox_transaction_context *_t);
int maildir_save_begin(struct mail_save_context *ctx, struct istream *input);
int maildir_save_continue(struct mail_save_context *ctx);
void maildir_save_finish_keywords(struct mail_save_context *ctx);
int maildir_save_finish(struct mail_save_context *ctx);
void maildir_save_cancel(struct mail_save_context *ctx);

struct maildir_filename *
maildir_save_add(struct mail_save_context *_ctx, const char *tmp_fname,
		 struct mail *src_mail) ATTR_NULL(3);
void maildir_save_set_dest_basename(struct mail_save_context *ctx,
				    struct maildir_filename *mf,
				    const char *basename);
void maildir_save_set_sizes(struct maildir_filename *mf,
			    uoff_t size, uoff_t vsize);

int maildir_save_file_get_size(struct mailbox_transaction_context *t,
			       uint32_t seq, bool vsize, uoff_t *size_r);
const char *maildir_save_file_get_path(struct mailbox_transaction_context *t,
				       uint32_t seq);

int maildir_transaction_save_commit_pre(struct mail_save_context *ctx);
void maildir_transaction_save_commit_post(struct mail_save_context *ctx,
					  struct mail_index_transaction_commit_result *result);
void maildir_transaction_save_rollback(struct mail_save_context *ctx);

int maildir_copy(struct mail_save_context *ctx, struct mail *mail);
int maildir_transaction_copy_commit(struct maildir_copy_context *ctx);
void maildir_transaction_copy_rollback(struct maildir_copy_context *ctx);

#endif
