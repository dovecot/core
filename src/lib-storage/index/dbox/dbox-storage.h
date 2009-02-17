#ifndef DBOX_STORAGE_H
#define DBOX_STORAGE_H

#include "index-storage.h"
#include "mailbox-list-private.h"

#define DBOX_STORAGE_NAME "dbox"
#define DBOX_SUBSCRIPTION_FILE_NAME ".dbox-subscriptions"
#define DBOX_UIDVALIDITY_FILE_NAME ".dbox-uidvalidity"
#define DBOX_INDEX_PREFIX "dovecot.index"

#define DBOX_MAILDIR_NAME "dbox-Mails"
#define DBOX_INDEX_NAME "dbox.index"
#define DBOX_MAIL_FILE_MULTI_PREFIX "m."
#define DBOX_MAIL_FILE_UID_PREFIX "u."
#define DBOX_MAIL_FILE_MULTI_FORMAT DBOX_MAIL_FILE_MULTI_PREFIX"%u"
#define DBOX_MAIL_FILE_UID_FORMAT DBOX_MAIL_FILE_UID_PREFIX"%u"

/* How often to scan for stale temp files (based on dir's atime) */
#define DBOX_TMP_SCAN_SECS (8*60*60)
/* Delete temp files having ctime older than this. */
#define DBOX_TMP_DELETE_SECS (36*60*60)

/* Default rotation settings */
#define DBOX_DEFAULT_ROTATE_SIZE (2*1024*1024)
#define DBOX_DEFAULT_ROTATE_MIN_SIZE (1024*16)
#define DBOX_DEFAULT_ROTATE_DAYS 0
#define DBOX_DEFAULT_MAX_OPEN_FILES 64

/* Flag specifies if the message should be in primary or alternative storage */
#define DBOX_INDEX_FLAG_ALT MAIL_INDEX_MAIL_FLAG_BACKEND

struct dbox_index_header {
	uint32_t unused; /* for backwards compatibility */
	uint32_t highest_maildir_uid;
};

struct dbox_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;
	const char *alt_dir;
};

struct dbox_mail_index_record {
	uint32_t file_id;
	uint32_t offset;
};

struct dbox_mailbox {
	struct index_mailbox ibox;
	struct dbox_storage *storage;

	struct maildir_uidlist *maildir_uidlist;
	uint32_t highest_maildir_uid;

	struct dbox_index *dbox_index;
	uint32_t dbox_ext_id, dbox_hdr_ext_id;

	uoff_t rotate_size, rotate_min_size;
	unsigned int rotate_days;

	ARRAY_DEFINE(open_files, struct dbox_file *);
	unsigned int max_open_files;

	const char *path, *alt_path;
};

struct dbox_transaction_context {
	struct index_transaction_context ictx;
	union mail_index_transaction_module_context module_ctx;

	uint32_t first_saved_mail_seq;
	struct dbox_save_context *save_ctx;
};

extern struct mail_vfuncs dbox_mail_vfuncs;

void dbox_transaction_class_init(void);
void dbox_transaction_class_deinit(void);

struct mail *
dbox_mail_alloc(struct mailbox_transaction_context *t,
		enum mail_fetch_field wanted_fields,
		struct mailbox_header_lookup_ctx *wanted_headers);

struct mail_save_context *
dbox_save_alloc(struct mailbox_transaction_context *_t);
int dbox_save_begin(struct mail_save_context *ctx, struct istream *input);
int dbox_save_continue(struct mail_save_context *ctx);
int dbox_save_finish(struct mail_save_context *ctx);
void dbox_save_cancel(struct mail_save_context *ctx);

int dbox_transaction_save_commit_pre(struct dbox_save_context *ctx);
void dbox_transaction_save_commit_post(struct dbox_save_context *ctx);
void dbox_transaction_save_rollback(struct dbox_save_context *ctx);

#endif
