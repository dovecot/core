#ifndef DBOX_STORAGE_H
#define DBOX_STORAGE_H

#include "index-storage.h"
#include "mailbox-list-private.h"
#include "dbox-settings.h"

#define DBOX_STORAGE_NAME "dbox"
#define DBOX_SUBSCRIPTION_FILE_NAME "subscriptions"
#define DBOX_UIDVALIDITY_FILE_NAME "dovecot-uidvalidity"
#define DBOX_INDEX_PREFIX "dovecot.index"
#define DBOX_DIR_GUID_FILE_NAME "dbox-GUID"

#define DBOX_MAILBOX_DIR_NAME "mailboxes"
#define DBOX_TRASH_DIR_NAME "trash"
#define DBOX_MAILDIR_NAME "dbox-Mails"
#define DBOX_GLOBAL_INDEX_PREFIX "dovecot.map.index"
#define DBOX_GLOBAL_DIR_NAME "storage"
#define DBOX_MAIL_FILE_MULTI_PREFIX "m."
#define DBOX_MAIL_FILE_UID_PREFIX "u."
#define DBOX_MAIL_FILE_MULTI_FORMAT DBOX_MAIL_FILE_MULTI_PREFIX"%u"
#define DBOX_MAIL_FILE_UID_FORMAT DBOX_MAIL_FILE_UID_PREFIX"%u"
#define DBOX_MAIL_FILE_BROKEN_COPY_SUFFIX ".broken"

/* How often to scan for stale temp files (based on dir's atime) */
#define DBOX_TMP_SCAN_SECS (8*60*60)
/* Delete temp files having ctime older than this. */
#define DBOX_TMP_DELETE_SECS (36*60*60)

/* Flag specifies if the message should be in primary or alternative storage */
#define DBOX_INDEX_FLAG_ALT MAIL_INDEX_MAIL_FLAG_BACKEND

#define DBOX_INDEX_HEADER_MIN_SIZE (sizeof(uint32_t))
struct dbox_index_header {
	uint32_t map_uid_validity;
	uint32_t highest_maildir_uid;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
};

struct dbox_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;
	const struct dbox_settings *set;

	/* root path for alt directory */
	const char *alt_dir;
	/* paths for storage directories */
	const char *storage_dir, *alt_storage_dir;
	struct dbox_map *map;

	/* mode/gid to use for new dbox storage files */
	mode_t dir_create_mode;
	gid_t create_gid;
	const char *create_gid_origin;

	ARRAY_DEFINE(open_files, struct dbox_file *);

	unsigned int sync_rebuild:1;
	unsigned int have_multi_msgs:1;
};

struct dbox_mail_index_record {
	uint32_t map_uid;
	/* UNIX timestamp of when the message was saved/copied to this
	   mailbox */
	uint32_t save_date;
};

struct dbox_mailbox {
	struct index_mailbox ibox;
	struct dbox_storage *storage;

	struct maildir_uidlist *maildir_uidlist;
	uint32_t highest_maildir_uid;
	uint32_t map_uid_validity;

	uint32_t dbox_ext_id, dbox_hdr_ext_id, guid_ext_id;

	const char *alt_path;

	unsigned int creating:1;
};

extern struct mail_vfuncs dbox_mail_vfuncs;

struct mailbox *
dbox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		   const char *name, struct istream *input,
		   enum mailbox_flags flags);
int dbox_mailbox_open(struct mailbox *box);

struct mail *
dbox_mail_alloc(struct mailbox_transaction_context *t,
		enum mail_fetch_field wanted_fields,
		struct mailbox_header_lookup_ctx *wanted_headers);

/* Get map_uid for wanted message. */
int dbox_mail_lookup(struct dbox_mailbox *mbox, struct mail_index_view *view,
		     uint32_t seq, uint32_t *map_uid_r);
uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list);
int dbox_read_header(struct dbox_mailbox *mbox, struct dbox_index_header *hdr);
void dbox_update_header(struct dbox_mailbox *mbox,
			struct mail_index_transaction *trans,
			const struct mailbox_update *update);

struct mail_save_context *
dbox_save_alloc(struct mailbox_transaction_context *_t);
int dbox_save_begin(struct mail_save_context *ctx, struct istream *input);
int dbox_save_continue(struct mail_save_context *ctx);
int dbox_save_finish(struct mail_save_context *ctx);
void dbox_save_cancel(struct mail_save_context *ctx);

struct dbox_file *
dbox_save_file_get_file(struct mailbox_transaction_context *t,
			uint32_t seq, uoff_t *offset_r);

int dbox_transaction_save_commit_pre(struct mail_save_context *ctx);
void dbox_transaction_save_commit_post(struct mail_save_context *ctx);
void dbox_transaction_save_rollback(struct mail_save_context *ctx);

int dbox_copy(struct mail_save_context *ctx, struct mail *mail);

#endif
