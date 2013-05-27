#ifndef DBOX_STORAGE_H
#define DBOX_STORAGE_H

#include "mail-storage-private.h"

struct dbox_file;
struct dbox_mail;
struct dbox_storage;
struct dbox_save_context;

#define DBOX_SUBSCRIPTION_FILE_NAME "subscriptions"
#define DBOX_UIDVALIDITY_FILE_NAME "dovecot-uidvalidity"
#define DBOX_TEMP_FILE_PREFIX ".temp."
#define DBOX_ALT_SYMLINK_NAME "dbox-alt-root"

#define DBOX_MAILBOX_DIR_NAME "mailboxes"
#define DBOX_TRASH_DIR_NAME "trash"
#define DBOX_MAILDIR_NAME "dbox-Mails"

/* Delete temp files having ctime older than this. */
#define DBOX_TMP_DELETE_SECS (36*60*60)

/* Flag specifies if the message should be in primary or alternative storage */
#define DBOX_INDEX_FLAG_ALT MAIL_INDEX_MAIL_FLAG_BACKEND

enum dbox_index_header_flags {
	/* messages' metadata contain POP3 UIDLs */
	DBOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS	= 0x01,
	/* messages' metadata contain POP3 orders */
	DBOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS	= 0x02
};

struct dbox_storage_vfuncs {
	/* dbox file has zero references now. it should be either freed or
	   left open in case it's accessed again soon */
	void (*file_unrefed)(struct dbox_file *file);
	/* create a new file using the same permissions as file.
	   if parents=TRUE, create the directory if necessary */
	int (*file_create_fd)(struct dbox_file *file, const char *path,
			      bool parents);
	/* open the mail and return its file/offset */
	int (*mail_open)(struct dbox_mail *mail, uoff_t *offset_r,
			 struct dbox_file **file_r);
	/* create/update mailbox indexes */
	int (*mailbox_create_indexes)(struct mailbox *box,
				      const struct mailbox_update *update,
				      struct mail_index_transaction *trans);
	/* returns attachment path suffix. mdbox returns "", sdbox returns
	   "-<mailbox_guid>-<uid>" */
	const char *(*get_attachment_path_suffix)(struct dbox_file *file);
	/* mark the mailbox corrupted */
	void (*set_mailbox_corrupted)(struct mailbox *box);
	/* mark the file corrupted */
	void (*set_file_corrupted)(struct dbox_file *file);
};

struct dbox_storage {
	struct mail_storage storage;
	struct dbox_storage_vfuncs v;

	struct fs *attachment_fs;
	const char *attachment_dir;
};

void dbox_storage_get_list_settings(const struct mail_namespace *ns,
				    struct mailbox_list_settings *set);
int dbox_storage_create(struct mail_storage *storage,
			struct mail_namespace *ns,
			const char **error_r);
void dbox_storage_destroy(struct mail_storage *storage);
uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list);
void dbox_notify_changes(struct mailbox *box);
int dbox_mailbox_open(struct mailbox *box);
int dbox_mailbox_create(struct mailbox *box,
			const struct mailbox_update *update, bool directory);
int dbox_verify_alt_storage(struct mailbox_list *list);
bool dbox_header_have_flag(struct mailbox *box, uint32_t ext_id,
			   unsigned int flags_offset, uint8_t flag);

#endif
