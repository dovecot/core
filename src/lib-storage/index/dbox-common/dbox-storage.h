#ifndef DBOX_STORAGE_H
#define DBOX_STORAGE_H

#include "mail-storage-private.h"

struct dbox_file;
struct dbox_mail;

#define DBOX_SUBSCRIPTION_FILE_NAME "subscriptions"
#define DBOX_UIDVALIDITY_FILE_NAME "dovecot-uidvalidity"
#define DBOX_INDEX_PREFIX "dovecot.index"

#define DBOX_MAILBOX_DIR_NAME "mailboxes"
#define DBOX_TRASH_DIR_NAME "trash"
#define DBOX_MAILDIR_NAME "dbox-Mails"

/* How often to scan for stale temp files (based on dir's atime) */
#define DBOX_TMP_SCAN_SECS (8*60*60)
/* Delete temp files having ctime older than this. */
#define DBOX_TMP_DELETE_SECS (36*60*60)

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
				      const struct mailbox_update *update);
};

struct dbox_storage {
	struct mail_storage storage;
	struct dbox_storage_vfuncs v;

	unsigned int files_corrupted:1;
};

void dbox_storage_get_list_settings(const struct mail_namespace *ns,
				    struct mailbox_list_settings *set);
uint32_t dbox_get_uidvalidity_next(struct mailbox_list *list);
void dbox_notify_changes(struct mailbox *box);
int dbox_mailbox_open(struct mailbox *box);
int dbox_mailbox_create(struct mailbox *box,
			const struct mailbox_update *update, bool directory);
int dbox_list_iter_is_mailbox(struct mailbox_list_iterate_context *ctx,
			      const char *dir, const char *fname,
			      const char *mailbox_name,
			      enum mailbox_list_file_type type,
			      enum mailbox_info_flags *flags);
int dbox_list_rename_mailbox_pre(struct mailbox_list *oldlist,
				 const char *oldname,
				 struct mailbox_list *newlist,
				 const char *newname);
int dbox_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			     struct mailbox_list *newlist, const char *newname,
			     bool rename_children);

int dbox_list_delete_mailbox1(struct mailbox_list *list, const char *name,
			      const char **trash_dest_r);
int dbox_list_delete_mailbox2(struct mailbox_list *list, const char *name,
			      int ret, const char *trash_dest);

#endif
