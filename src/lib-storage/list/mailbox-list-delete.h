#ifndef MAILBOX_LIST_DELETE_H
#define MAILBOX_LIST_DELETE_H

#include "mailbox-list.h"

/* Delete the mailbox atomically by rename()ing it to trash_dir and afterwards
   recursively deleting the trash_dir. If the rename() fails because trash_dir
   already exists, the trash_dir is first deleted and rename() is retried.

   Returns 1 if the rename() succeeded. Returns 0 if rename() fails with EXDEV,
   which means the source and destination are on different filesystems and
   the rename can never succeed.

   If the path didn't exist, returns -1 and sets the list error to
   MAIL_ERROR_NOTFOUND.

   Attempting to delete INBOX or the namespace root returns -1 and sets the
   list error to MAIL_ERROR_NOTPOSSIBLE.

   Returns -1 and sets the list error on other errors. */
int mailbox_list_delete_maildir_via_trash(struct mailbox_list *list,
					  const char *name,
					  const char *trash_dir);
/* Try to unlink() the path. Returns 0 on success. If the path didn't exist,
   returns -1 and sets the list error to MAIL_ERROR_NOTFOUND.
   Returns -1 and sets the list error on other errors. */
int mailbox_list_delete_mailbox_file(struct mailbox_list *list,
				     const char *name, const char *path);
/* Delete all files from the given path. Also all internal directories
   (as returned by is_internal_name() check) are recursively deleted.
   Otherwise directories are left undeleted.

   Returns 0 if anything was unlink()ed and no unexpected errors happened.
   Also returns 0 if there were no files and the path was successfully
   rmdir()ed.

   If the path didn't exist, returns -1 and sets the list error to
   MAIL_ERROR_NOTFOUND.

   If the path exists and has subdirectories, but no files were unlink()ed,
   returns -1 and sets the list error to MAIL_ERROR_NOTPOSSIBLE.

   Attempting to delete INBOX or the namespace root returns -1 and sets the
   list error to MAIL_ERROR_NOTPOSSIBLE.

   Returns -1 and sets the list error on other errors. */
int mailbox_list_delete_mailbox_nonrecursive(struct mailbox_list *list,
					     const char *name, const char *path,
					     bool rmdir_path);
/* Lookup INDEX, CONTROL and ALT directories for the mailbox and delete them.
   Returns 1 if anything was unlink()ed or rmdir()ed, 0 if not.
   Returns -1 and sets the list error on any errors. */
int mailbox_list_delete_finish(struct mailbox_list *list, const char *name);
/* Finish mailbox deletion by calling mailbox_list_delete_finish() if needed.
   Set root_delete_success to TRUE if the mail root directory was successfully
   deleted, FALSE if not. The list is expected to have a proper error when
   root_delete_success==FALSE.

   Returns 0 if mailbox deletion should be treated as success. If not, returns
   -1 and sets the list error if necessary. */
int mailbox_list_delete_finish_ret(struct mailbox_list *list,
				   const char *name, bool root_delete_success);

/* rmdir() path and its parent directories until the root directory is reached.
   The root isn't rmdir()ed. */
void mailbox_list_delete_until_root(struct mailbox_list *list, const char *path,
				    enum mailbox_list_path_type type);
/* Call mailbox_list_delete_until_root() for all the paths of the mailbox. */
void mailbox_list_delete_mailbox_until_root(struct mailbox_list *list,
					    const char *storage_name);
/* Wrapper to unlink_directory(UNLINK_DIRECTORY_FLAG_RMDIR). If it fails due
   to ELOOP, try to unlink() the path instead. */
int mailbox_list_delete_trash(const char *path, const char **error_r);
/* Try to unlink() the path to the mailbox. Returns 0 on success.

   If the path didn't exist, returns -1 and sets the list error to
   MAIL_ERROR_NOTFOUND.

   If the path is a directory, returns -1 and sets the list error to
   MAIL_ERROR_NOTPOSSIBLE.

   Returns -1 and sets the list error on other errors. */
int mailbox_list_delete_symlink_default(struct mailbox_list *list,
					const char *name);

#endif
