#ifndef MAILBOX_LIST_DELETE_H
#define MAILBOX_LIST_DELETE_H

int mailbox_list_delete_maildir_via_trash(struct mailbox_list *list,
					  const char *name,
					  const char *trash_dir);
int mailbox_list_delete_mailbox_file(struct mailbox_list *list,
				     const char *name);
int mailbox_list_delete_mailbox_nonrecursive(struct mailbox_list *list,
					     const char *name, const char *path,
					     bool rmdir_path);
void mailbox_list_delete_finish(struct mailbox_list *list, const char *name);

#endif
