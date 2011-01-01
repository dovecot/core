#ifndef MAILBOX_LIST_DELETE_H
#define MAILBOX_LIST_DELETE_H

enum mailbox_list_path_type;

int mailbox_list_delete_maildir_via_trash(struct mailbox_list *list,
					  const char *name,
					  const char *trash_dir);
int mailbox_list_delete_mailbox_file(struct mailbox_list *list,
				     const char *name);
int mailbox_list_delete_mailbox_nonrecursive(struct mailbox_list *list,
					     const char *name, const char *path,
					     bool rmdir_path);
void mailbox_list_delete_finish(struct mailbox_list *list, const char *name);

void mailbox_list_delete_until_root(struct mailbox_list *list, const char *path,
				    enum mailbox_list_path_type type);
int mailbox_list_delete_trash(const char *path);

#endif
