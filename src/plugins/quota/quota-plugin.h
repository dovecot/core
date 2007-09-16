#ifndef QUOTA_PLUGIN_H
#define QUOTA_PLUGIN_H

struct mail_storage;

extern void (*quota_next_hook_mail_storage_created)
	(struct mail_storage *storage);
extern void (*quota_next_hook_mailbox_list_created)(struct mailbox_list *list);

/* "quota" symbol already exists in OSX, so we'll use this slightly uglier
   name. */
extern struct quota *quota_set;

void quota_mail_storage_created(struct mail_storage *storage);
void quota_mailbox_list_created(struct mailbox_list *list);

void quota_plugin_init(void);
void quota_plugin_deinit(void);

#endif
