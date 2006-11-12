#ifndef __QUOTA_PLUGIN_H
#define __QUOTA_PLUGIN_H

struct mail_storage;

extern void (*quota_next_hook_mail_storage_created)
	(struct mail_storage *storage);
/* "quota" symbol already exists in OSX, so we'll use this slightly uglier
   name. */
extern struct quota *quota_set;

void quota_mail_storage_created(struct mail_storage *storage);

void quota_plugin_init(void);
void quota_plugin_deinit(void);

#endif
