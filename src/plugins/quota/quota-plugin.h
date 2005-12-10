#ifndef __QUOTA_PLUGIN_H
#define __QUOTA_PLUGIN_H

struct mail_storage;

extern void (*quota_next_hook_mail_storage_created)
	(struct mail_storage *storage);
extern struct quota *quota;

void quota_mail_storage_created(struct mail_storage *storage);

void quota_plugin_init(void);
void quota_plugin_deinit(void);

#endif
