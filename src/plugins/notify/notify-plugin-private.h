#ifndef NOTIFY_PLUGIN_PRIVATE_H
#define NOTIFY_PLUGIN_PRIVATE_H

#include "notify-plugin.h"

void notify_contexts_mail_transaction_begin(struct mailbox_transaction_context *t);
void notify_contexts_mail_save(struct mail *mail);
void notify_contexts_mail_copy(struct mail *src, struct mail *dst);
void notify_contexts_mail_expunge(struct mail *mail);
void notify_contexts_mail_update_flags(struct mail *mail,
				       enum mail_flags old_flags);
void notify_contexts_mail_update_keywords(struct mail *mail,
					  const char *const *old_keywords);
void notify_contexts_mail_transaction_commit(struct mailbox_transaction_context *t,
					     struct mail_transaction_commit_changes *changes);
void notify_contexts_mail_transaction_rollback(struct mailbox_transaction_context *t);
void notify_contexts_mailbox_create(struct mailbox *box);
void notify_contexts_mailbox_delete_begin(struct mailbox *box);
void notify_contexts_mailbox_delete_commit(struct mailbox *box);
void notify_contexts_mailbox_delete_rollback(void);
void notify_contexts_mailbox_rename(struct mailbox *src, struct mailbox *dest,
				    bool rename_children);

void notify_plugin_init_storage(struct module *module);
void notify_plugin_deinit_storage(void);

#endif
