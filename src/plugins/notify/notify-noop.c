#include "lib.h"
#include "mail-types.h"
#include "notify-plugin.h"

void notify_noop_mail_transaction_begin(struct mailbox_transaction_context *t ATTR_UNUSED) {}
void notify_noop_mail_save(void *txn ATTR_UNUSED,
			   struct mail *mail ATTR_UNUSED) {}
void notify_noop_mail_copy(void *txn ATTR_UNUSED,
			   struct mail *src ATTR_UNUSED,
			   struct mail *dst ATTR_UNUSED) {}
void notify_noop_mail_expunge(void *txn ATTR_UNUSED,
			      struct mail *mail ATTR_UNUSED) {}
void notify_noop_mail_update_flags(void *txn ATTR_UNUSED,
				   struct mail *mail ATTR_UNUSED,
				   enum mail_flags old_flags ATTR_UNUSED) {}
void notify_noop_mail_update_keywords(void *txn ATTR_UNUSED,
				      struct mail *mail ATTR_UNUSED,
				      const char *const *old_keywords ATTR_UNUSED) {}
void notify_noop_mail_transaction_commit(void *txn ATTR_UNUSED,
					 struct mail_transaction_commit_changes *changes ATTR_UNUSED) {}
void notify_noop_mail_transaction_rollback(void *txn ATTR_UNUSED) {}
void *notify_noop_mailbox_delete_begin(struct mailbox *box ATTR_UNUSED) { return NULL; }
void notify_noop_mailbox_delete_commit(void *txn ATTR_UNUSED,
				       struct mailbox *box ATTR_UNUSED) {}
void notify_noop_mailbox_delete_rollback(void *txn ATTR_UNUSED) {}
void notify_noop_mailbox_rename(struct mailbox_list *oldlist ATTR_UNUSED,
				const char *oldname ATTR_UNUSED,
				struct mailbox_list *newlist ATTR_UNUSED,
				const char *newname ATTR_UNUSED,
				bool rename_children ATTR_UNUSED) {}
