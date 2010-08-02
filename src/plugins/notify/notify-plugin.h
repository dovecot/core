#ifndef NOTIFY_PLUGIN_H
#define NOTIFY_PLUGIN_H

enum mail_flags;
struct mail;
struct mail_transaction_commit_changes;
struct mail_storage;
struct mailbox_transaction_context;
struct mailbox_list;
struct mailbox;
struct notify_context;
struct module;

struct notify_vfuncs {
	void *(*mail_transaction_begin)(struct mailbox_transaction_context *t);
	void (*mail_save)(void *txn, struct mail *mail);
	void (*mail_copy)(void *txn, struct mail *src, struct mail *dst);
	void (*mail_expunge)(void *txn, struct mail *mail);
	void (*mail_update_flags)(void *txn, struct mail *mail,
				  enum mail_flags old_flags);
	void (*mail_update_keywords)(void *txn, struct mail *mail,
				     const char *const *old_keywords);
	void (*mail_transaction_commit)(void *txn,
			struct mail_transaction_commit_changes *changes);
	void (*mail_transaction_rollback)(void *txn);
	void (*mailbox_create)(struct mailbox *box);
	void *(*mailbox_delete_begin)(struct mailbox *box);
	void (*mailbox_delete_commit)(void *txn, struct mailbox *box);
	void (*mailbox_delete_rollback)(void *txn);
	void (*mailbox_rename)(struct mailbox *src, struct mailbox *dest,
			       bool rename_children);
};

void notify_noop_mailbox_create(struct mailbox *box);
struct notify_context *
notify_register(const struct notify_vfuncs *vfuncs);
void notify_unregister(struct notify_context *ctx);

void notify_plugin_init(struct module *module);
void notify_plugin_deinit(void);

#endif
