#ifndef MAIL_STORAGE_HOOKS_H
#define MAIL_STORAGE_HOOKS_H

struct module;
struct mail_user;
struct mail_storage;
struct mail_namespace;
struct mailbox_list;
struct mailbox;
struct mail;

struct mail_storage_hooks {
	void (*mail_user_created)(struct mail_user *user);
	void (*mail_namespace_storage_added)(struct mail_namespace *ns);
	/* called the first time user's initial namespaces were added */
	void (*mail_namespaces_created)(struct mail_namespace *namespaces);
	/* called every time namespaces are added. most importantly called
	   when shared mailbox accesses trigger creating new namespaces.
	   this is called before mail_namespaces_created() at startup.
	   The namespaces parameter contains all of the current namespaces. */
	void (*mail_namespaces_added)(struct mail_namespace *namespaces);
	void (*mail_storage_created)(struct mail_storage *storage);
	void (*mailbox_list_created)(struct mailbox_list *list);
	void (*mailbox_allocated)(struct mailbox *box);
	void (*mailbox_opened)(struct mailbox *box);
	void (*mail_allocated)(struct mail *mail);
};

void mail_storage_hooks_init(void);
void mail_storage_hooks_deinit(void);

void mail_storage_hooks_add(struct module *module,
			    const struct mail_storage_hooks *hooks);
/* Add hooks to this plugin regardless of whether it exists in user's
   mail_plugins setting. */
void mail_storage_hooks_add_forced(struct module *module,
				   const struct mail_storage_hooks *hooks);
void mail_storage_hooks_remove(const struct mail_storage_hooks *hooks);

void mail_storage_hooks_add_internal(const struct mail_storage_hooks *hooks);
void mail_storage_hooks_remove_internal(const struct mail_storage_hooks *hooks);

void hook_mail_user_created(struct mail_user *user);
void hook_mail_namespace_storage_added(struct mail_namespace *ns);
void hook_mail_namespaces_created(struct mail_namespace *namespaces);
void hook_mail_namespaces_added(struct mail_namespace *namespaces);
void hook_mail_storage_created(struct mail_storage *storage);
void hook_mailbox_list_created(struct mailbox_list *list);
void hook_mailbox_allocated(struct mailbox *box);
void hook_mailbox_opened(struct mailbox *box);
void hook_mail_allocated(struct mail *mail);

#endif
