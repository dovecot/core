#ifndef SHARED_STORAGE_H
#define SHARED_STORAGE_H

#define SHARED_STORAGE_NAME "shared"

struct shared_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;

	const char *ns_prefix_pattern;
	const char *location, *unexpanded_location;

	struct mail_storage *storage_class;
};

struct mailbox_list *shared_mailbox_list_alloc(void);

/* Returns -1 = error, 0 = user doesn't exist, 1 = ok */
int shared_storage_get_namespace(struct mail_namespace **_ns,
				 const char **_name);

#endif
