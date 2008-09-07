#ifndef SHARED_STORAGE_H
#define SHARED_STORAGE_H

#include "index-storage.h"
#include "mailbox-list-private.h"

#define SHARED_STORAGE_NAME "shared"

struct shared_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;

	const char *ns_prefix_pattern;
	const char *location;

	struct mail_storage *storage_class;
};

struct mailbox_list *shared_mailbox_list_alloc(void);

int shared_storage_get_namespace(struct mail_storage *storage,
				 const char **name,
				 struct mail_namespace **ns_r);

#endif
