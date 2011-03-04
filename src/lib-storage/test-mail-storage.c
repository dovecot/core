/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "test-mail-storage.h"

extern struct mail_storage test_storage;
struct mail_index_module_register mail_index_module_register = { 0 };

static struct mail_storage *test_storage_alloc(void)
{
	struct mail_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("test mail storage", 1024);
	storage = p_new(pool, struct mail_storage, 1);
	*storage = test_storage;
	storage->pool = pool;
	return storage;
}

static void
test_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
			      struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = "test";
	if (set->subscription_fname == NULL)
		set->subscription_fname = "subscriptions";
}

struct mail_storage test_storage = {
	.name = "test",
	.class_flags = 0,

	.v = {
		NULL,
		test_storage_alloc,
		NULL,
		NULL,
		NULL,
		test_storage_get_list_settings,
		NULL,
		test_mailbox_alloc,
		NULL
	}
};

struct mail_storage *test_mail_storage_create(void)
{
	struct mail_storage *storage;

	storage = test_storage_alloc();
	storage->refcount = 1;
	storage->storage_class = &test_storage;
	p_array_init(&storage->module_contexts, storage->pool, 5);
	return storage;
}
