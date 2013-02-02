/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "fail-mail-storage.h"

extern struct mail_storage fail_storage;

static struct mail_storage *fail_storage_alloc(void)
{
	struct mail_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("fail mail storage", 1024);
	storage = p_new(pool, struct mail_storage, 1);
	*storage = fail_storage;
	storage->pool = pool;
	return storage;
}

static void fail_storage_destroy(struct mail_storage *storage ATTR_UNUSED)
{
}

static void
fail_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
			      struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = "fail";
	if (set->subscription_fname == NULL)
		set->subscription_fname = "subscriptions";
}

struct mail_storage fail_storage = {
	.name = "fail",
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NO_ROOT,

	.v = {
		NULL,
		fail_storage_alloc,
		NULL,
		fail_storage_destroy,
		NULL,
		fail_storage_get_list_settings,
		NULL,
		fail_mailbox_alloc,
		NULL
	}
};

struct mail_storage *fail_mail_storage_create(void)
{
	struct mail_storage *storage;

	storage = fail_storage_alloc();
	storage->refcount = 1;
	storage->storage_class = &fail_storage;
	p_array_init(&storage->module_contexts, storage->pool, 5);
	return storage;
}
