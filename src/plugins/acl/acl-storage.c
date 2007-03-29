/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "acl-api-private.h"
#include "mailbox-list-private.h"
#include "acl-plugin.h"

#include <stdlib.h>

unsigned int acl_storage_module_id = 0;

static bool acl_storage_module_id_set = FALSE;

static const char *acl_storage_right_names[ACL_STORAGE_RIGHT_COUNT] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN
};

int acl_storage_have_right(struct mail_storage *storage, const char *name,
			   unsigned int acl_storage_right_idx, bool *can_see_r)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);
	const unsigned int *idx_arr = astorage->acl_storage_right_idx;
	struct acl_object *aclobj;
	int ret, ret2;

	aclobj = acl_object_init_from_name(astorage->backend, name);
	ret = acl_object_have_right(aclobj, idx_arr[acl_storage_right_idx]);

	if (can_see_r != NULL) {
		ret2 = acl_object_have_right(aclobj,
					     idx_arr[ACL_STORAGE_RIGHT_LOOKUP]);
		if (ret2 < 0)
			ret = -1;
		*can_see_r = ret2 > 0;
	}
	acl_object_deinit(&aclobj);

	return ret;
}

const char *
acl_storage_get_parent_mailbox_name(struct mail_storage *storage,
				    const char *name)
{
	const char *p;
	char sep;

	sep = mail_storage_get_hierarchy_sep(storage);
	p = strrchr(name, sep);
	return p == NULL ? "" : t_strdup_until(name, p);
}

static void acl_storage_destroy(struct mail_storage *storage)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);

	acl_backend_deinit(&astorage->backend);
	astorage->super.destroy(storage);
}

static struct mailbox *
acl_mailbox_open(struct mail_storage *storage, const char *name,
		 struct istream *input, enum mailbox_open_flags flags)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);
	struct mailbox *box;
	bool can_see;
	int ret;

	/* mailbox can be opened either for reading or appending new messages */
	if ((flags & MAILBOX_OPEN_SAVEONLY) != 0) {
		ret = acl_storage_have_right(storage, name,
					     ACL_STORAGE_RIGHT_INSERT,
					     &can_see);
	} else {
		ret = acl_storage_have_right(storage, name,
					     ACL_STORAGE_RIGHT_READ,
					     &can_see);
	}
	if (ret <= 0) {
		if (ret < 0)
			return NULL;
		if (can_see) {
			mail_storage_set_error(storage,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		} else {
			mail_storage_set_error(storage,
				MAILBOX_LIST_ERR_MAILBOX_NOT_FOUND, name);
		}
		return NULL;
	}

	box = astorage->super.mailbox_open(storage, name, input, flags);
	if (box == NULL)
		return NULL;

	return acl_mailbox_open_box(box);
}

static int acl_mailbox_create(struct mail_storage *storage, const char *name,
			      bool directory)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);
	int ret;

	t_push();
	ret = acl_storage_have_right(storage,
			acl_storage_get_parent_mailbox_name(storage, name),
			ACL_STORAGE_RIGHT_CREATE, NULL);
	t_pop();

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this not reveals to user the mailbox's
			   existence. Can't help it. */
			mail_storage_set_error(storage,
					       MAILBOX_LIST_ERR_NO_PERMISSION);
		}
		return -1;
	}

	return astorage->super.mailbox_create(storage, name, directory);
}

void acl_mail_storage_created(struct mail_storage *storage)
{
	struct acl_mail_storage *astorage;
	struct acl_backend *backend;
	const char *acl_env, *user_env, *owner_username;
	unsigned int i;

	if (acl_next_hook_mail_storage_created != NULL)
		acl_next_hook_mail_storage_created(storage);

	acl_env = getenv("ACL");
	user_env = getenv("MASTER_USER");
	if (user_env == NULL)
		user_env = getenv("USER");
	i_assert(acl_env != NULL && user_env != NULL);

	/* FIXME: set groups. owner_username isn't also correct here it's a
	   per-mailbox thing. but we don't currently support shared mailboxes,
	   so this will do for now.. */
	owner_username =
		(storage->flags & MAIL_STORAGE_FLAG_SHARED_NAMESPACE) == 0 ?
		getenv("USER") : NULL;
	backend = acl_backend_init(acl_env, storage, user_env, NULL,
				   owner_username);
	if (backend == NULL)
		i_fatal("ACL backend initialization failed");

	if ((storage->flags & MAIL_STORAGE_FLAG_FULL_FS_ACCESS) != 0) {
		/* FIXME: not necessarily, but safer to do this for now.. */
		i_fatal("mail_full_filesystem_access=yes is "
			"incompatible with ACLs");
	}

	astorage = p_new(storage->pool, struct acl_mail_storage, 1);
	astorage->super = storage->v;
	astorage->backend = backend;
	storage->v.destroy = acl_storage_destroy;
	storage->v.mailbox_open = acl_mailbox_open;
	storage->v.mailbox_create = acl_mailbox_create;

	acl_mailbox_list_set_storage(storage);

	/* build ACL right lookup table */
	for (i = 0; i < ACL_STORAGE_RIGHT_COUNT; i++) {
		astorage->acl_storage_right_idx[i] =
			acl_backend_lookup_right(backend,
						 acl_storage_right_names[i]);
	}

	if (!acl_storage_module_id_set) {
		acl_storage_module_id = mail_storage_module_id++;
		acl_storage_module_id_set = TRUE;
	}

	array_idx_set(&storage->module_contexts,
		      acl_storage_module_id, &astorage);
}

