/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "acl-cache.h"
#include "acl-api-private.h"

#include <stdlib.h>

extern struct acl_backend_vfuncs acl_backend_vfile;

static const char *const owner_mailbox_rights[] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN,
	NULL
};

static const char *const non_owner_mailbox_rights[] = { NULL };

struct acl_backend *
acl_backend_init(const char *data, struct mail_storage *storage,
		 const char *acl_username, const char *const *groups,
		 const char *owner_username)
{
	struct acl_backend *backend;
	unsigned int i, group_count;
	bool storage_owner;

	group_count = strarray_length(groups);

	if (strncmp(data, "vfile:", 6) != 0)
		i_fatal("Unknown ACL backend: %s", t_strcut(data, ':'));
	data += 6;

	backend = acl_backend_vfile.init(data);
	backend->v = acl_backend_vfile;
	backend->storage = storage;
	backend->username = p_strdup(backend->pool, acl_username);
	backend->owner_username = p_strdup(backend->pool, owner_username);
	backend->group_count = group_count;
	backend->cache = acl_cache_init(backend);
	backend->aclobjs = hash_create(default_pool, backend->pool, 0,
				       str_hash, (hash_cmp_callback_t *)strcmp);

	storage_owner = owner_username != NULL &&
		strcmp(acl_username, owner_username) == 0;
	backend->default_rights =
		acl_cache_mask_init(backend->cache, backend->pool,
				    storage_owner ? owner_mailbox_rights :
				    non_owner_mailbox_rights);

	if (group_count > 0) {
		backend->groups =
			p_new(backend->pool, const char *, group_count);
		for (i = 0; i < group_count; i++)
			backend->groups[i] = groups[i];
		qsort(backend->groups, group_count, sizeof(const char *),
		      strcmp_p);
	}
	return backend;
}

void acl_backend_deinit(struct acl_backend **_backend)
{
	struct acl_backend *backend = *_backend;
	struct hash_iterate_context *iter;
	void *key, *value;

	*_backend = NULL;

	iter = hash_iterate_init(backend->aclobjs);
	while (hash_iterate(iter, &key, &value)) {
		struct acl_object *aclobj = value;

		aclobj->backend->v.object_deinit(aclobj);
	}
	hash_iterate_deinit(iter);

	acl_cache_deinit(&backend->cache);
	hash_destroy(backend->aclobjs);
	backend->v.deinit(backend);
}

bool acl_backend_user_is_authenticated(struct acl_backend *backend)
{
	return backend->username != NULL;
}

bool acl_backend_user_name_equals(struct acl_backend *backend,
				  const char *username)
{
	if (backend->username == NULL) {
		/* anonymous user never matches */
		return FALSE;
	}

	return strcmp(backend->username, username) == 0;
}

bool acl_backend_user_is_in_group(struct acl_backend *backend,
				  const char *group_name)
{
	return bsearch(group_name, backend->groups, backend->group_count,
		       sizeof(const char *), bsearch_strcmp) != NULL;
}

unsigned int acl_backend_lookup_right(struct acl_backend *backend,
				      const char *right)
{
	return acl_cache_right_lookup(backend->cache, right);
}
