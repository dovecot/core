/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "mail-storage.h"
#include "acl-cache.h"
#include "acl-api-private.h"

struct acl_object *acl_object_init_from_name(struct acl_backend *backend,
					     const char *name)
{
	struct acl_object *aclobj;
	const char *control_dir;

	aclobj = hash_lookup(backend->aclobjs, name);
	if (aclobj != NULL) {
		i_assert(aclobj->refcount >= 0);
		aclobj->refcount++;
		return aclobj;
	}

	control_dir =
		mail_storage_get_mailbox_control_dir(backend->storage, name);

	aclobj = backend->v.object_init(backend, name, control_dir);
	aclobj->refcount++;
	hash_insert(backend->aclobjs, aclobj->name, aclobj);
	return aclobj;
}

struct acl_object *acl_object_init_from_mailbox(struct acl_backend *backend,
						struct mailbox *box)
{
	i_assert(mailbox_get_storage(box) == backend->storage);

	return acl_object_init_from_name(backend, mailbox_get_name(box));
}

void acl_object_deinit(struct acl_object **_aclobj)
{
	struct acl_object *aclobj = *_aclobj;

	i_assert(aclobj->refcount > 0);

	*_aclobj = NULL;
	if (--aclobj->refcount > 0)
		return;

	/* currently ACL objects are really freed only at backend
	   deinitialization. */
}

int acl_object_have_right(struct acl_object *aclobj, unsigned int right_idx)
{
	const struct acl_mask *have_mask;
	unsigned int mask_idx;

	if (*aclobj->name == '\0') {
		/* we want to look up default rights */
		have_mask = aclobj->backend->default_rights;
	} else {
		if (aclobj->backend->v.object_refresh_cache(aclobj) < 0)
			return -1;

		have_mask = acl_cache_get_my_rights(aclobj->backend->cache,
						    aclobj->name);
		if (have_mask == NULL)
			have_mask = aclobj->backend->default_rights;
	}

	mask_idx = right_idx / CHAR_BIT;
	return mask_idx < have_mask->size &&
		(have_mask->mask[mask_idx] &
		 (1 << (right_idx % CHAR_BIT))) != 0;
}

int acl_object_get_my_rights(struct acl_object *aclobj, pool_t pool,
                             const char *const **rights_r)
{
	const struct acl_mask *mask;
	const char *const *names;
	const char **buf, **rights;
	unsigned int names_count, count, i, j, name_idx;

	if (*aclobj->name == '\0') {
		/* we want to look up default rights */
		mask = aclobj->backend->default_rights;
	} else {
		if (aclobj->backend->v.object_refresh_cache(aclobj) < 0)
			return -1;

		mask = acl_cache_get_my_rights(aclobj->backend->cache,
					       aclobj->name);
		if (mask == NULL)
			mask = aclobj->backend->default_rights;
	}

	if (!pool->datastack_pool)
		t_push();

	names = acl_cache_get_names(aclobj->backend->cache, &names_count);
	buf = t_new(const char *, (mask->size * CHAR_BIT) + 1);
	count = 0;
	for (i = 0, name_idx = 0; i < mask->size; i++) {
		if (mask->mask[i] == 0)
			name_idx += CHAR_BIT;
		else {
			for (j = 1; j < (1 << CHAR_BIT); j <<= 1, name_idx++) {
				if ((mask->mask[j] & j) == 0)
					continue;

				/* @UNSAFE */
				i_assert(name_idx < names_count);
				buf[count++] = p_strdup(pool, names[name_idx]);
			}
		}
	}

	/* @UNSAFE */
	rights = p_new(pool, const char *, count + 1);
	memcpy(rights, buf, count * sizeof(const char *));
	*rights_r = rights;

	if (!pool->datastack_pool)
		t_pop();
	return 0;
}

int acl_object_update(struct acl_object *aclobj,
		      const struct acl_rights *rights)
{
        return aclobj->backend->v.object_update(aclobj, rights);
}

struct acl_object_list_iter *acl_object_list_init(struct acl_object *aclobj)
{
        return aclobj->backend->v.object_list_init(aclobj);
}

int acl_object_list_next(struct acl_object_list_iter *iter,
                         struct acl_rights *rights_r)
{
        return iter->aclobj->backend->v.object_list_next(iter, rights_r);
}

void acl_object_list_deinit(struct acl_object_list_iter *iter)
{
        iter->aclobj->backend->v.object_list_deinit(iter);
}
