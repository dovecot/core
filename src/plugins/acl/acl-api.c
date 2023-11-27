/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "hash.h"
#include "mail-user.h"
#include "mailbox-list.h"
#include "acl-global-file.h"
#include "acl-cache.h"
#include "acl-api-private.h"

struct acl_object *acl_object_init_from_name(struct acl_backend *backend,
					     const char *name)
{
	return backend->v->object_init(backend, name);
}

struct acl_object *acl_object_init_from_parent(struct acl_backend *backend,
					       const char *child_name)
{
	return backend->v->object_init_parent(backend, child_name);
}

void acl_object_deinit(struct acl_object **_aclobj)
{
	struct acl_object *aclobj = *_aclobj;

	if (aclobj == NULL)
		return;
	*_aclobj = NULL;
	aclobj->backend->v->object_deinit(aclobj);
}

int acl_object_have_right(struct acl_object *aclobj, unsigned int right_idx)
{
	struct acl_backend *backend = aclobj->backend;
	const struct acl_mask *have_mask;
	unsigned int read_idx;

	if (backend->v->object_refresh_cache(aclobj) < 0)
		return -1;

	have_mask = acl_cache_get_my_rights(backend->cache, aclobj->name);
	if (have_mask == NULL) {
		if (acl_backend_get_default_rights(backend, &have_mask) < 0)
			return -1;
	}

	if (acl_cache_mask_isset(have_mask, right_idx))
		return 1;

	if (mailbox_list_get_user(aclobj->backend->list)->dsyncing) {
		/* when dsync is running on a shared mailbox, it must be able
		   to do everything inside it. however, dsync shouldn't touch
		   mailboxes where user doesn't have any read access, because
		   that could make them readable on the replica. */
		read_idx = acl_backend_lookup_right(aclobj->backend,
						    MAIL_ACL_READ);
		if (acl_cache_mask_isset(have_mask, read_idx))
			return 1;
	}
	return 0;
}

const char *const *
acl_backend_mask_get_names(struct acl_backend *backend,
			   const struct acl_mask *mask, pool_t pool)
{
	const char *const *names;
	const char **buf, **rights;
	unsigned int names_count, count, i, j, name_idx;

	names = acl_cache_get_names(backend->cache, &names_count);
	buf = t_new(const char *, (mask->size * CHAR_BIT) + 1);
	count = 0;
	for (i = 0, name_idx = 0; i < mask->size; i++) {
		if (mask->mask[i] == 0)
			name_idx += CHAR_BIT;
		else {
			for (j = 1; j < (1 << CHAR_BIT); j <<= 1, name_idx++) {
				if ((mask->mask[i] & j) == 0)
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
	return rights;
}

static int acl_object_get_my_rights_real(struct acl_object *aclobj, pool_t pool,
					 const char *const **rights_r)
{
	struct acl_backend *backend = aclobj->backend;
	const struct acl_mask *mask;

	if (backend->v->object_refresh_cache(aclobj) < 0)
		return -1;

	mask = acl_cache_get_my_rights(backend->cache, aclobj->name);
	if (mask == NULL) {
		if (acl_backend_get_default_rights(backend, &mask) < 0)
			return -1;
	}

	*rights_r = acl_backend_mask_get_names(backend, mask, pool);
	return 0;
}

int acl_object_get_my_rights(struct acl_object *aclobj, pool_t pool,
			     const char *const **rights_r)
{
	int ret;

	if (pool->datastack_pool)
		return acl_object_get_my_rights_real(aclobj, pool, rights_r);
	T_BEGIN {
		ret = acl_object_get_my_rights_real(aclobj, pool, rights_r);
	} T_END;
	return ret;
}

const char *const *acl_object_get_default_rights(struct acl_object *aclobj)
{
	return acl_backend_mask_get_names(aclobj->backend,
					  aclobj->backend->default_aclmask,
					  pool_datastack_create());
}

int acl_object_last_changed(struct acl_object *aclobj, time_t *last_changed_r)
{
	return aclobj->backend->v->last_changed(aclobj, last_changed_r);
}

int acl_object_update(struct acl_object *aclobj,
		      const struct acl_rights_update *update)
{
	return aclobj->backend->v->object_update(aclobj, update);
}

struct acl_object_list_iter *acl_object_list_init(struct acl_object *aclobj)
{
	return aclobj->backend->v->object_list_init(aclobj);
}

bool acl_object_list_next(struct acl_object_list_iter *iter,
			 struct acl_rights *rights_r)
{
	if (iter->failed)
		return FALSE;

	return iter->aclobj->backend->v->object_list_next(iter, rights_r);
}

int acl_object_list_deinit(struct acl_object_list_iter **_iter)
{
	struct acl_object_list_iter *iter = *_iter;

	*_iter = NULL;
	return iter->aclobj->backend->v->object_list_deinit(iter);
}

struct acl_object_list_iter *
acl_default_object_list_init(struct acl_object *aclobj)
{
	struct acl_object_list_iter *iter;
	const struct acl_rights *aclobj_rights;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("acl object list", 512);
	iter = p_new(pool, struct acl_object_list_iter, 1);
	iter->pool = pool;
	iter->aclobj = aclobj;

	if (!array_is_created(&aclobj->rights)) {
		/* we may have the object cached, but we don't have all the
		   rights read into memory */
		acl_cache_flush(aclobj->backend->cache, aclobj->name);
	}

	if (aclobj->backend->v->object_refresh_cache(aclobj) < 0)
		iter->failed = TRUE;

	aclobj_rights = array_get(&aclobj->rights, &iter->count);
	if (iter->count > 0) {
		iter->rights = p_new(pool, struct acl_rights, iter->count);
		for (i = 0; i < iter->count; i++)
			acl_rights_dup(&aclobj_rights[i], pool, &iter->rights[i]);
	} else
		iter->empty = TRUE;
	return iter;
}

bool acl_default_object_list_next(struct acl_object_list_iter *iter,
				 struct acl_rights *rights_r)
{
	if (iter->failed)
		return FALSE;

	if (iter->idx == iter->count)
		return FALSE;
	*rights_r = iter->rights[iter->idx++];
	return TRUE;
}

int acl_default_object_list_deinit(struct acl_object_list_iter *iter)
{
	int ret = 0;
	if (iter->failed)
		ret = -1;
	else if (iter->empty)
		ret = 0;
	else
		ret = 1;

	pool_unref(&iter->pool);
	return ret;
}

struct acl_mailbox_list_context *
acl_backend_nonowner_lookups_iter_init(struct acl_backend *backend)
{
	return backend->v->nonowner_lookups_iter_init(backend);
}

bool acl_backend_nonowner_lookups_iter_next(struct acl_mailbox_list_context *ctx,
					   const char **name_r)
{
	return ctx->backend->v->nonowner_lookups_iter_next(ctx, name_r);
}

int acl_backend_nonowner_lookups_iter_deinit(struct acl_mailbox_list_context **_ctx)
{
	struct acl_mailbox_list_context *ctx = *_ctx;

	*_ctx = NULL;
	return ctx->backend->v->nonowner_lookups_iter_deinit(ctx);
}

int acl_backend_nonowner_lookups_rebuild(struct acl_backend *backend)
{
	return backend->v->nonowner_lookups_rebuild(backend);
}

void acl_rights_sort(struct acl_object *aclobj)
{
	struct acl_rights *rights;
	unsigned int i, dest, count;

	if (!array_is_created(&aclobj->rights))
		return;

	array_sort(&aclobj->rights, acl_rights_cmp);

	/* merge identical identifiers */
	rights = array_get_modifiable(&aclobj->rights, &count);
	for (dest = 0, i = 1; i < count; i++) {
		if (acl_rights_cmp(&rights[i], &rights[dest]) == 0) {
			/* add i's rights to dest and delete i */
			acl_right_names_merge(aclobj->rights_pool,
					      &rights[dest].rights,
					      rights[i].rights, FALSE);
			acl_right_names_merge(aclobj->rights_pool,
					      &rights[dest].neg_rights,
					      rights[i].neg_rights, FALSE);
		} else {
			if (++dest != i)
				rights[dest] = rights[i];
		}
	}
	if (++dest < count)
		array_delete(&aclobj->rights, dest, count - dest);
}

static void apply_owner_default_rights(struct acl_object *aclobj)
{
	struct acl_rights_update ru;

	i_zero(&ru);
	ru.modify_mode = ACL_MODIFY_MODE_REPLACE;
	ru.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
	ru.rights.id_type = ACL_ID_OWNER;
	ru.rights.rights = aclobj->backend->default_rights;
	ru.rights.neg_rights = empty_str_array;
	acl_cache_update(aclobj->backend->cache, aclobj->name, &ru);
}

void acl_object_rebuild_cache(struct acl_object *aclobj)
{
	struct acl_rights_update ru;
	enum acl_modify_mode add_mode;
	const struct acl_rights *rights, *prev_match = NULL;
	unsigned int i, count;
	bool first_global = TRUE;

	acl_cache_flush(aclobj->backend->cache, aclobj->name);

	if (!array_is_created(&aclobj->rights))
		return;

	/* Rights are sorted by their 1) locals first, globals next,
	   2) acl_id_type. We'll apply only the rights matching ourself.

	   Every time acl_id_type or local/global changes, the new ACLs will
	   replace all of the existing ACLs. Basically this means that if
	   user belongs to multiple matching groups or group-overrides, their
	   ACLs are merged. In all other situations the ACLs are replaced
	   (because there aren't duplicate rights entries and a user can't
	   match multiple usernames). */
	i_zero(&ru);
	rights = array_get(&aclobj->rights, &count);
	if (!acl_backend_user_is_owner(aclobj->backend))
		i = 0;
	else {
		/* we're the owner. skip over all rights entries until we
		   reach ACL_ID_OWNER or higher, or alternatively when we
		   reach a global ACL (even ACL_ID_ANYONE overrides owner's
		   rights if it's global) */
		for (i = 0; i < count; i++) {
			if (rights[i].id_type >= ACL_ID_OWNER ||
			    rights[i].global)
				break;
		}
		apply_owner_default_rights(aclobj);
		/* now continue applying the rest of the rights,
		   if there are any */
	}
	for (; i < count; i++) {
		if (!acl_backend_rights_match_me(aclobj->backend, &rights[i]))
			continue;

		if (prev_match == NULL ||
		    prev_match->id_type != rights[i].id_type ||
		    prev_match->global != rights[i].global) {
			/* replace old ACLs */
			add_mode = ACL_MODIFY_MODE_REPLACE;
		} else {
			/* merging to existing ACLs */
			i_assert(rights[i].id_type == ACL_ID_GROUP ||
				 rights[i].id_type == ACL_ID_GROUP_OVERRIDE);
			add_mode = ACL_MODIFY_MODE_ADD;
		}
		prev_match = &rights[i];

		/* If [neg_]rights is NULL it needs to be ignored.
		   The easiest way to do that is to just mark it with
		   REMOVE mode */
		ru.modify_mode = rights[i].rights == NULL ?
			ACL_MODIFY_MODE_REMOVE : add_mode;
		ru.neg_modify_mode = rights[i].neg_rights == NULL ?
			ACL_MODIFY_MODE_REMOVE : add_mode;
		ru.rights = rights[i];
		if (rights[i].global && first_global) {
			/* first global: reset negative ACLs so local ACLs
			   can't mess things up via them */
			first_global = FALSE;
			ru.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
		}
		acl_cache_update(aclobj->backend->cache, aclobj->name, &ru);
	}
}

void acl_object_remove_all_access(struct acl_object *aclobj)
{
	struct acl_rights rights;

	i_zero(&rights);
	rights.id_type = ACL_ID_ANYONE;
	rights.rights = empty_str_array;
	array_push_back(&aclobj->rights, &rights);

	rights.id_type = ACL_ID_OWNER;
	rights.rights = empty_str_array;
	array_push_back(&aclobj->rights, &rights);
}

void acl_object_add_global_acls(struct acl_object *aclobj)
{
	struct acl_backend *backend = aclobj->backend;
	const char *vname, *error;

	if (mailbox_list_is_valid_name(backend->list, aclobj->name, &error))
		vname = mailbox_list_get_vname(backend->list, aclobj->name);
	else
		vname = "";

	acl_global_file_get(backend->global_file, vname,
			    aclobj->rights_pool, &aclobj->rights);
}
