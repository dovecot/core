/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "mail-user.h"
#include "mailbox-list.h"
#include "acl-cache.h"
#include "acl-api-private.h"

struct acl_object *acl_object_init_from_name(struct acl_backend *backend,
					     const char *name)
{
	return backend->v.object_init(backend, name);
}

struct acl_object *acl_object_init_from_parent(struct acl_backend *backend,
					       const char *child_name)
{
	return backend->v.object_init_parent(backend, child_name);
}

void acl_object_deinit(struct acl_object **_aclobj)
{
	struct acl_object *aclobj = *_aclobj;

	*_aclobj = NULL;
	aclobj->backend->v.object_deinit(aclobj);
}

int acl_object_have_right(struct acl_object *aclobj, unsigned int right_idx)
{
	struct acl_backend *backend = aclobj->backend;
	const struct acl_mask *have_mask;
	unsigned int read_idx;

	if (backend->v.object_refresh_cache(aclobj) < 0)
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

	if (backend->v.object_refresh_cache(aclobj) < 0)
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
	return aclobj->backend->v.last_changed(aclobj, last_changed_r);
}

int acl_object_update(struct acl_object *aclobj,
		      const struct acl_rights_update *update)
{
        return aclobj->backend->v.object_update(aclobj, update);
}

struct acl_object_list_iter *acl_object_list_init(struct acl_object *aclobj)
{
        return aclobj->backend->v.object_list_init(aclobj);
}

int acl_object_list_next(struct acl_object_list_iter *iter,
                         struct acl_rights *rights_r)
{
	if (iter->failed)
		return -1;

	return iter->aclobj->backend->v.object_list_next(iter, rights_r);
}

void acl_object_list_deinit(struct acl_object_list_iter **_iter)
{
	struct acl_object_list_iter *iter = *_iter;

	*_iter = NULL;
        iter->aclobj->backend->v.object_list_deinit(iter);
}

struct acl_mailbox_list_context *
acl_backend_nonowner_lookups_iter_init(struct acl_backend *backend)
{
	return backend->v.nonowner_lookups_iter_init(backend);
}

int acl_backend_nonowner_lookups_iter_next(struct acl_mailbox_list_context *ctx,
					   const char **name_r)
{
	return ctx->backend->v.nonowner_lookups_iter_next(ctx, name_r);
}

void
acl_backend_nonowner_lookups_iter_deinit(struct acl_mailbox_list_context **_ctx)
{
	struct acl_mailbox_list_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->backend->v.nonowner_lookups_iter_deinit(ctx);
}

int acl_backend_nonowner_lookups_rebuild(struct acl_backend *backend)
{
	return backend->v.nonowner_lookups_rebuild(backend);
}

void acl_rights_write_id(string_t *dest, const struct acl_rights *right)
{
	switch (right->id_type) {
	case ACL_ID_ANYONE:
		str_append(dest, ACL_ID_NAME_ANYONE);
		break;
	case ACL_ID_AUTHENTICATED:
		str_append(dest, ACL_ID_NAME_AUTHENTICATED);
		break;
	case ACL_ID_OWNER:
		str_append(dest, ACL_ID_NAME_OWNER);
		break;
	case ACL_ID_USER:
		str_append(dest, ACL_ID_NAME_USER_PREFIX);
		str_append(dest, right->identifier);
		break;
	case ACL_ID_GROUP:
		str_append(dest, ACL_ID_NAME_GROUP_PREFIX);
		str_append(dest, right->identifier);
		break;
	case ACL_ID_GROUP_OVERRIDE:
		str_append(dest, ACL_ID_NAME_GROUP_OVERRIDE_PREFIX);
		str_append(dest, right->identifier);
		break;
	case ACL_ID_TYPE_COUNT:
		i_unreached();
	}
}

const char *acl_rights_get_id(const struct acl_rights *right)
{
	string_t *str = t_str_new(32);

	acl_rights_write_id(str, right);
	return str_c(str);
}

static bool is_standard_right(const char *name)
{
	unsigned int i;

	for (i = 0; all_mailbox_rights[i] != NULL; i++) {
		if (strcmp(all_mailbox_rights[i], name) == 0)
			return TRUE;
	}
	return FALSE;
}

int acl_rights_update_import(struct acl_rights_update *update,
			     const char *id, const char *const *rights,
			     const char **error_r)
{
	ARRAY_TYPE(const_string) dest_rights, dest_neg_rights, *dest;
	unsigned int i, j;

	if (acl_identifier_parse(id, &update->rights) < 0) {
		*error_r = t_strdup_printf("Invalid ID: %s", id);
		return -1;
	}
	if (rights == NULL) {
		update->modify_mode = ACL_MODIFY_MODE_CLEAR;
		update->neg_modify_mode = ACL_MODIFY_MODE_CLEAR;
		return 0;
	}

	t_array_init(&dest_rights, 8);
	t_array_init(&dest_neg_rights, 8);
	for (i = 0; rights[i] != NULL; i++) {
		const char *right = rights[i];

		if (right[0] != '-')
			dest = &dest_rights;
		else {
			right++;
			dest = &dest_neg_rights;
		}
		if (strcmp(right, "all") != 0) {
			if (*right == ':') {
				/* non-standard right */
				right++;
				array_append(dest, &right, 1);
			} else if (is_standard_right(right)) {
				array_append(dest, &right, 1);
			} else {
				*error_r = t_strdup_printf("Invalid right '%s'",
							   right);
				return -1;
			}
		} else {
			for (j = 0; all_mailbox_rights[j] != NULL; j++)
				array_append(dest, &all_mailbox_rights[j], 1);
		}
	}
	if (array_count(&dest_rights) > 0) {
		array_append_zero(&dest_rights);
		update->rights.rights = array_idx(&dest_rights, 0);
	} else if (update->modify_mode == ACL_MODIFY_MODE_REPLACE) {
		update->modify_mode = ACL_MODIFY_MODE_CLEAR;
	}
	if (array_count(&dest_neg_rights) > 0) {
		array_append_zero(&dest_neg_rights);
		update->rights.neg_rights = array_idx(&dest_neg_rights, 0);
	} else if (update->neg_modify_mode == ACL_MODIFY_MODE_REPLACE) {
		update->neg_modify_mode = ACL_MODIFY_MODE_CLEAR;
	}
	return 0;
}

const char *acl_rights_export(const struct acl_rights *rights)
{
	string_t *str = t_str_new(128);

	if (rights->rights != NULL)
		str_append(str, t_strarray_join(rights->rights, " "));
	if (rights->neg_rights != NULL) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append_c(str, '-');
		str_append(str, t_strarray_join(rights->neg_rights, " -"));
	}
	return str_c(str);
}

bool acl_rights_has_nonowner_lookup_changes(const struct acl_rights *rights)
{
	const char *const *p;

	if (rights->id_type == ACL_ID_OWNER) {
		/* ignore owner rights */
		return FALSE;
	}

	if (rights->rights == NULL)
		return FALSE;

	for (p = rights->rights; *p != NULL; p++) {
		if (strcmp(*p, MAIL_ACL_LOOKUP) == 0)
			return TRUE;
	}
	return FALSE;
}

int acl_identifier_parse(const char *line, struct acl_rights *rights)
{
	if (strncmp(line, ACL_ID_NAME_USER_PREFIX,
		    strlen(ACL_ID_NAME_USER_PREFIX)) == 0) {
		rights->id_type = ACL_ID_USER;
		rights->identifier = line + 5;
	} else if (strcmp(line, ACL_ID_NAME_OWNER) == 0) {
		rights->id_type = ACL_ID_OWNER;
	} else if (strncmp(line, ACL_ID_NAME_GROUP_PREFIX,
			   strlen(ACL_ID_NAME_GROUP_PREFIX)) == 0) {
		rights->id_type = ACL_ID_GROUP;
		rights->identifier = line + 6;
	} else if (strncmp(line, ACL_ID_NAME_GROUP_OVERRIDE_PREFIX,
			   strlen(ACL_ID_NAME_GROUP_OVERRIDE_PREFIX)) == 0) {
		rights->id_type = ACL_ID_GROUP_OVERRIDE;
		rights->identifier = line + 15;
	} else if (strcmp(line, ACL_ID_NAME_AUTHENTICATED) == 0) {
		rights->id_type = ACL_ID_AUTHENTICATED;
	} else if (strcmp(line, ACL_ID_NAME_ANYONE) == 0 ||
		   strcmp(line, "anonymous") == 0) {
		rights->id_type = ACL_ID_ANYONE;
	} else {
		return -1;
	}
	return 0;
}
