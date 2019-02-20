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

struct acl_letter_map {
	char letter;
	const char *name;
};

static const struct acl_letter_map acl_letter_map[] = {
	{ 'l', MAIL_ACL_LOOKUP },
	{ 'r', MAIL_ACL_READ },
	{ 'w', MAIL_ACL_WRITE },
	{ 's', MAIL_ACL_WRITE_SEEN },
	{ 't', MAIL_ACL_WRITE_DELETED },
	{ 'i', MAIL_ACL_INSERT },
	{ 'p', MAIL_ACL_POST },
	{ 'e', MAIL_ACL_EXPUNGE },
	{ 'k', MAIL_ACL_CREATE },
	{ 'x', MAIL_ACL_DELETE },
	{ 'a', MAIL_ACL_ADMIN },
	{ '\0', NULL }
};

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

bool acl_object_list_next(struct acl_object_list_iter *iter,
			 struct acl_rights *rights_r)
{
	if (iter->failed)
		return FALSE;

	return iter->aclobj->backend->v.object_list_next(iter, rights_r);
}

int acl_object_list_deinit(struct acl_object_list_iter **_iter)
{
	struct acl_object_list_iter *iter = *_iter;

	*_iter = NULL;
	return iter->aclobj->backend->v.object_list_deinit(iter);
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

	if (aclobj->backend->v.object_refresh_cache(aclobj) < 0)
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
	return backend->v.nonowner_lookups_iter_init(backend);
}

bool acl_backend_nonowner_lookups_iter_next(struct acl_mailbox_list_context *ctx,
					   const char **name_r)
{
	return ctx->backend->v.nonowner_lookups_iter_next(ctx, name_r);
}

int acl_backend_nonowner_lookups_iter_deinit(struct acl_mailbox_list_context **_ctx)
{
	struct acl_mailbox_list_context *ctx = *_ctx;

	*_ctx = NULL;
	return ctx->backend->v.nonowner_lookups_iter_deinit(ctx);
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
				array_push_back(dest, &right);
			} else if (is_standard_right(right)) {
				array_push_back(dest, &right);
			} else {
				*error_r = t_strdup_printf("Invalid right '%s'",
							   right);
				return -1;
			}
		} else {
			for (j = 0; all_mailbox_rights[j] != NULL; j++)
				array_push_back(dest, &all_mailbox_rights[j]);
		}
	}
	if (array_count(&dest_rights) > 0) {
		array_append_zero(&dest_rights);
		update->rights.rights = array_front(&dest_rights);
	} else if (update->modify_mode == ACL_MODIFY_MODE_REPLACE) {
		update->modify_mode = ACL_MODIFY_MODE_CLEAR;
	}
	if (array_count(&dest_neg_rights) > 0) {
		array_append_zero(&dest_neg_rights);
		update->rights.neg_rights = array_front(&dest_neg_rights);
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
	if (rights->neg_rights != NULL && rights->neg_rights[0] != NULL) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append_c(str, '-');
		str_append(str, t_strarray_join(rights->neg_rights, " -"));
	}
	return str_c(str);
}

int acl_rights_parse_line(const char *line, pool_t pool,
			  struct acl_rights *rights_r, const char **error_r)
{
	const char *id_str, *const *right_names, *error = NULL;

	/* <id> [<imap acls>] [:<named acls>] */
	if (*line == '"') {
		line++;
		if (str_unescape_next(&line, &id_str) < 0 ||
		    (line[0] != ' ' && line[0] != '\0')) {
			*error_r = "Invalid quoted ID";
			return -1;
		}
		if (line[0] == ' ')
			line++;
	} else {
		id_str = line;
		line = strchr(id_str, ' ');
		if (line == NULL)
			line = "";
		else
			id_str = t_strdup_until(id_str, line++);
	}

	i_zero(rights_r);

	right_names = acl_right_names_parse(pool, line, &error);
	if (*id_str != '-')
		rights_r->rights = right_names;
	else {
		id_str++;
		rights_r->neg_rights = right_names;
	}

	if (acl_identifier_parse(id_str, rights_r) < 0)
		error = t_strdup_printf("Unknown ID '%s'", id_str);

	if (error != NULL) {
		*error_r = error;
		return -1;
	}

	rights_r->identifier = p_strdup(pool, rights_r->identifier);
	return 0;
}

void acl_rights_dup(const struct acl_rights *src,
		    pool_t pool, struct acl_rights *dest_r)
{
	i_zero(dest_r);
	dest_r->id_type = src->id_type;
	dest_r->identifier = p_strdup(pool, src->identifier);
	dest_r->rights = src->rights == NULL ? NULL :
		p_strarray_dup(pool, src->rights);
	dest_r->neg_rights = src->neg_rights == NULL ? NULL :
		p_strarray_dup(pool, src->neg_rights);
	dest_r->global = src->global;
}

int acl_rights_cmp(const struct acl_rights *r1, const struct acl_rights *r2)
{
	int ret;

	if (r1->global != r2->global) {
		/* globals have higher priority than locals */
		return r1->global ? 1 : -1;
	}

	ret = r1->id_type - r2->id_type;
	if (ret != 0)
		return ret;

	return null_strcmp(r1->identifier, r2->identifier);
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
	if (++dest != count)
		array_delete(&aclobj->rights, dest, count - dest);
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
	if (str_begins(line, ACL_ID_NAME_USER_PREFIX)) {
		rights->id_type = ACL_ID_USER;
		rights->identifier = line + 5;
	} else if (strcmp(line, ACL_ID_NAME_OWNER) == 0) {
		rights->id_type = ACL_ID_OWNER;
	} else if (str_begins(line, ACL_ID_NAME_GROUP_PREFIX)) {
		rights->id_type = ACL_ID_GROUP;
		rights->identifier = line + 6;
	} else if (str_begins(line, ACL_ID_NAME_GROUP_OVERRIDE_PREFIX)) {
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

static const char *const *
acl_right_names_alloc(pool_t pool, ARRAY_TYPE(const_string) *rights_arr,
		      bool dup_strings)
{
	const char **ret, *const *rights;
	unsigned int i, dest, count;

	/* sort the rights first so we can easily drop duplicates */
	array_sort(rights_arr, i_strcmp_p);

	/* @UNSAFE */
	rights = array_get(rights_arr, &count);
	ret = p_new(pool, const char *, count + 1);
	if (count > 0) {
		ret[0] = rights[0];
		for (i = dest = 1; i < count; i++) {
			if (strcmp(rights[i-1], rights[i]) != 0)
				ret[dest++] = rights[i];
		}
		ret[dest] = NULL;
		if (dup_strings) {
			for (i = 0; i < dest; i++)
				ret[i] = p_strdup(pool, ret[i]);
		}
	}
	return ret;
}

const char *const *
acl_right_names_parse(pool_t pool, const char *acl, const char **error_r)
{
	ARRAY_TYPE(const_string) rights;
	const char *const *names;
	unsigned int i;

	/* parse IMAP ACL list */
	while (*acl == ' ' || *acl == '\t')
		acl++;

	t_array_init(&rights, 64);
	while (*acl != '\0' && *acl != ' ' && *acl != '\t' && *acl != ':') {
		for (i = 0; acl_letter_map[i].letter != '\0'; i++) {
			if (acl_letter_map[i].letter == *acl)
				break;
		}

		if (acl_letter_map[i].letter == '\0') {
			*error_r = t_strdup_printf("Unknown ACL '%c'", *acl);
			return NULL;
		}

		array_push_back(&rights, &acl_letter_map[i].name);
		acl++;
	}
	while (*acl == ' ' || *acl == '\t') acl++;

	if (*acl != '\0') {
		/* parse our own extended ACLs */
		if (*acl != ':') {
			*error_r = "Missing ':' prefix in ACL extensions";
			return NULL;
		}

		names = t_strsplit_spaces(acl + 1, ", \t");
		for (; *names != NULL; names++) {
			const char *name = p_strdup(pool, *names);
			array_push_back(&rights, &name);
		}
	}

	return acl_right_names_alloc(pool, &rights, FALSE);
}

void acl_right_names_write(string_t *dest, const char *const *rights)
{
	char c2[2];
	unsigned int i, j, pos;

	c2[1] = '\0';
	pos = str_len(dest);
	for (i = 0; rights[i] != NULL; i++) {
		/* use letters if possible */
		for (j = 0; acl_letter_map[j].name != NULL; j++) {
			if (strcmp(rights[i], acl_letter_map[j].name) == 0) {
				c2[0] = acl_letter_map[j].letter;
				str_insert(dest, pos, c2);
				pos++;
				break;
			}
		}
		if (acl_letter_map[j].name == NULL) {
			/* fallback to full name */
			str_append_c(dest, ' ');
			str_append(dest, rights[i]);
		}
	}
	if (pos + 1 < str_len(dest)) {
		c2[0] = ':';
		str_insert(dest, pos + 1, c2);
	}
}

void acl_right_names_merge(pool_t pool, const char *const **destp,
			   const char *const *src, bool dup_strings)
{
	const char *const *dest = *destp;
	ARRAY_TYPE(const_string) rights;
	unsigned int i;

	t_array_init(&rights, 64);
	if (dest != NULL) {
		for (i = 0; dest[i] != NULL; i++)
			array_push_back(&rights, &dest[i]);
	}
	if (src != NULL) {
		for (i = 0; src[i] != NULL; i++)
			array_push_back(&rights, &src[i]);
	}

	*destp = acl_right_names_alloc(pool, &rights, dup_strings);
}

bool acl_right_names_modify(pool_t pool,
			    const char *const **rightsp,
			    const char *const *modify_rights,
			    enum acl_modify_mode modify_mode)
{
	const char *const *old_rights = *rightsp;
	const char *const *new_rights = NULL;
	const char *null = NULL;
	ARRAY_TYPE(const_string) rights;
	unsigned int i, j;

	if (modify_rights == NULL && modify_mode != ACL_MODIFY_MODE_CLEAR) {
		/* nothing to do here */
		return FALSE;
	}

	switch (modify_mode) {
	case ACL_MODIFY_MODE_REMOVE:
		if (old_rights == NULL || *old_rights == NULL) {
			/* nothing to do */
			return FALSE;
		}
		t_array_init(&rights, 64);
		for (i = 0; old_rights[i] != NULL; i++) {
			for (j = 0; modify_rights[j] != NULL; j++) {
				if (strcmp(old_rights[i], modify_rights[j]) == 0)
					break;
			}
			if (modify_rights[j] == NULL)
				array_push_back(&rights, &old_rights[i]);
		}
		new_rights = &null;
		modify_rights = array_count(&rights) == 0 ? NULL :
			array_front(&rights);
		acl_right_names_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_ADD:
		new_rights = old_rights;
		acl_right_names_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_REPLACE:
		new_rights = &null;
		acl_right_names_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_CLEAR:
		if (*rightsp == NULL) {
			/* ACL didn't exist before either */
			return FALSE;
		}
		*rightsp = NULL;
		return TRUE;
	}
	i_assert(new_rights != NULL);
	*rightsp = new_rights;

	if (old_rights == NULL)
		return new_rights[0] != NULL;

	/* see if anything changed */
	for (i = 0; old_rights[i] != NULL && new_rights[i] != NULL; i++) {
		if (strcmp(old_rights[i], new_rights[i]) != 0)
			return TRUE;
	}
	return old_rights[i] != NULL || new_rights[i] != NULL;
}

static void apply_owner_default_rights(struct acl_object *aclobj)
{
	struct acl_rights_update ru;
	const char *null = NULL;

	i_zero(&ru);
	ru.modify_mode = ACL_MODIFY_MODE_REPLACE;
	ru.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
	ru.rights.id_type = ACL_ID_OWNER;
	ru.rights.rights = aclobj->backend->default_rights;
	ru.rights.neg_rights = &null;
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
	static const char *null = NULL;
	struct acl_rights rights;

	i_zero(&rights);
	rights.id_type = ACL_ID_ANYONE;
	rights.rights = &null;
	array_push_back(&aclobj->rights, &rights);

	rights.id_type = ACL_ID_OWNER;
	rights.rights = &null;
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
