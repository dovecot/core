/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "dict.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "acl-api-private.h"
#include "acl-storage.h"
#include "acl-plugin.h"
#include "acl-lookup-dict.h"

#include <stdlib.h>

#define DICT_SHARED_BOXES_PATH "shared-boxes/"

struct acl_lookup_dict {
	struct mail_user *user;
};

struct acl_lookup_dict_iter {
	pool_t pool;
	struct acl_lookup_dict *dict;

	ARRAY_TYPE(const_string) iter_ids;
	struct dict_iterate_context *dict_iter;
	unsigned int iter_idx;

	const char *prefix;
	unsigned int prefix_len;

	unsigned int failed:1;
};

static struct dict *acl_dict;

void acl_lookup_dicts_init(void)
{
	const char *uri;

	uri = getenv("ACL_SHARED_DICT");
	if (uri == NULL) {
		if (getenv("DEBUG") != NULL) {
			i_info("acl: No acl_shared_dict setting - "
			       "shared mailbox listing is disabled");
		}
		return;
	}

	acl_dict = dict_init(uri, DICT_DATA_TYPE_STRING, "");
	if (acl_dict == NULL)
		i_fatal("acl: dict_init(%s) failed", uri);
}

void acl_lookup_dicts_deinit(void)
{
	if (acl_dict != NULL)
		dict_deinit(&acl_dict);
}

struct acl_lookup_dict *acl_lookup_dict_init(struct mail_user *user)
{
	struct acl_lookup_dict *dict;

	dict = i_new(struct acl_lookup_dict, 1);
	dict->user = user;
	return dict;
}

void acl_lookup_dict_deinit(struct acl_lookup_dict **_dict)
{
	struct acl_lookup_dict *dict = *_dict;

	*_dict = NULL;
	i_free(dict);
}

static void
acl_lookup_dict_write_rights_id(string_t *dest, const struct acl_rights *right)
{
	switch (right->id_type) {
	case ACL_ID_ANYONE:
	case ACL_ID_AUTHENTICATED:
		/* don't bother separating these */
		str_append(dest, "anyone");
		break;
	case ACL_ID_USER:
		str_append(dest, "user/");
		str_append(dest, right->identifier);
		break;
	case ACL_ID_GROUP:
	case ACL_ID_GROUP_OVERRIDE:
		str_append(dest, "group/");
		str_append(dest, right->identifier);
		break;
	case ACL_ID_OWNER:
	case ACL_ID_TYPE_COUNT:
		i_unreached();
	}
}

static int acl_lookup_dict_rebuild_add_backend(struct mail_namespace *ns,
					       ARRAY_TYPE(const_string) *ids)
{
	struct acl_backend *backend;
	struct acl_mailbox_list_context *ctx;
	struct acl_object *aclobj;
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	const char *name, *id_dup;
	string_t *id;
	int ret, ret2 = 0;

	if ((ns->flags & NAMESPACE_FLAG_INTERNAL) != 0)
		return 0;

	id = t_str_new(128);
	backend = acl_storage_get_backend(ns->storage);
	ctx = acl_backend_nonowner_lookups_iter_init(backend);
	while ((ret = acl_backend_nonowner_lookups_iter_next(ctx, &name)) > 0) {
		aclobj = acl_object_init_from_name(backend, ns->storage, name);

		iter = acl_object_list_init(aclobj);
		while ((ret = acl_object_list_next(iter, &rights)) > 0) {
			if (acl_rights_has_nonowner_lookup_changes(&rights)) {
				str_truncate(id, 0);
				acl_lookup_dict_write_rights_id(id, &rights);
				id_dup = t_strdup(str_c(id));
				array_append(ids, &id_dup, 1);
			}
		}
		acl_object_list_deinit(&iter);
		if (ret < 0)
			ret2 = -1;
		acl_object_deinit(&aclobj);
	}
	acl_backend_nonowner_lookups_iter_deinit(&ctx);
	return ret < 0 || ret2 < 0 ? -1 : 0;
}

static int
acl_lookup_dict_rebuild_update(struct acl_lookup_dict *dict,
			       const ARRAY_TYPE(const_string) *new_ids_arr,
			       bool no_removes)
{
	const char *username = dict->user->username;
	struct dict_iterate_context *iter;
	struct dict_transaction_context *dt;
	const char *prefix, *key, *value, **old_ids, *const *new_ids, *p;
	ARRAY_TYPE(const_string) old_ids_arr;
	unsigned int newi, oldi, old_count, new_count;
	string_t *path;
	unsigned int prefix_len;
	int ret;

	/* get all existing identifiers for the user */
	t_array_init(&old_ids_arr, 128);
	prefix = DICT_PATH_SHARED DICT_SHARED_BOXES_PATH;
	prefix_len = strlen(prefix);
	iter = dict_iterate_init(acl_dict, prefix, DICT_ITERATE_FLAG_RECURSE);
	while ((ret = dict_iterate(iter, &key, &value)) > 0) {
		/* prefix/$dest/$source */
		key += prefix_len;
		p = strchr(key, '/');
		if (p != NULL && strcmp(p + 1, username) == 0) {
			key = t_strdup_until(key, p);
			array_append(&old_ids_arr, &key, 1);
		}
	}
	dict_iterate_deinit(&iter);
	if (ret < 0) {
		i_error("acl: dict iteration failed, can't update dict");
		return -1;
	}

	/* sort the existing identifiers */
	old_ids = array_get_modifiable(&old_ids_arr, &old_count);
	qsort(old_ids, old_count, sizeof(*old_ids), i_strcmp_p);

	/* sync the identifiers */
	path = t_str_new(256);
	str_append(path, prefix);

	dt = dict_transaction_begin(acl_dict);
	new_ids = array_get(new_ids_arr, &new_count);
	for (newi = oldi = 0; newi < new_count || oldi < old_count; ) {
		ret = newi == new_count ? 1 :
			oldi == old_count ? -1 :
			strcmp(new_ids[newi], old_ids[oldi]);
		if (ret == 0) {
			newi++; oldi++;
		} else if (ret < 0) {
			/* new identifier, add it */
			str_truncate(path, prefix_len);
			str_append(path, new_ids[newi]);
			str_append_c(path, '/');
			str_append(path, username);
			dict_set(dt, str_c(path), "1");
			newi++;
		} else if (!no_removes) {
			/* old identifier removed */
			str_truncate(path, prefix_len);
			str_append(path, old_ids[oldi]);
			str_append_c(path, '/');
			str_append(path, username);
			dict_unset(dt, str_c(path));
			oldi++;
		}
	}
	if (dict_transaction_commit(&dt) < 0) {
		i_error("acl: dict commit failed");
		return -1;
	}
	return 0;
}

int acl_lookup_dict_rebuild(struct acl_lookup_dict *dict)
{
	struct mail_namespace *ns;
	ARRAY_TYPE(const_string) ids_arr;
	const char **ids;
	unsigned int i, dest, count;
	int ret = 0;

	if (acl_dict == NULL)
		return 0;

	/* get all ACL identifiers with a positive lookup right */
	t_array_init(&ids_arr, 128);
	for (ns = dict->user->namespaces; ns != NULL; ns = ns->next) {
		if (acl_lookup_dict_rebuild_add_backend(ns, &ids_arr) < 0)
			ret = -1;
	}

	/* sort identifiers and remove duplicates */
	ids = array_get_modifiable(&ids_arr, &count);
	qsort(ids, count, sizeof(*ids), i_strcmp_p);

	for (i = 1, dest = 0; i < count; i++) {
		if (strcmp(ids[dest], ids[i]) != 0) {
			if (++dest != i)
				ids[dest] = ids[i];
		}
	}
	if (++dest < count)
		array_delete(&ids_arr, dest, count-dest);

	/* if lookup failed at some point we can still add new ids,
	   but we can't remove any existing ones */
	if (acl_lookup_dict_rebuild_update(dict, &ids_arr, ret < 0) < 0)
		ret = -1;
	return ret;
}

static void acl_lookup_dict_iterate_start(struct acl_lookup_dict_iter *iter)
{
	const char *const *idp;

	idp = array_idx(&iter->iter_ids, iter->iter_idx);
	iter->iter_idx++;
	iter->prefix = p_strconcat(iter->pool, DICT_PATH_SHARED
				   DICT_SHARED_BOXES_PATH, *idp, "/", NULL);
	iter->prefix_len = strlen(iter->prefix);

	iter->dict_iter = dict_iterate_init(acl_dict, iter->prefix,
					    DICT_ITERATE_FLAG_RECURSE);
}

struct acl_lookup_dict_iter *
acl_lookup_dict_iterate_visible_init(struct acl_lookup_dict *dict)
{
	struct acl_user *auser = ACL_USER_CONTEXT(dict->user);
	struct acl_lookup_dict_iter *iter;
	const char *id;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("acl lookup dict iter", 512);
	iter = p_new(pool, struct acl_lookup_dict_iter, 1);
	iter->pool = pool;
	iter->dict = dict;

	p_array_init(&iter->iter_ids, pool, 16);
	id = "anyone";
	array_append(&iter->iter_ids, &id, 1);
	id = p_strconcat(pool, "user/", dict->user->username, NULL);
	array_append(&iter->iter_ids, &id, 1);

	/* get all groups we belong to */
	if (auser->groups != NULL) {
		for (i = 0; auser->groups[i] != NULL; i++) {
			id = p_strconcat(pool, "group/", auser->groups[i],
					 NULL);
			array_append(&iter->iter_ids, &id, 1);
		}
	}

	/* iterate through all identifiers that match us, start with the
	   first one */
	if (acl_dict != NULL)
		acl_lookup_dict_iterate_start(iter);
	return iter;
}

const char *
acl_lookup_dict_iterate_visible_next(struct acl_lookup_dict_iter *iter)
{
	const char *key, *value;
	int ret;

	if (iter->dict_iter == NULL)
		return 0;

	ret = dict_iterate(iter->dict_iter, &key, &value);
	if (ret > 0) {
		i_assert(iter->prefix_len < strlen(key));
		return key + iter->prefix_len;
	}
	if (ret < 0)
		iter->failed = TRUE;
	dict_iterate_deinit(&iter->dict_iter);

	if (iter->iter_idx < array_count(&iter->iter_ids)) {
		/* get to the next iterator */
		acl_lookup_dict_iterate_start(iter);
		return acl_lookup_dict_iterate_visible_next(iter);
	}
	return NULL;
}

int acl_lookup_dict_iterate_visible_deinit(struct acl_lookup_dict_iter **_iter)
{
	struct acl_lookup_dict_iter *iter = *_iter;
	int ret = iter->failed ? -1 : 0;

	*_iter = NULL;
	if (iter->dict_iter != NULL)
		dict_iterate_deinit(&iter->dict_iter);
	pool_unref(&iter->pool);
	return ret;
}
