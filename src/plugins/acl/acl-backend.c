/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "sort.h"
#include "mail-storage-settings.h"
#include "mailbox-list.h"
#include "mail-namespace.h"
#include "mail-user.h"
#include "acl-cache.h"
#include "acl-api-private.h"


extern struct acl_backend_vfuncs acl_backend_vfile;

const char *const all_mailbox_rights[] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_POST,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN,
	NULL
};

static const char *const *owner_mailbox_rights = all_mailbox_rights;
static const char *const non_owner_mailbox_rights[] = { NULL };

struct acl_backend *
acl_backend_init(const char *data, struct mailbox_list *list,
		 const char *acl_username, const char *const *groups,
		 bool owner)
{
	struct mail_user *user = mailbox_list_get_user(list);
	struct acl_backend *backend;
	unsigned int i, group_count;

	e_debug(user->event, "acl: initializing backend with data: %s", data);
	e_debug(user->event, "acl: acl username = %s", acl_username);
	e_debug(user->event, "acl: owner = %d", owner ? 1 : 0);

	group_count = str_array_length(groups);

	if (str_begins(data, "vfile:"))
		data += 6;
	else if (strcmp(data, "vfile") == 0)
		data = "";
	else
		i_fatal("Unknown ACL backend: %s", t_strcut(data, ':'));

	backend = acl_backend_vfile.alloc();
	backend->debug = user->mail_debug;
	backend->v = acl_backend_vfile;
	backend->list = list;
	backend->username = p_strdup(backend->pool, acl_username);
	backend->owner = owner;
	backend->globals_only =
		mail_user_plugin_getenv_bool(user, "acl_globals_only");

	if (group_count > 0) {
		backend->group_count = group_count;
		backend->groups =
			p_new(backend->pool, const char *, group_count);
		for (i = 0; i < group_count; i++) {
			backend->groups[i] = p_strdup(backend->pool, groups[i]);
			e_debug(user->event, "acl: group added: %s", groups[i]);
		}
		i_qsort(backend->groups, group_count, sizeof(const char *),
			i_strcmp_p);
	}

	T_BEGIN {
		if (acl_backend_vfile.init(backend, data) < 0)
			i_fatal("acl: backend vfile init failed with data: %s",
				data);
	} T_END;

	backend->default_rights = owner ? owner_mailbox_rights :
		non_owner_mailbox_rights;
	backend->default_aclmask =
		acl_cache_mask_init(backend->cache, backend->pool,
				    backend->default_rights);
	return backend;
}

void acl_backend_deinit(struct acl_backend **_backend)
{
	struct acl_backend *backend = *_backend;

	*_backend = NULL;

	if (backend->default_aclobj != NULL)
		acl_object_deinit(&backend->default_aclobj);
	acl_cache_deinit(&backend->cache);
	backend->v.deinit(backend);
}

const char *acl_backend_get_acl_username(struct acl_backend *backend)
{
	return backend->username;
}

bool acl_backend_user_is_authenticated(struct acl_backend *backend)
{
	return backend->username != NULL;
}

bool acl_backend_user_is_owner(struct acl_backend *backend)
{
	return backend->owner;
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
	return i_bsearch(group_name, backend->groups, backend->group_count,
			 sizeof(const char *), bsearch_strcmp) != NULL;
}

bool acl_backend_rights_match_me(struct acl_backend *backend,
				 const struct acl_rights *rights)
{
	switch (rights->id_type) {
	case ACL_ID_ANYONE:
		return TRUE;
	case ACL_ID_AUTHENTICATED:
		return acl_backend_user_is_authenticated(backend);
	case ACL_ID_GROUP:
	case ACL_ID_GROUP_OVERRIDE:
		return acl_backend_user_is_in_group(backend, rights->identifier);
	case ACL_ID_USER:
		return acl_backend_user_name_equals(backend, rights->identifier);
	case ACL_ID_OWNER:
		return acl_backend_user_is_owner(backend);
	case ACL_ID_TYPE_COUNT:
		break;
	}
	i_unreached();
}

unsigned int acl_backend_lookup_right(struct acl_backend *backend,
				      const char *right)
{
	return acl_cache_right_lookup(backend->cache, right);
}

struct acl_object *acl_backend_get_default_object(struct acl_backend *backend)
{
	struct mail_user *user = mailbox_list_get_user(backend->list);
	struct mail_namespace *ns = mailbox_list_get_namespace(backend->list);
	const char *default_name = "";

	if (backend->default_aclobj != NULL)
		return backend->default_aclobj;

	if (mail_user_plugin_getenv_bool(user, "acl_defaults_from_inbox")) {
		if (ns->type == MAIL_NAMESPACE_TYPE_PRIVATE ||
		    ns->type == MAIL_NAMESPACE_TYPE_SHARED)
			default_name = "INBOX";
	}
	backend->default_aclobj =
		acl_object_init_from_name(backend, default_name);
	return backend->default_aclobj;
}

int acl_backend_get_default_rights(struct acl_backend *backend,
				   const struct acl_mask **mask_r)
{
	struct acl_object *aclobj = acl_backend_get_default_object(backend);

	if (backend->v.object_refresh_cache(aclobj) < 0)
		return -1;

	*mask_r = acl_cache_get_my_rights(backend->cache, aclobj->name);
	if (*mask_r == NULL)
		*mask_r = backend->default_aclmask;
	return 0;
}
