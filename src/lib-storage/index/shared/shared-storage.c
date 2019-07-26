/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "var-expand.h"
#include "index-storage.h"
#include "mail-storage-service.h"
#include "mailbox-list-private.h"
#include "fail-mail-storage.h"
#include "shared-storage.h"

#include <ctype.h>

extern struct mail_storage shared_storage;

static struct mail_storage *shared_storage_alloc(void)
{
	struct shared_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("shared storage", 1024);
	storage = p_new(pool, struct shared_storage, 1);
	storage->storage = shared_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static int
shared_storage_create(struct mail_storage *_storage, struct mail_namespace *ns,
		      const char **error_r)
{
	struct shared_storage *storage = SHARED_STORAGE(_storage);
	const char *driver, *p;
	char *wildcardp, key;
	bool have_username;

	/* location must begin with the actual mailbox driver */
	p = strchr(ns->set->location, ':');
	if (p == NULL) {
		*error_r = "Shared mailbox location not prefixed with driver";
		return -1;
	}
	driver = t_strdup_until(ns->set->location, p);
	storage->location = p_strdup(_storage->pool, ns->set->location);
	storage->unexpanded_location =
		p_strdup(_storage->pool, ns->unexpanded_set->location);
	storage->storage_class_name = p_strdup(_storage->pool, driver);

	if (mail_user_get_storage_class(_storage->user, driver) == NULL &&
	    strcmp(driver, "auto") != 0) {
		*error_r = t_strconcat("Unknown shared storage driver: ",
				       driver, NULL);
		return -1;
	}

	wildcardp = strchr(ns->prefix, '%');
	if (wildcardp == NULL) {
		*error_r = "Shared namespace prefix doesn't contain %";
		return -1;
	}
	storage->ns_prefix_pattern = p_strdup(_storage->pool, wildcardp);

	have_username = FALSE;
	for (p = storage->ns_prefix_pattern; *p != '\0'; p++) {
		if (*p != '%')
			continue;

		key = p[1];
		if (key == 'u' || key == 'n')
			have_username = TRUE;
		else if (key != '%' && key != 'd')
			break;
	}
	if (*p != '\0') {
		*error_r = "Shared namespace prefix contains unknown variables";
		return -1;
	}
	if (!have_username) {
		*error_r = "Shared namespace prefix doesn't contain %u or %n";
		return -1;
	}
	if (p[-1] != mail_namespace_get_sep(ns) &&
	    (ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			  NAMESPACE_FLAG_LIST_CHILDREN)) != 0) {
		*error_r = "Shared namespace prefix doesn't end with hierarchy separator";
		return -1;
	}

	/* truncate prefix after the above checks are done, so they can log
	   the full prefix in error conditions */
	*wildcardp = '\0';
	ns->prefix_len = strlen(ns->prefix);
	return 0;
}

static void
shared_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				 struct mailbox_list_settings *set)
{
	set->layout = "shared";
}

static void
get_nonexistent_user_location(struct shared_storage *storage,
			      const char *username, string_t *location)
{
	/* user wasn't found. we'll still need to create the storage
	   to avoid exposing which users exist and which don't. */
	str_append(location, storage->storage_class_name);
	str_append_c(location, ':');

	/* use a reachable but nonexistent path as the mail root directory */
	str_append(location, storage->storage.user->set->base_dir);
	str_append(location, "/user-not-found/");
	str_append(location, username);
}

static bool shared_namespace_exists(struct mail_namespace *ns)
{
	const char *path;
	struct stat st;

	path = mailbox_list_get_root_forced(ns->list, MAILBOX_LIST_PATH_TYPE_DIR);
	if (path == NULL) {
		/* we can't know if this exists */
		return TRUE;
	}
	return stat(path, &st) == 0;
}

int shared_storage_get_namespace(struct mail_namespace **_ns,
				 const char **_name)
{
	struct mail_storage *_storage = (*_ns)->storage;
	struct mailbox_list *list = (*_ns)->list;
	struct shared_storage *storage = SHARED_STORAGE(_storage);
	struct mail_user *user = _storage->user;
	struct mail_namespace *new_ns, *ns = *_ns;
	struct mail_namespace_settings *ns_set, *unexpanded_ns_set;
	struct mail_user *owner;
	const char *domain = NULL, *username = NULL, *userdomain = NULL;
	const char *name, *p, *next, **dest, *error;
	string_t *prefix, *location;
	char ns_sep = mail_namespace_get_sep(ns);
	int ret;

	p = storage->ns_prefix_pattern;
	for (name = *_name; *p != '\0';) {
		if (*p != '%') {
			if (*p != *name)
				break;
			p++; name++;
			continue;
		}
		switch (*++p) {
		case 'd':
			dest = &domain;
			break;
		case 'n':
			dest = &username;
			break;
		case 'u':
			dest = &userdomain;
			break;
		default:
			/* we checked this already above */
			i_unreached();
		}
		p++;

		next = strchr(name, *p != '\0' ? *p : ns_sep);
		if (next == NULL) {
			*dest = name;
			name = "";
			break;
		}
		*dest = t_strdup_until(name, next);
		name = next;
	}
	if (*p != '\0') {
		if (*name == '\0' ||
		    (name[1] == '\0' && *name == ns_sep)) {
			/* trying to open <prefix>/<user> mailbox */
			name = "INBOX";
		} else {
			mailbox_list_set_critical(list,
					"Invalid namespace prefix %s vs %s",
					storage->ns_prefix_pattern, *_name);
			return -1;
		}
	}

	/* successfully matched the name. */
	if (userdomain != NULL) {
		/* user@domain given */
		domain = strchr(userdomain, '@');
		if (domain == NULL)
			username = userdomain;
		else {
			username = t_strdup_until(userdomain, domain);
			domain++;
		}
	} else if (username == NULL) {
		/* trying to open namespace "shared/domain"
		   namespace prefix. */
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				       T_MAIL_ERR_MAILBOX_NOT_FOUND(*_name));
		return -1;
	} else {
		if (domain == NULL) {
			/* no domain given, use ours (if we have one) */
			domain = i_strchr_to_next(user->username, '@');
		}
		userdomain = domain == NULL ? username :
			t_strconcat(username, "@", domain, NULL);
	}
	if (*userdomain == '\0') {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Empty username doesn't exist");
		return -1;
	}

	/* expand the namespace prefix and see if it already exists.
	   this should normally happen only when the mailbox is being opened */
	struct var_expand_table tab[] = {
		{ 'u', userdomain, "user" },
		{ 'n', username, "username" },
		{ 'd', domain, "domain" },
		{ 'h', NULL, "home" },
		{ '\0', NULL, NULL }
	};

	prefix = t_str_new(128);
	str_append(prefix, ns->prefix);
	if (var_expand(prefix, storage->ns_prefix_pattern, tab, &error) <= 0) {
		mailbox_list_set_critical(list,
			"Failed to expand namespace prefix '%s': %s",
			storage->ns_prefix_pattern, error);
		return -1;
	}

	*_ns = mail_namespace_find_prefix(user->namespaces, str_c(prefix));
	if (*_ns != NULL) {
		*_name = mailbox_list_get_storage_name(ns->list,
				t_strconcat(ns->prefix, name, NULL));
		return 0;
	}

	owner = mail_user_alloc(event_get_parent(user->event), userdomain,
				user->set_info, user->unexpanded_set);
	owner->_service_user = user->_service_user;
	mail_storage_service_user_ref(owner->_service_user);
	owner->creator = user;
	owner->autocreated = TRUE;
	owner->session_id = p_strdup(owner->pool, user->session_id);
	if (mail_user_init(owner, &error) < 0) {
		if (!owner->nonexistent) {
			mailbox_list_set_critical(list,
				"Couldn't create namespace '%s' for user %s: %s",
				ns->prefix, userdomain, error);
			mail_user_deinit(&owner);
			return -1;
		}
		ret = 0;
	} else if (!var_has_key(storage->location, 'h', "home")) {
		ret = 1;
	} else {
		/* we'll need to look up the user's home directory */
		if ((ret = mail_user_get_home(owner, &tab[3].value)) < 0) {
			mailbox_list_set_critical(list, "Namespace '%s': "
				"Could not lookup home for user %s",
				ns->prefix, userdomain);
			mail_user_deinit(&owner);
			return -1;
		}
	}

	location = t_str_new(256);
	if (ret > 0 &&
	    var_expand(location, storage->location, tab, &error) <= 0) {
		mailbox_list_set_critical(list,
			"Failed to expand namespace location '%s': %s",
			storage->location, error);
		return -1;
	}

	/* create the new namespace */
	new_ns = i_new(struct mail_namespace, 1);
	new_ns->refcount = 1;
	new_ns->type = MAIL_NAMESPACE_TYPE_SHARED;
	new_ns->user = user;
	new_ns->prefix = i_strdup(str_c(prefix));
	new_ns->owner = owner;
	new_ns->flags = (NAMESPACE_FLAG_SUBSCRIPTIONS & ns->flags) |
		NAMESPACE_FLAG_LIST_PREFIX | NAMESPACE_FLAG_HIDDEN |
		NAMESPACE_FLAG_AUTOCREATED | NAMESPACE_FLAG_INBOX_ANY;
	new_ns->user_set = user->set;
	new_ns->mail_set = _storage->set;
	i_array_init(&new_ns->all_storages, 2);

	if (ret <= 0) {
		get_nonexistent_user_location(storage, userdomain, location);
		new_ns->flags |= NAMESPACE_FLAG_UNUSABLE;
		e_debug(ns->user->event,
			"shared: Tried to access mails of "
			"nonexistent user %s", userdomain);
	}

	ns_set = p_new(user->pool, struct mail_namespace_settings, 1);
	ns_set->type = "shared";
	ns_set->separator = p_strdup_printf(user->pool, "%c", ns_sep);
	ns_set->prefix = new_ns->prefix;
	ns_set->location = p_strdup(user->pool, str_c(location));
	ns_set->hidden = TRUE;
	ns_set->list = "yes";
	new_ns->set = ns_set;

	unexpanded_ns_set =
		p_new(user->pool, struct mail_namespace_settings, 1);
	*unexpanded_ns_set = *ns_set;
	unexpanded_ns_set->location =
		p_strdup(user->pool, storage->unexpanded_location);
	new_ns->unexpanded_set = unexpanded_ns_set;

	/* We need to create a prefix="" namespace for the owner */
	if (mail_namespaces_init_location(owner, str_c(location), &error) < 0) {
		/* owner gets freed by namespace deinit */
		mail_namespace_destroy(new_ns);
		return -1;
	}

	if (mail_storage_create(new_ns, NULL, _storage->flags |
				MAIL_STORAGE_FLAG_NO_AUTOVERIFY, &error) < 0) {
		mailbox_list_set_critical(list, "Namespace '%s': %s",
					  new_ns->prefix, error);
		/* owner gets freed by namespace deinit */
		mail_namespace_destroy(new_ns);
		return -1;
	}
	if ((new_ns->flags & NAMESPACE_FLAG_UNUSABLE) == 0 &&
	    !shared_namespace_exists(new_ns)) {
		/* this user doesn't have a usable storage */
		new_ns->flags |= NAMESPACE_FLAG_UNUSABLE;
	}
	/* mark the shared namespace root as usable, since it now has
	   child namespaces */
	ns->flags |= NAMESPACE_FLAG_USABLE;
	*_name = mailbox_list_get_storage_name(new_ns->list,
				t_strconcat(new_ns->prefix, name, NULL));
	*_ns = new_ns;
	if (_storage->class_flags == 0) {
		/* flags are unset if we were using "auto" storage */
		_storage->class_flags =
			mail_namespace_get_default_storage(new_ns)->class_flags;
	}

	mail_user_add_namespace(user, &new_ns);
	return 0;
}

struct mail_storage shared_storage = {
	.name = MAIL_SHARED_STORAGE_NAME,
	.class_flags = 0, /* unknown at this point */

	.v = {
		NULL,
		shared_storage_alloc,
		shared_storage_create,
		index_storage_destroy,
		NULL,
		shared_storage_get_list_settings,
		NULL,
		fail_mailbox_alloc,
		NULL,
		NULL,
	}
};
