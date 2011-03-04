/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "var-expand.h"
#include "index-storage.h"
#include "mailbox-list-private.h"
#include "shared-storage.h"

#include <stdlib.h>
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
	struct shared_storage *storage = (struct shared_storage *)_storage;
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
	storage->storage_class = mail_storage_find_class(driver);
	if (storage->storage_class == NULL) {
		*error_r = t_strconcat("Unknown shared storage driver: ",
				       driver, NULL);
		return -1;
	}
	_storage->class_flags = storage->storage_class->class_flags;

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
	str_append(location, storage->storage_class->name);
	str_append_c(location, ':');

	/* use a reachable but nonexistent path as the mail root directory */
	str_append(location, storage->storage.user->set->base_dir);
	str_append(location, "/user-not-found/");
	str_append(location, username);
}

int shared_storage_get_namespace(struct mail_namespace **_ns,
				 const char **_name)
{
	struct mail_storage *_storage = (*_ns)->storage;
	struct mailbox_list *list = (*_ns)->list;
	struct shared_storage *storage = (struct shared_storage *)_storage;
	struct mail_user *user = _storage->user;
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 'h', NULL, "home" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	struct mail_namespace *new_ns, *ns = *_ns;
	struct mail_namespace_settings *ns_set, *unexpanded_ns_set;
	struct mail_user *owner;
	const char *domain = NULL, *username = NULL, *userdomain = NULL;
	const char *name, *p, *next, **dest, *error;
	string_t *prefix, *location;
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

		next = strchr(name, *p != '\0' ? *p : ns->sep);
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
		    (name[1] == '\0' && *name == ns->sep)) {
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
			domain = strchr(user->username, '@');
			if (domain != NULL) domain++;
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
	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));
	tab[0].value = userdomain;
	tab[1].value = username;
	tab[2].value = domain;

	prefix = t_str_new(128);
	str_append(prefix, ns->prefix);
	var_expand(prefix, storage->ns_prefix_pattern, tab);

	*_ns = mail_namespace_find_prefix(user->namespaces, str_c(prefix));
	if (*_ns != NULL) {
		*_name = mail_namespace_fix_sep(ns, name);
		return 0;
	}

	owner = mail_user_alloc(userdomain, user->set_info,
				user->unexpanded_set);
	if (!var_has_key(storage->location, 'h', "home"))
		ret = 1;
	else {
		/* we'll need to look up the user's home directory */
		if ((ret = mail_user_get_home(owner, &tab[3].value)) < 0) {
			mailbox_list_set_critical(list, "Namespace '%s': "
				"Could not lookup home for user %s",
				ns->prefix, userdomain);
			mail_user_unref(&owner);
			return -1;
		}
	}
	if (mail_user_init(owner, &error) < 0) {
		mailbox_list_set_critical(list,
			"Couldn't create namespace '%s' for user %s: %s",
			ns->prefix, userdomain, error);
		mail_user_unref(&owner);
		return -1;
	}

	/* create the new namespace */
	new_ns = i_new(struct mail_namespace, 1);
	new_ns->refcount = 1;
	new_ns->type = NAMESPACE_SHARED;
	new_ns->user = user;
	new_ns->prefix = i_strdup(str_c(prefix));
	new_ns->owner = owner;
	new_ns->flags = (NAMESPACE_FLAG_SUBSCRIPTIONS & ns->flags) |
		NAMESPACE_FLAG_LIST_PREFIX | NAMESPACE_FLAG_HIDDEN |
		NAMESPACE_FLAG_AUTOCREATED | NAMESPACE_FLAG_INBOX_ANY;
	new_ns->sep = ns->sep;
	new_ns->mail_set = _storage->set;

	location = t_str_new(256);
	if (ret > 0)
		var_expand(location, storage->location, tab);
	else {
		get_nonexistent_user_location(storage, userdomain, location);
		new_ns->flags |= NAMESPACE_FLAG_UNUSABLE;
		if (ns->user->mail_debug) {
			i_debug("shared: Tried to access mails of "
				"nonexistent user %s", userdomain);
		}
	}

	ns_set = p_new(user->pool, struct mail_namespace_settings, 1);
	ns_set->type = "shared";
	ns_set->separator = p_strdup_printf(user->pool, "%c", new_ns->sep);
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

	if (mail_storage_create(new_ns, NULL, _storage->flags |
				MAIL_STORAGE_FLAG_NO_AUTOVERIFY, &error) < 0) {
		mailbox_list_set_critical(list, "Namespace '%s': %s",
					  new_ns->prefix, error);
		mail_namespace_destroy(new_ns);
		return -1;
	}
	ns->flags |= NAMESPACE_FLAG_USABLE;
	*_name = mail_namespace_fix_sep(new_ns, name);
	*_ns = new_ns;

	mail_user_add_namespace(user, &new_ns);
	return 0;
}

struct mail_storage shared_storage = {
	.name = SHARED_STORAGE_NAME,
	.class_flags = 0, /* unknown at this point */

	.v = {
		NULL,
		shared_storage_alloc,
		shared_storage_create,
		NULL,
		NULL,
		shared_storage_get_list_settings,
		NULL,
		NULL,
		NULL
	}
};
