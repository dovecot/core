/* Copyright (c) 2008-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "var-expand.h"
#include "index-storage.h"
#include "shared-storage.h"

#include <stdlib.h>
#include <ctype.h>

#define SHARED_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, shared_mailbox_list_module)

extern struct mail_storage shared_storage;
extern struct mailbox shared_mailbox;

static MODULE_CONTEXT_DEFINE_INIT(shared_mailbox_list_module,
				  &mailbox_list_module_register);

static struct mail_storage *shared_alloc(void)
{
	struct shared_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("shared storage", 1024);
	storage = p_new(pool, struct shared_storage, 1);
	storage->storage = shared_storage;
	storage->storage.pool = pool;
	storage->storage.storage_class = &shared_storage;

	storage->base_dir = p_strdup(pool, getenv("BASE_DIR"));
	if (storage->base_dir == NULL)
		storage->base_dir = PKG_RUNDIR;

	return &storage->storage;
}

static int shared_create(struct mail_storage *_storage, const char *data,
			 const char **error_r)
{
	struct shared_storage *storage = (struct shared_storage *)_storage;
	struct mailbox_list_settings list_set;
	const char *driver, *p;
	char *wildcardp;
	bool have_username;

	/* data must begin with the actual mailbox driver */
	p = strchr(data, ':');
	if (p == NULL) {
		*error_r = "Shared mailbox location not prefixed with driver";
		return -1;
	}
	driver = t_strdup_until(data, p);
	storage->location = p_strdup(_storage->pool, data);
	storage->storage_class = mail_storage_find_class(driver);
	if (storage->storage_class == NULL) {
		*error_r = t_strconcat("Unknown shared storage driver: ",
				       driver, NULL);
		return -1;
	}
	_storage->mailbox_is_file = storage->storage_class->mailbox_is_file;

	wildcardp = strchr(_storage->ns->prefix, '%');
	if (wildcardp == NULL) {
		*error_r = "Shared namespace prefix doesn't contain %";
		return -1;
	}
	storage->ns_prefix_pattern = p_strdup(_storage->pool, wildcardp);
	*wildcardp = '\0';

	have_username = FALSE;
	for (p = storage->ns_prefix_pattern; *p != '\0'; p++) {
		if (*p != '%')
			continue;
		if (*++p == '\0')
			break;
		if (*p == 'u' || *p == 'n')
			have_username = TRUE;
		else if (*p != '%' && *p != 'd')
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

	if (mailbox_list_alloc("shared", &_storage->list, error_r) < 0)
		return -1;
	MODULE_CONTEXT_SET_FULL(_storage->list, shared_mailbox_list_module,
				storage, &storage->list_module_ctx);

	memset(&list_set, 0, sizeof(list_set));
	list_set.mail_storage_flags = &_storage->flags;
	list_set.lock_method = &_storage->lock_method;
	mailbox_list_init(_storage->list, _storage->ns, &list_set,
			  mail_storage_get_list_flags(_storage->flags));
	return 0;
}

static void
get_nonexisting_user_location(struct shared_storage *storage,
			      const char *username, string_t *location)
{
	/* user wasn't found. we'll still need to create the storage
	   to avoid exposing which users exist and which don't. */
	str_append(location, storage->storage_class->name);
	str_append_c(location, ':');

	/* use a reachable but non-existing path as the mail root directory */
	str_append(location, storage->base_dir);
	str_append(location, "/user-not-found/");
	str_append(location, username);
}

int shared_storage_get_namespace(struct mail_storage *_storage,
				 const char **_name,
				 struct mail_namespace **ns_r)
{
	struct shared_storage *storage = (struct shared_storage *)_storage;
	struct mail_user *user = _storage->ns->user;
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 'h', NULL, "home" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	struct mail_namespace *ns;
	struct mail_user *owner;
	const char *domain = NULL, *username = NULL, *userdomain = NULL;
	const char *name, *p, *next, **dest, *error;
	string_t *prefix, *location;
	int ret;

	*ns_r = NULL;

	p = storage->ns_prefix_pattern;
	for (name = *_name; *p != '\0';) {
		if (*p != '%') {
			if (*p != *name) {
				mail_storage_set_critical(_storage,
					"Invalid namespace prefix %s vs %s",
					storage->ns_prefix_pattern, *_name);
				return -1;
			}
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

		next = strchr(name, *p != '\0' ? *p : _storage->ns->sep);
		if (next == NULL) {
			mail_storage_set_critical(_storage,
				"Invalid namespace prefix %s vs %s",
				storage->ns_prefix_pattern, *_name);
			return -1;
		}

		*dest = t_strdup_until(name, next);
		name = next;
	}
	/* successfully matched the name. */
	if (userdomain == NULL) {
		i_assert(username != NULL);
		userdomain = domain == NULL ? username :
			t_strconcat(username, "@", domain, NULL);
	} else {
		domain = strchr(userdomain, '@');
		if (domain == NULL)
			username = userdomain;
		else {
			username = t_strdup_until(userdomain, domain);
			domain++;
		}
	}

	/* expand the namespace prefix and see if it already exists.
	   this should normally happen only when the mailbox is being opened */
	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));
	tab[0].value = userdomain;
	tab[1].value = username;
	tab[2].value = domain;

	prefix = t_str_new(128);
	str_append(prefix, _storage->ns->prefix);
	var_expand(prefix, storage->ns_prefix_pattern, tab);

	ns = mail_namespace_find_prefix(user->namespaces, str_c(prefix));
	if (ns != NULL) {
		*_name = mail_namespace_fix_sep(ns, name);
		*ns_r = ns;
		return 0;
	}

	owner = mail_user_init(userdomain);
	if (!var_has_key(storage->location, 'h', "home"))
		ret = 1;
	else {
		/* we'll need to look up the user's home directory */
		if ((ret = mail_user_get_home(owner, &tab[3].value)) < 0) {
			mail_storage_set_critical(_storage, "Namespace '%s': "
				"Could not lookup home for user %s",
				_storage->ns->prefix, userdomain);
			mail_user_unref(&owner);
			return -1;
		}
	}

	/* create the new namespace */
	ns = i_new(struct mail_namespace, 1);
	ns->type = NAMESPACE_SHARED;
	ns->user = user;
	ns->prefix = i_strdup(str_c(prefix));
	ns->owner = owner;
	ns->flags = NAMESPACE_FLAG_LIST_PREFIX | NAMESPACE_FLAG_HIDDEN |
		NAMESPACE_FLAG_AUTOCREATED | NAMESPACE_FLAG_INBOX;
	ns->sep = _storage->ns->sep;

	location = t_str_new(256);
	if (ret > 0)
		var_expand(location, storage->location, tab);
	else {
		get_nonexisting_user_location(storage, userdomain, location);
		ns->flags |= NAMESPACE_FLAG_UNUSABLE;
	}
	if (mail_storage_create(ns, NULL, str_c(location), _storage->flags,
				_storage->lock_method, &error) < 0) {
		mail_storage_set_critical(_storage, "Namespace '%s': %s",
					  ns->prefix, error);
		mail_namespace_destroy(ns);
		return -1;
	}
	_storage->ns->flags |= NAMESPACE_FLAG_USABLE;
	*_name = mail_namespace_fix_sep(ns, name);
	*ns_r = ns;

	mail_user_add_namespace(user, &ns);
	return 0;
}

static void shared_mailbox_copy_error(struct mail_storage *shared_storage,
				      struct mail_namespace *backend_ns)
{
	const char *str;
	enum mail_error error;

	str = mail_storage_get_last_error(backend_ns->storage, &error);
	mail_storage_set_error(shared_storage, error, str);
}

static struct mailbox *
shared_mailbox_open(struct mail_storage *storage, const char *name,
		    struct istream *input, enum mailbox_open_flags flags)
{
	struct mail_namespace *ns;
	struct mailbox *box;

	if (input != NULL) {
		mail_storage_set_critical(storage,
			"Shared storage doesn't support streamed mailboxes");
		return NULL;
	}

	if (shared_storage_get_namespace(storage, &name, &ns) < 0)
		return NULL;

	/* if we call the normal mailbox_open() here the plugins will see
	   mailbox_open() called twice and they could break. */
	box = ns->storage->storage_class->v.
		mailbox_open(ns->storage, name, NULL, flags);
	if (box == NULL)
		shared_mailbox_copy_error(storage, ns);
	else
		ns->flags |= NAMESPACE_FLAG_USABLE;
	return box;
}

static int shared_mailbox_create(struct mail_storage *storage,
				 const char *name, bool directory)
{
	struct mail_namespace *ns;
	int ret;

	if (shared_storage_get_namespace(storage, &name, &ns) < 0)
		return -1;

	ret = mail_storage_mailbox_create(ns->storage, name, directory);
	if (ret < 0)
		shared_mailbox_copy_error(storage, ns);
	return ret;
}

struct mail_storage shared_storage = {
	MEMBER(name) SHARED_STORAGE_NAME,
	MEMBER(mailbox_is_file) FALSE, /* unknown at this point */

	{
		NULL,
		NULL,
		shared_alloc,
		shared_create,
		index_storage_destroy,
		NULL,
		shared_mailbox_open,
		shared_mailbox_create
	}
};
