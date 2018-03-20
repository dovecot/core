/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "file-lock.h"
#include "settings-parser.h"
#include "mailbox-list-private.h"
#include "mail-storage-private.h"
#include "mail-storage-settings.h"
#include "mail-namespace.h"


static struct mail_namespace_settings prefixless_ns_unexpanded_set = {
	.name = "",
	.type = "private",
	.separator = "",
	.prefix = "0",
	.location = "0fail::LAYOUT=none",
	.alias_for = NULL,

	.inbox = FALSE,
	.hidden = TRUE,
	.list = "no",
	.subscriptions = FALSE,
	.ignore_on_failure = FALSE,
	.disabled = FALSE,

	.mailboxes = ARRAY_INIT
};
static struct mail_namespace_settings prefixless_ns_set;

void mail_namespace_add_storage(struct mail_namespace *ns,
				struct mail_storage *storage)
{
	if (ns->storage == NULL)
		ns->storage = storage;
	array_append(&ns->all_storages, &storage, 1);

	if (storage->v.add_list != NULL)
		storage->v.add_list(storage, ns->list);
	hook_mail_namespace_storage_added(ns);
}

void mail_namespace_finish_list_init(struct mail_namespace *ns,
				     struct mailbox_list *list)
{
	ns->list = list;
	ns->prefix_len = strlen(ns->prefix);
}

static void mail_namespace_free(struct mail_namespace *ns)
{
	struct mail_storage **storagep;

	if (array_is_created(&ns->all_storages)) {
		array_foreach_modifiable(&ns->all_storages, storagep)
			mail_storage_unref(storagep);
		array_free(&ns->all_storages);
	}
	if (ns->list != NULL)
		mailbox_list_destroy(&ns->list);

	if (ns->owner != ns->user && ns->owner != NULL)
		mail_user_unref(&ns->owner);
	i_free(ns->prefix);
	i_free(ns);
}

static bool
namespace_has_special_use_mailboxes(struct mail_namespace_settings *ns_set)
{
	struct mailbox_settings *const *box_set;

	if (!array_is_created(&ns_set->mailboxes))
		return FALSE;

	array_foreach(&ns_set->mailboxes, box_set) {
		if ((*box_set)->special_use[0] != '\0')
			return TRUE;
	}
	return FALSE;
}

int mail_namespace_alloc(struct mail_user *user,
			 void *user_all_settings,
			 struct mail_namespace_settings *ns_set,
			 struct mail_namespace_settings *unexpanded_set,
			 struct mail_namespace **ns_r,
			 const char **error_r)
{
	struct mail_namespace *ns;

	ns = i_new(struct mail_namespace, 1);
	ns->refcount = 1;
	ns->user = user;
	ns->prefix = i_strdup(ns_set->prefix);
	ns->set = ns_set;
	ns->unexpanded_set = unexpanded_set;
	ns->user_set = user_all_settings;
	ns->mail_set = mail_user_set_get_driver_settings(user->set_info,
				ns->user_set, MAIL_STORAGE_SET_DRIVER_NAME);
	i_array_init(&ns->all_storages, 2);

	if (strcmp(ns_set->type, "private") == 0) {
		ns->owner = user;
		ns->type = MAIL_NAMESPACE_TYPE_PRIVATE;
	} else if (strcmp(ns_set->type, "shared") == 0)
		ns->type = MAIL_NAMESPACE_TYPE_SHARED;
	else if (strcmp(ns_set->type, "public") == 0)
		ns->type = MAIL_NAMESPACE_TYPE_PUBLIC;
	else {
		*error_r = t_strdup_printf("Unknown namespace type: %s",
					   ns_set->type);
		mail_namespace_free(ns);
		return -1;
	}

	if (strcmp(ns_set->list, "children") == 0)
		ns->flags |= NAMESPACE_FLAG_LIST_CHILDREN;
	else if (strcmp(ns_set->list, "yes") == 0)
		ns->flags |= NAMESPACE_FLAG_LIST_PREFIX;
	else if (strcmp(ns_set->list, "no") != 0) {
		*error_r = t_strdup_printf("Invalid list setting value: %s",
					   ns_set->list);
		mail_namespace_free(ns);
		return -1;
	}

	if (ns_set->inbox) {
		ns->flags |= NAMESPACE_FLAG_INBOX_USER |
			NAMESPACE_FLAG_INBOX_ANY;
	}
	if (ns_set->hidden)
		ns->flags |= NAMESPACE_FLAG_HIDDEN;
	if (ns_set->subscriptions)
		ns->flags |= NAMESPACE_FLAG_SUBSCRIPTIONS;

	*ns_r = ns;

	return 0;
}

int mail_namespaces_init_add(struct mail_user *user,
			     struct mail_namespace_settings *ns_set,
			     struct mail_namespace_settings *unexpanded_ns_set,
			     struct mail_namespace **ns_p, const char **error_r)
{
	const struct mail_storage_settings *mail_set =
		mail_user_set_get_storage_set(user);
	struct mail_namespace *ns;
	const char *driver, *error;
	int ret;

	if (*ns_set->location == '\0')
		ns_set->location = mail_set->mail_location;

	e_debug(user->event, "Namespace %s: type=%s, prefix=%s, sep=%s, "
		"inbox=%s, hidden=%s, list=%s, subscriptions=%s "
		"location=%s",
		ns_set->name, ns_set->type, ns_set->prefix,
		ns_set->separator == NULL ? "" : ns_set->separator,
		ns_set->inbox ? "yes" : "no",
		ns_set->hidden ? "yes" : "no",
		ns_set->list,
		ns_set->subscriptions ? "yes" : "no", ns_set->location);

	if ((ret = mail_namespace_alloc(user, user->set,
					ns_set, unexpanded_ns_set,
					&ns, error_r)) < 0)
		return ret;

	if (ns_set == &prefixless_ns_set) {
		/* autocreated prefix="" namespace */
		ns->flags |= NAMESPACE_FLAG_UNUSABLE |
			NAMESPACE_FLAG_AUTOCREATED;
	}

	ns->special_use_mailboxes = namespace_has_special_use_mailboxes(ns_set);

	if (ns->type == MAIL_NAMESPACE_TYPE_SHARED &&
	    (strchr(ns->prefix, '%') != NULL ||
	     strchr(ns->set->location, '%') != NULL)) {
		/* dynamic shared namespace. the above check catches wrong
		   mixed %% usage, but still allows for specifying a shared
		   namespace to an explicit location without any %% */
		ns->flags |= NAMESPACE_FLAG_NOQUOTA | NAMESPACE_FLAG_NOACL;
		driver = MAIL_SHARED_STORAGE_NAME;
	} else {
		driver = NULL;
	}

	if (mail_storage_create(ns, driver, 0, &error) < 0) {
		*error_r = t_strdup_printf("Namespace '%s': %s",
					   ns->prefix, error);
		mail_namespace_free(ns);
		return -1;
	}

	*ns_p = ns;
	return 0;
}

static bool namespace_is_valid_alias_storage(struct mail_namespace *ns,
					     const char **error_r)
{
	if (strcmp(ns->storage->name, ns->alias_for->storage->name) != 0) {
		*error_r = t_strdup_printf(
			"Namespace %s can't have alias_for=%s "
			"to a different storage type (%s vs %s)",
			ns->prefix, ns->alias_for->prefix,
			ns->storage->name, ns->alias_for->storage->name);
		return FALSE;
	}

	if ((ns->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT) != 0 &&
	    ns->storage != ns->alias_for->storage) {
		*error_r = t_strdup_printf(
			"Namespace %s can't have alias_for=%s "
			"to a different storage (different root dirs)",
			ns->prefix, ns->alias_for->prefix);
		return FALSE;
	}
	return TRUE;
}

static int
namespace_set_alias_for(struct mail_namespace *ns,
			struct mail_namespace *all_namespaces,
			const char **error_r)
{
	if (ns->set->alias_for != NULL) {
		ns->alias_for = mail_namespace_find_prefix(all_namespaces,
							   ns->set->alias_for);
		if (ns->alias_for == NULL) {
			*error_r = t_strdup_printf("Invalid namespace alias_for: %s",
						   ns->set->alias_for);
			return -1;
		}
		if (ns->alias_for->alias_for != NULL) {
			*error_r = t_strdup_printf("Chained namespace alias_for: %s",
						   ns->set->alias_for);
			return -1;
		}
		if (!namespace_is_valid_alias_storage(ns, error_r))
			return -1;

		if ((ns->alias_for->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
			/* copy inbox=yes */
			ns->flags |= NAMESPACE_FLAG_INBOX_USER;
		}

		ns->alias_chain_next = ns->alias_for->alias_chain_next;
		ns->alias_for->alias_chain_next = ns;
	}
	return 0;
}

static bool get_listindex_path(struct mail_namespace *ns, const char **path_r)
{
	const char *root;

	if (ns->list->set.list_index_fname[0] == '\0' ||
	    !mailbox_list_get_root_path(ns->list,
					MAILBOX_LIST_PATH_TYPE_LIST_INDEX,
					&root))
		return FALSE;

	*path_r = t_strconcat(root, "/", ns->list->set.list_index_fname, NULL);
	return TRUE;
}

static bool
namespace_has_duplicate_listindex(struct mail_namespace *ns,
				  const char **error_r)
{
	struct mail_namespace *ns2;
	const char *ns_list_index_path, *ns_mailboxes_root;
	const char *ns2_list_index_path, *ns2_mailboxes_root;

	if (!ns->mail_set->mailbox_list_index) {
		/* mailbox list indexes not in use */
		return FALSE;
	}

	if (!get_listindex_path(ns, &ns_list_index_path) ||
	    !mailbox_list_get_root_path(ns->list, MAILBOX_LIST_PATH_TYPE_MAILBOX,
					&ns_mailboxes_root))
		return FALSE;

	for (ns2 = ns->next; ns2 != NULL; ns2 = ns2->next) {
		if (!get_listindex_path(ns2, &ns2_list_index_path) ||
		    !mailbox_list_get_root_path(ns2->list, MAILBOX_LIST_PATH_TYPE_MAILBOX,
						&ns2_mailboxes_root))
			continue;

		if (strcmp(ns_list_index_path, ns2_list_index_path) == 0 &&
		    strcmp(ns_mailboxes_root, ns2_mailboxes_root) != 0) {
			*error_r = t_strdup_printf(
				"Namespaces '%s' and '%s' have different mailboxes paths, but duplicate LISTINDEX path. "
				"Add a unique LISTINDEX=<fname>",
				ns->prefix, ns2->prefix);
			return TRUE;
		}
	}
	return FALSE;
}

static bool
namespaces_check(struct mail_namespace *namespaces, const char **error_r)
{
	struct mail_namespace *ns, *inbox_ns = NULL;
	unsigned int subscriptions_count = 0;
	bool visible_namespaces = FALSE, have_list_yes = FALSE;
	char ns_sep, list_sep = '\0';

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		ns_sep = mail_namespace_get_sep(ns);
		if (mail_namespace_find_prefix(ns->next, ns->prefix) != NULL) {
			*error_r = t_strdup_printf(
				"Duplicate namespace prefix: \"%s\"",
				ns->prefix);
			return FALSE;
		}
		if ((ns->flags & NAMESPACE_FLAG_HIDDEN) == 0)
			visible_namespaces = TRUE;
		/* check the inbox=yes status before alias_for changes it */
		if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
			if (inbox_ns != NULL) {
				*error_r = "There can be only one namespace with "
					"inbox=yes";
				return FALSE;
			}
			inbox_ns = ns;
		}
		if (namespace_set_alias_for(ns, namespaces, error_r) < 0)
			return FALSE;
		if (namespace_has_duplicate_listindex(ns, error_r))
			return FALSE;

		if (*ns->prefix != '\0' &&
		    (ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) != 0 &&
		    ns->prefix[strlen(ns->prefix)-1] != ns_sep) {
			*error_r = t_strdup_printf(
				"list=yes requires prefix=%s "
				"to end with separator %c", ns->prefix, ns_sep);
			return FALSE;
		}
		if (*ns->prefix != '\0' &&
		    (ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) != 0 &&
		    ns->prefix[0] == ns_sep) {
			*error_r = t_strdup_printf(
				"list=yes requires prefix=%s "
				"not to start with separator", ns->prefix);
			return FALSE;
		}
		if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) != 0) {
			if ((ns->flags & NAMESPACE_FLAG_LIST_PREFIX) != 0)
				have_list_yes = TRUE;
			if (list_sep == '\0')
				list_sep = ns_sep;
			else if (list_sep != ns_sep) {
				*error_r = "All list=yes namespaces must use "
					"the same separator";
				return FALSE;
			}
		}
		if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0)
			subscriptions_count++;
	}

	if (inbox_ns == NULL) {
		*error_r = "inbox=yes namespace missing";
		return FALSE;
	}
	if (!have_list_yes) {
		*error_r = "list=yes namespace missing";
		return FALSE;
	}
	if (!visible_namespaces) {
		*error_r = "hidden=no namespace missing";
		return FALSE;
	}
	if (subscriptions_count == 0) {
		*error_r = "subscriptions=yes namespace missing";
		return FALSE;
	}
	return TRUE;
}

int mail_namespaces_init_finish(struct mail_namespace *namespaces,
				const char **error_r)
{
	struct mail_namespace *ns;
	bool prefixless_found = FALSE;

	i_assert(namespaces != NULL);

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (ns->prefix_len == 0)
			prefixless_found = TRUE;
	}
	if (!prefixless_found) {
		prefixless_ns_set = prefixless_ns_unexpanded_set;
		/* a pretty evil way to expand the values */
		prefixless_ns_set.prefix++;
		prefixless_ns_set.location++;

		if (mail_namespaces_init_add(namespaces->user,
					     &prefixless_ns_set,
					     &prefixless_ns_unexpanded_set,
					     &ns, error_r) < 0)
			i_unreached();
		ns->next = namespaces;
		namespaces = ns;
	}
	if (namespaces->user->autocreated) {
		/* e.g. raw user - don't check namespaces' validity */
	} else if (!namespaces_check(namespaces, error_r)) {
		namespaces->user->error =
			t_strconcat("namespace configuration error: ",
				    *error_r, NULL);
	}

	if (namespaces->user->error == NULL) {
		mail_user_add_namespace(namespaces->user, &namespaces);
		T_BEGIN {
			hook_mail_namespaces_created(namespaces);
		} T_END;
	}

	/* allow namespace hooks to return failure via the user error */
	if (namespaces->user->error != NULL) {
		namespaces->user->namespaces = NULL;
		*error_r = t_strdup(namespaces->user->error);
		while (namespaces != NULL) {
			ns = namespaces;
			namespaces = ns->next;
			mail_namespace_free(ns);
		}
		return -1;
	}

	namespaces->user->namespaces_created = TRUE;
	return 0;
}

int mail_namespaces_init(struct mail_user *user, const char **error_r)
{
	struct mail_namespace_settings *const *ns_set;
	struct mail_namespace_settings *const *unexpanded_ns_set;
	struct mail_namespace *namespaces, **ns_p;
	unsigned int i, count, count2;

	i_assert(user->initialized);

        namespaces = NULL; ns_p = &namespaces;

	if (array_is_created(&user->set->namespaces)) {
		ns_set = array_get(&user->set->namespaces, &count);
		unexpanded_ns_set =
			array_get(&user->unexpanded_set->namespaces, &count2);
		i_assert(count == count2);
	} else {
		ns_set = unexpanded_ns_set = NULL;
		count = 0;
	}
	for (i = 0; i < count; i++) {
		if (ns_set[i]->disabled)
			continue;

		if (mail_namespaces_init_add(user, ns_set[i],
					     unexpanded_ns_set[i],
					     ns_p, error_r) < 0) {
			if (!ns_set[i]->ignore_on_failure) {
				mail_namespaces_deinit(&namespaces);
				return -1;
			}
			e_debug(user->event, "Skipping namespace %s: %s",
				ns_set[i]->prefix, *error_r);
		} else {
			ns_p = &(*ns_p)->next;
		}
	}

	if (namespaces == NULL) {
		/* no namespaces defined, create a default one */
		return mail_namespaces_init_location(user, NULL, error_r);
	}
	return mail_namespaces_init_finish(namespaces, error_r);
}

int mail_namespaces_init_location(struct mail_user *user, const char *location,
				  const char **error_r)
{
	struct mail_namespace_settings *inbox_set, *unexpanded_inbox_set;
	struct mail_namespace *ns;
	const struct mail_storage_settings *mail_set;
	const char *error, *driver, *location_source;
	bool default_location = FALSE;
	int ret;

	i_assert(location == NULL || *location != '\0');

	inbox_set = p_new(user->pool, struct mail_namespace_settings, 1);
	*inbox_set = mail_namespace_default_settings;
	inbox_set->inbox = TRUE;
	/* enums must be changed */
	inbox_set->type = "private";
	inbox_set->list = "yes";

	unexpanded_inbox_set = p_new(user->pool, struct mail_namespace_settings, 1);
	*unexpanded_inbox_set = *inbox_set;

	driver = NULL;
	mail_set = mail_user_set_get_storage_set(user);
	if (location != NULL) {
		inbox_set->location = p_strdup(user->pool, location);
		location_source = "mail_location parameter";
	} else if (*mail_set->mail_location != '\0') {
		location_source = "mail_location setting";
		inbox_set->location = mail_set->mail_location;
		default_location = TRUE;
	} else {
		location_source = "environment MAIL";
		inbox_set->location = getenv("MAIL");
	}
	if (inbox_set->location == NULL) {
		/* support also maildir-specific environment */
		inbox_set->location = getenv("MAILDIR");
		if (inbox_set->location == NULL)
			inbox_set->location = "";
		else {
			driver = "maildir";
			location_source = "environment MAILDIR";
		}
	}
	if (default_location) {
		/* treat this the same as if a namespace was created with
		   default settings. dsync relies on finding a namespace
		   without explicit location setting. */
		unexpanded_inbox_set->location = SETTING_STRVAR_UNEXPANDED;
	} else {
		unexpanded_inbox_set->location =
			p_strconcat(user->pool, SETTING_STRVAR_EXPANDED,
				    inbox_set->location, NULL);
	}

	if ((ret = mail_namespace_alloc(user, user->set,
					inbox_set, unexpanded_inbox_set,
					&ns, error_r)) < 0)
		return ret;

	if (mail_storage_create(ns, driver, 0, &error) < 0) {
		if (*inbox_set->location != '\0') {
			*error_r = t_strdup_printf(
				"Initializing mail storage from %s "
				"failed: %s", location_source, error);
		} else {
			*error_r = t_strdup_printf("mail_location not set and "
					"autodetection failed: %s", error);
		}
		mail_namespace_free(ns);
		return -1;
	}
	return mail_namespaces_init_finish(ns, error_r);
}

struct mail_namespace *mail_namespaces_init_empty(struct mail_user *user)
{
	struct mail_namespace *ns;

	ns = i_new(struct mail_namespace, 1);
	ns->refcount = 1;
	ns->user = user;
	ns->owner = user;
	ns->prefix = i_strdup("");
	ns->flags = NAMESPACE_FLAG_INBOX_USER | NAMESPACE_FLAG_INBOX_ANY |
		NAMESPACE_FLAG_LIST_PREFIX | NAMESPACE_FLAG_SUBSCRIPTIONS;
	ns->user_set = user->set;
	ns->mail_set = mail_user_set_get_storage_set(user);
	i_array_init(&ns->all_storages, 2);
	return ns;
}

void mail_namespaces_deinit(struct mail_namespace **_namespaces)
{
	struct mail_namespace *ns, *next;

	/* update *_namespaces as needed, instead of immediately setting it
	   to NULL. for example mdbox_storage.destroy() wants to go through
	   user's namespaces. */
	while (*_namespaces != NULL) {
		ns = *_namespaces;
		next = ns->next;

		mail_namespace_free(ns);
		*_namespaces = next;
	}
}

void mail_namespaces_set_storage_callbacks(struct mail_namespace *namespaces,
					   struct mail_storage_callbacks *callbacks,
					   void *context)
{
	struct mail_namespace *ns;
	struct mail_storage *const *storagep;

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		array_foreach(&ns->all_storages, storagep)
			mail_storage_set_callbacks(*storagep, callbacks, context);
	}
}

void mail_namespace_ref(struct mail_namespace *ns)
{
	i_assert(ns->refcount > 0);

	ns->refcount++;
}

void mail_namespace_unref(struct mail_namespace **_ns)
{
	struct mail_namespace *ns = *_ns;

	i_assert(ns->refcount > 0);

	*_ns = NULL;

	if (--ns->refcount > 0)
		return;

	i_assert(ns->destroyed);
	mail_namespace_free(ns);
}

void mail_namespace_destroy(struct mail_namespace *ns)
{
	struct mail_namespace **nsp;

	i_assert(!ns->destroyed);

	/* remove from user's namespaces list */
	for (nsp = &ns->user->namespaces; *nsp != NULL; nsp = &(*nsp)->next) {
		if (*nsp == ns) {
			*nsp = ns->next;
			break;
		}
	}
	ns->destroyed = TRUE;

	mail_namespace_unref(&ns);
}

struct mail_storage *
mail_namespace_get_default_storage(struct mail_namespace *ns)
{
	return ns->storage;
}

char mail_namespace_get_sep(struct mail_namespace *ns)
{
	return *ns->set->separator != '\0' ? *ns->set->separator :
		mailbox_list_get_hierarchy_sep(ns->list);
}

char mail_namespaces_get_root_sep(struct mail_namespace *namespaces)
{
	while ((namespaces->flags & NAMESPACE_FLAG_LIST_PREFIX) == 0)
		namespaces = namespaces->next;
	return mail_namespace_get_sep(namespaces);
}

static bool mail_namespace_is_usable_prefix(struct mail_namespace *ns,
					    const char *mailbox, bool inbox)
{
	if (strncmp(ns->prefix, mailbox, ns->prefix_len) == 0) {
		/* true exact prefix match */
		return TRUE;
	}

	if (inbox && str_begins(ns->prefix, "INBOX") &&
	    strncmp(ns->prefix+5, mailbox+5, ns->prefix_len-5) == 0) {
		/* we already checked that mailbox begins with case-insensitive
		   INBOX. this namespace also begins with INBOX and the rest
		   of the prefix matches too. */
		return TRUE;
	}

	if (strncmp(ns->prefix, mailbox, ns->prefix_len-1) == 0 &&
	    mailbox[ns->prefix_len-1] == '\0' &&
	    ns->prefix[ns->prefix_len-1] == mail_namespace_get_sep(ns)) {
		/* we're trying to access the namespace prefix itself */
		return TRUE;
	}
	return FALSE;
}

static struct mail_namespace *
mail_namespace_find_mask(struct mail_namespace *namespaces, const char *box,
			 enum namespace_flags flags,
			 enum namespace_flags mask)
{
        struct mail_namespace *ns = namespaces;
	struct mail_namespace *best = NULL;
	size_t best_len = 0;
	bool inbox;

	inbox = strncasecmp(box, "INBOX", 5) == 0;
	if (inbox && box[5] == '\0') {
		/* find the INBOX namespace */
		while (ns != NULL) {
			if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
			    (ns->flags & mask) == flags)
				return ns;
			if (*ns->prefix == '\0')
				best = ns;
			ns = ns->next;
		}
		return best;
	}

	for (; ns != NULL; ns = ns->next) {
		if (ns->prefix_len >= best_len && (ns->flags & mask) == flags &&
		    mail_namespace_is_usable_prefix(ns, box, inbox)) {
			best = ns;
			best_len = ns->prefix_len;
		}
	}
	return best;
}

static struct mail_namespace *
mail_namespace_find_shared(struct mail_namespace *ns, const char *mailbox)
{
	struct mailbox_list *list = ns->list;
	struct mail_storage *storage;

	if (mailbox_list_get_storage(&list, mailbox, &storage) < 0)
		return ns;

	return mailbox_list_get_namespace(list);
}

struct mail_namespace *
mail_namespace_find(struct mail_namespace *namespaces, const char *mailbox)
{
	struct mail_namespace *ns;

	ns = mail_namespace_find_mask(namespaces, mailbox, 0, 0);
	i_assert(ns != NULL);

	if (mail_namespace_is_shared_user_root(ns)) {
		/* see if we need to autocreate a namespace for shared user */
		if (strchr(mailbox, mail_namespace_get_sep(ns)) != NULL)
			return mail_namespace_find_shared(ns, mailbox);
	}
	return ns;
}

struct mail_namespace *
mail_namespace_find_unalias(struct mail_namespace *namespaces,
			    const char **mailbox)
{
	struct mail_namespace *ns;
	const char *storage_name;

	ns = mail_namespace_find(namespaces, *mailbox);
	if (ns->alias_for != NULL) {
		storage_name =
			mailbox_list_get_storage_name(ns->list, *mailbox);
		ns = ns->alias_for;
		*mailbox = mailbox_list_get_vname(ns->list, storage_name);
	}
	return ns;
}

struct mail_namespace *
mail_namespace_find_visible(struct mail_namespace *namespaces,
			    const char *mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox, 0,
					NAMESPACE_FLAG_HIDDEN);
}

struct mail_namespace *
mail_namespace_find_subscribable(struct mail_namespace *namespaces,
				 const char *mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox,
					NAMESPACE_FLAG_SUBSCRIPTIONS,
					NAMESPACE_FLAG_SUBSCRIPTIONS);
}

struct mail_namespace *
mail_namespace_find_unsubscribable(struct mail_namespace *namespaces,
				   const char *mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox,
					0, NAMESPACE_FLAG_SUBSCRIPTIONS);
}

struct mail_namespace *
mail_namespace_find_inbox(struct mail_namespace *namespaces)
{
	i_assert(namespaces != NULL);

	/* there should always be an INBOX */
	while ((namespaces->flags & NAMESPACE_FLAG_INBOX_USER) == 0) {
		namespaces = namespaces->next;
		i_assert(namespaces != NULL);
	}
	return namespaces;
}

struct mail_namespace *
mail_namespace_find_prefix(struct mail_namespace *namespaces,
			   const char *prefix)
{
        struct mail_namespace *ns;
	size_t len = strlen(prefix);

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (ns->prefix_len == len &&
		    strcmp(ns->prefix, prefix) == 0)
			return ns;
	}
	return NULL;
}

struct mail_namespace *
mail_namespace_find_prefix_nosep(struct mail_namespace *namespaces,
				 const char *prefix)
{
        struct mail_namespace *ns;
	size_t len = strlen(prefix);

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (ns->prefix_len == len + 1 &&
		    strncmp(ns->prefix, prefix, len) == 0 &&
		    ns->prefix[len] == mail_namespace_get_sep(ns))
			return ns;
	}
	return NULL;
}

bool mail_namespace_is_shared_user_root(struct mail_namespace *ns)
{
	struct mail_storage *const *storagep;

	if (ns->type != MAIL_NAMESPACE_TYPE_SHARED)
		return FALSE;
	if ((ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0) {
		/* child of the shared root */
		return FALSE;
	}
	/* if we have driver=shared storage, we're a real shared root */
	array_foreach(&ns->all_storages, storagep) {
		if (strcmp((*storagep)->name, MAIL_SHARED_STORAGE_NAME) == 0)
			return TRUE;
	}
	return FALSE;
}
