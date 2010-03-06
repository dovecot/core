/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "file-lock.h"
#include "mail-storage-private.h"
#include "mail-storage-settings.h"
#include "mail-namespace.h"

#include <stdlib.h>

void mail_namespace_add_storage(struct mail_namespace *ns,
				struct mail_storage *storage)
{
	/* currently we support only a single storage */
	i_assert(ns->storage == NULL);
	ns->storage = storage;

	if (storage->v.add_list != NULL)
		storage->v.add_list(storage, ns->list);
	hook_mail_namespace_storage_added(ns);
}

void mail_namespace_finish_list_init(struct mail_namespace *ns,
				     struct mailbox_list *list)
{
	ns->list = list;

	/* allow plugins to override real_sep */
	if (ns->real_sep == '\0')
		ns->real_sep = mailbox_list_get_hierarchy_sep(list);
	ns->prefix_len = strlen(ns->prefix);

	if (ns->set->separator != NULL)
		ns->sep = *ns->set->separator;
	if (ns->sep == '\0')
                ns->sep = ns->real_sep;
	if (ns->sep == '"' || ns->sep == '\\') {
		ns->sep_str[0] = '\\';
		ns->sep_str[1] = ns->sep;
	} else {
		ns->sep_str[0] = ns->sep;
	}
}

static void mail_namespace_free(struct mail_namespace *ns)
{
	if (ns->storage != NULL)
		mail_storage_unref(&ns->storage);
	if (ns->list != NULL)
		mailbox_list_destroy(&ns->list);

	if (ns->owner != ns->user && ns->owner != NULL)
		mail_user_unref(&ns->owner);
	i_free(ns->prefix);
	i_free(ns);
}

static int
namespace_add(struct mail_user *user,
	      struct mail_namespace_settings *ns_set,
	      const struct mail_storage_settings *mail_set,
	      struct mail_namespace **ns_p, const char **error_r)
{
        struct mail_namespace *ns;
	const char *driver, *error;

	ns = i_new(struct mail_namespace, 1);
	ns->user = user;
	if (strncmp(ns_set->type, "private", 7) == 0) {
		ns->owner = user;
		ns->type = NAMESPACE_PRIVATE;
	} else if (strncmp(ns_set->type, "shared", 6) == 0)
		ns->type = NAMESPACE_SHARED;
	else if (strncmp(ns_set->type, "public", 6) == 0)
		ns->type = NAMESPACE_PUBLIC;
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

	if (ns_set->inbox)
		ns->flags |= NAMESPACE_FLAG_INBOX;
	if (ns_set->hidden)
		ns->flags |= NAMESPACE_FLAG_HIDDEN;
	if (ns_set->subscriptions)
		ns->flags |= NAMESPACE_FLAG_SUBSCRIPTIONS;

	if (mail_set->mail_debug) {
		i_debug("Namespace: type=%s, prefix=%s, sep=%s, "
			"inbox=%s, hidden=%s, list=%s, subscriptions=%s",
			ns_set->type, ns_set->prefix,
			ns_set->separator == NULL ? "" : ns_set->separator,
			ns_set->inbox ? "yes" : "no",
			ns_set->hidden ? "yes" : "no",
			ns_set->list ? "yes" : "no",
			ns_set->subscriptions ? "yes" : "no");
	}

	if (*ns_set->location == '\0')
		ns_set->location = mail_set->mail_location;

	ns->set = ns_set;
	ns->mail_set = mail_set;
	ns->prefix = i_strdup(ns_set->prefix);

	if (ns->type == NAMESPACE_SHARED && strchr(ns->prefix, '%') != NULL) {
		/* dynamic shared namespace */
		ns->flags |= NAMESPACE_FLAG_NOQUOTA | NAMESPACE_FLAG_NOACL;
		driver = "shared";
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
		ns->alias_chain_next = ns->alias_for->alias_chain_next;
		ns->alias_for->alias_chain_next = ns;
	}
	return 0;
}

static bool
namespaces_check(struct mail_namespace *namespaces, const char **error_r)
{
	struct mail_namespace *ns, *inbox_ns = NULL;
	unsigned int subscriptions_count = 0;
	char list_sep = '\0';

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (namespace_set_alias_for(ns, namespaces, error_r) < 0)
			return FALSE;
		if ((ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
			if (inbox_ns != NULL) {
				*error_r = "namespace configuration error: "
					"There can be only one namespace with "
					"inbox=yes";
				return FALSE;
			}
			inbox_ns = ns;
		}
		if (*ns->prefix != '\0' &&
		    (ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) != 0 &&
		    ns->prefix[strlen(ns->prefix)-1] != ns->sep) {
			*error_r = t_strdup_printf(
				"namespace configuration error: "
				"list=yes requires prefix=%s "
				"to end with separator", ns->prefix);
			return FALSE;
		}
		if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) != 0) {
			if (list_sep == '\0')
				list_sep = ns->sep;
			else if (list_sep != ns->sep) {
				*error_r = "namespace configuration error: "
					"All list=yes namespaces must use "
					"the same separator";
				return FALSE;
			}
		}
		if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0)
			subscriptions_count++;
	}

	if (inbox_ns == NULL) {
			*error_r = "namespace configuration error: "
				"inbox=yes namespace missing";
		return FALSE;
	}
	if (list_sep == '\0') {
		*error_r = "namespace configuration error: "
			"no list=yes namespaces";
		return FALSE;
	}
	if (subscriptions_count == 0) {
		*error_r = "namespace configuration error: "
			"no subscriptions=yes namespaces";
		return FALSE;
	}
	return TRUE;
}

int mail_namespaces_init(struct mail_user *user, const char **error_r)
{
	const struct mail_storage_settings *mail_set;
	struct mail_namespace_settings *const *ns_set;
	struct mail_namespace *namespaces, *ns, **ns_p;
	struct mail_namespace_settings *inbox_set;
	const char *error, *driver, *location_source;
	unsigned int i, count;

	i_assert(user->initialized);

        namespaces = NULL; ns_p = &namespaces;

	mail_set = mail_user_set_get_storage_set(user);
	if (array_is_created(&user->set->namespaces))
		ns_set = array_get(&user->set->namespaces, &count);
	else {
		ns_set = NULL;
		count = 0;
	}
	for (i = 0; i < count; i++) {
		if (namespace_add(user, ns_set[i], mail_set, ns_p, error_r) < 0)
			return -1;
		ns_p = &(*ns_p)->next;
	}

	if (namespaces != NULL) {
		if (!namespaces_check(namespaces, error_r)) {
			while (namespaces != NULL) {
				ns = namespaces;
				namespaces = ns->next;
				mail_namespace_free(ns);
			}
			return -1;
		}
		mail_user_add_namespace(user, &namespaces);

		T_BEGIN {
			hook_mail_namespaces_created(namespaces);
		} T_END;
		return 0;
	}

	/* no namespaces defined, create a default one */
	ns = i_new(struct mail_namespace, 1);
	ns->type = NAMESPACE_PRIVATE;
	ns->flags = NAMESPACE_FLAG_INBOX | NAMESPACE_FLAG_LIST_PREFIX |
		NAMESPACE_FLAG_SUBSCRIPTIONS;
	ns->owner = user;

	inbox_set = p_new(user->pool, struct mail_namespace_settings, 1);
	*inbox_set = mail_namespace_default_settings;
	inbox_set->inbox = TRUE;

	driver = NULL;
	if (*mail_set->mail_location != '\0') {
		inbox_set->location = mail_set->mail_location;
		location_source = "mail_location setting";
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

	ns->set = inbox_set;
	ns->mail_set = mail_set;
	ns->prefix = i_strdup(ns->set->prefix);
	ns->user = user;

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
	user->namespaces = ns;

	if (hook_mail_namespaces_created != NULL) {
		T_BEGIN {
			hook_mail_namespaces_created(ns);
		} T_END;
	}
	return 0;
}

struct mail_namespace *mail_namespaces_init_empty(struct mail_user *user)
{
	struct mail_namespace *ns;

	ns = i_new(struct mail_namespace, 1);
	ns->user = user;
	ns->owner = user;
	ns->prefix = i_strdup("");
	ns->flags = NAMESPACE_FLAG_INBOX | NAMESPACE_FLAG_LIST_PREFIX |
		NAMESPACE_FLAG_SUBSCRIPTIONS;
	ns->mail_set = mail_user_set_get_storage_set(user);
	user->namespaces = ns;
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

	for (ns = namespaces; ns != NULL; ns = ns->next)
		mail_storage_set_callbacks(ns->storage, callbacks, context);
}

void mail_namespace_destroy(struct mail_namespace *ns)
{
	struct mail_namespace **nsp;

	/* remove from user's namespaces list */
	for (nsp = &ns->user->namespaces; *nsp != NULL; nsp = &(*nsp)->next) {
		if (*nsp == ns) {
			*nsp = ns->next;
			break;
		}
	}

	mail_namespace_free(ns);
}

const char *mail_namespace_fix_sep(struct mail_namespace *ns, const char *name)
{
	char *ret, *p;

	if (ns->sep == ns->real_sep)
		return name;
	if (ns->type == NAMESPACE_SHARED &&
	    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) {
		/* shared namespace root. the backend storage's hierarchy
		   separator isn't known yet, so do nothing. */
		return name;
	}

	ret = p_strdup(unsafe_data_stack_pool, name);
	for (p = ret; *p != '\0'; p++) {
		if (*p == ns->sep)
			*p = ns->real_sep;
	}
	return ret;
}

const char *mail_namespace_get_storage_name(struct mail_namespace *ns,
					    const char *name)
{
	unsigned int len = strlen(ns->prefix);

	if (len > 0) {
		if (strncmp(ns->prefix, name, len) == 0)
			name += len;
		else {
			i_assert(strcasecmp(name, "INBOX") == 0);
		}
	}
	return mail_namespace_fix_sep(ns, name);
}

const char *mail_namespace_get_vname(struct mail_namespace *ns, string_t *dest,
				     const char *name)
{
	str_truncate(dest, 0);
	if ((ns->flags & NAMESPACE_FLAG_INBOX) == 0 ||
	    strcasecmp(name, "INBOX") != 0 ||
	    ns->user != ns->owner)
		str_append(dest, ns->prefix);

	for (; *name != '\0'; name++) {
		if (*name == ns->real_sep)
			str_append_c(dest, ns->sep);
		else
			str_append_c(dest, *name);
	}
	return str_c(dest);
}

struct mail_storage *
mail_namespace_get_default_storage(struct mail_namespace *ns)
{
	/* currently we don't support more than one storage per namespace */
	return ns->storage;
}

char mail_namespaces_get_root_sep(const struct mail_namespace *namespaces)
{
	while ((namespaces->flags & NAMESPACE_FLAG_LIST_PREFIX) == 0)
		namespaces = namespaces->next;
	return namespaces->sep;
}

static bool mail_namespace_is_usable_prefix(struct mail_namespace *ns,
					    const char *mailbox, bool inbox)
{
	if (strncmp(ns->prefix, mailbox, ns->prefix_len) == 0) {
		/* true exact prefix match */
		return TRUE;
	}

	if (inbox && strncmp(ns->prefix, "INBOX", 5) == 0 &&
	    strncmp(ns->prefix+5, mailbox+5, ns->prefix_len-5) == 0) {
		/* we already checked that mailbox begins with case-insensitive
		   INBOX. this namespace also begins with INBOX and the rest
		   of the prefix matches too. */
		return TRUE;
	}

	if (strncmp(ns->prefix, mailbox, ns->prefix_len-1) == 0 &&
	    mailbox[ns->prefix_len-1] == '\0' &&
	    ns->prefix[ns->prefix_len-1] == ns->sep) {
		/* we're trying to access the namespace prefix itself */
		return TRUE;
	}
	return FALSE;
}

static struct mail_namespace *
mail_namespace_find_mask(struct mail_namespace *namespaces,
			 const char **mailbox,
			 enum namespace_flags flags,
			 enum namespace_flags mask)
{
        struct mail_namespace *ns = namespaces;
	const char *box = *mailbox;
	struct mail_namespace *best = NULL;
	unsigned int len, best_len = 0;
	bool inbox;

	inbox = strncasecmp(box, "INBOX", 5) == 0;
	if (inbox && box[5] == '\0') {
		/* find the INBOX namespace */
		*mailbox = "INBOX";
		while (ns != NULL) {
			if ((ns->flags & NAMESPACE_FLAG_INBOX) != 0 &&
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

	if (best != NULL) {
		if (best_len > 0) {
			len = strlen(*mailbox);
			*mailbox += I_MIN(len, best_len);
		} else if (inbox && (box[5] == best->sep || box[5] == '\0'))
			*mailbox = t_strconcat("INBOX", box+5, NULL);

		*mailbox = mail_namespace_fix_sep(best, *mailbox);
	}
	return best;
}

struct mail_namespace *
mail_namespace_find(struct mail_namespace *namespaces, const char **mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox, 0, 0);
}

struct mail_namespace *
mail_namespace_find_visible(struct mail_namespace *namespaces,
			    const char **mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox, 0,
					NAMESPACE_FLAG_HIDDEN);
}

struct mail_namespace *
mail_namespace_find_subscribable(struct mail_namespace *namespaces,
				 const char **mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox,
					NAMESPACE_FLAG_SUBSCRIPTIONS,
					NAMESPACE_FLAG_SUBSCRIPTIONS);
}

struct mail_namespace *
mail_namespace_find_unsubscribable(struct mail_namespace *namespaces,
				   const char **mailbox)
{
	return mail_namespace_find_mask(namespaces, mailbox,
					0, NAMESPACE_FLAG_SUBSCRIPTIONS);
}

struct mail_namespace *
mail_namespace_find_inbox(struct mail_namespace *namespaces)
{
	while ((namespaces->flags & NAMESPACE_FLAG_INBOX) == 0)
		namespaces = namespaces->next;
	return namespaces;
}

bool mail_namespace_update_name(const struct mail_namespace *ns,
				const char **mailbox)
{
	struct mail_namespace tmp_ns = *ns;

	/* FIXME: a bit kludgy.. */
	tmp_ns.next = NULL;
	return mail_namespace_find_mask(&tmp_ns, mailbox, 0, 0) != NULL;
}

struct mail_namespace *
mail_namespace_find_prefix(struct mail_namespace *namespaces,
			   const char *prefix)
{
        struct mail_namespace *ns;
	unsigned int len = strlen(prefix);

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
	unsigned int len = strlen(prefix);

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (ns->prefix_len == len + 1 &&
		    strncmp(ns->prefix, prefix, len) == 0 &&
		    ns->prefix[len] == ns->sep)
			return ns;
	}
	return NULL;
}
