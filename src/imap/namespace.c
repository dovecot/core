/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "file-lock.h"
#include "commands.h"
#include "namespace.h"

#include <stdlib.h>

static void namespace_init_storage(struct namespace *ns)
{
	ns->prefix_len = strlen(ns->prefix);
	ns->real_sep = mail_storage_get_hierarchy_sep(ns->storage);

	if (ns->sep == '\0')
                ns->sep = ns->real_sep;

	if (ns->sep == '"' || ns->sep == '\\') {
		ns->sep_str[0] = '\\';
		ns->sep_str[1] = ns->sep;
	} else {
		ns->sep_str[0] = ns->sep;
	}
}

static struct namespace *
namespace_add_env(pool_t pool, const char *data, unsigned int num,
		  const char *user, enum mail_storage_flags flags,
		  enum file_lock_method lock_method)
{
        struct namespace *ns;
        const char *sep, *type, *prefix;
	bool inbox, hidden, subscriptions;

	ns = p_new(pool, struct namespace, 1);

	sep = getenv(t_strdup_printf("NAMESPACE_%u_SEP", num));
	type = getenv(t_strdup_printf("NAMESPACE_%u_TYPE", num));
	prefix = getenv(t_strdup_printf("NAMESPACE_%u_PREFIX", num));
	inbox = getenv(t_strdup_printf("NAMESPACE_%u_INBOX", num)) != NULL;
	hidden = getenv(t_strdup_printf("NAMESPACE_%u_HIDDEN", num)) != NULL;
	subscriptions = getenv(t_strdup_printf("NAMESPACE_%u_SUBSCRIPTIONS",
					       num)) != NULL;

	if (type == NULL || *type == '\0' || strncmp(type, "private", 7) == 0)
		ns->type = NAMESPACE_PRIVATE;
	else if (strncmp(type, "shared", 6) == 0)
		ns->type = NAMESPACE_SHARED;
	else if (strncmp(type, "public", 6) == 0)
		ns->type = NAMESPACE_PUBLIC;
	else
		i_fatal("Unknown namespace type: %s", type);

	if (ns->type != NAMESPACE_PRIVATE)
		flags |= MAIL_STORAGE_FLAG_SHARED_NAMESPACE;
	if (ns->inbox)
		flags |= MAIL_STORAGE_FLAG_HAS_INBOX;

	if (prefix == NULL)
		prefix = "";

	if ((flags & MAIL_STORAGE_FLAG_DEBUG) != 0) {
		i_info("Namespace: type=%s, prefix=%s, sep=%s, "
		       "inbox=%s, hidden=%s, subscriptions=%s",
		       type == NULL ? "" : type, prefix, sep == NULL ? "" : sep,
		       inbox ? "yes" : "no",
		       hidden ? "yes" : "no",
		       subscriptions ? "yes" : "no");
	}

	ns->prefix = p_strdup(pool, prefix);
	ns->inbox = inbox;
	ns->hidden = hidden;
	ns->subscriptions = subscriptions;
	ns->storage = mail_storage_create(NULL, data, user, flags, lock_method);
	if (ns->storage == NULL) {
		i_fatal("Failed to create storage for '%s' with data: %s",
			ns->prefix, data);
	}

	if (sep != NULL)
		ns->sep = *sep;
        namespace_init_storage(ns);
	return ns;
}

struct namespace *namespace_init(pool_t pool, const char *user)
{
	struct namespace *namespaces, *ns, **ns_p;
	enum mail_storage_flags flags;
        enum file_lock_method lock_method;
	const char *mail, *data;
	unsigned int i;

	mail_storage_parse_env(&flags, &lock_method);
        namespaces = NULL; ns_p = &namespaces;

	/* first try NAMESPACE_* environments */
	for (i = 1; ; i++) {
		t_push();
		data = getenv(t_strdup_printf("NAMESPACE_%u", i));
		t_pop();

		if (data == NULL)
			break;

		t_push();
		*ns_p = namespace_add_env(pool, data, i, user, flags,
					  lock_method);
		t_pop();

		ns_p = &(*ns_p)->next;
	}

	if (namespaces != NULL)
		return namespaces;

	/* fallback to MAIL */
	mail = getenv("MAIL");
	if (mail == NULL) {
		/* support also maildir-specific environment */
		mail = getenv("MAILDIR");
		if (mail != NULL)
			mail = t_strconcat("maildir:", mail, NULL);
	}

	ns = p_new(pool, struct namespace, 1);
	ns->type = NAMESPACE_PRIVATE;
	ns->inbox = TRUE;
	ns->subscriptions = TRUE;
	ns->prefix = "";

	flags |= MAIL_STORAGE_FLAG_HAS_INBOX;
	ns->storage = mail_storage_create(NULL, mail, user, flags, lock_method);
	if (ns->storage == NULL) {
		if (mail != NULL && *mail != '\0')
			i_fatal("Failed to create storage with data: %s", mail);
		else {
			const char *home;

			home = getenv("HOME");
			if (home == NULL) home = "not set";

			i_fatal("MAIL environment missing and "
				"autodetection failed (home %s)", home);
		}
	}

	namespace_init_storage(ns);
	return ns;
}

void namespace_deinit(struct namespace *namespaces)
{
	while (namespaces != NULL) {
		mail_storage_destroy(&namespaces->storage);
		namespaces = namespaces->next;
	}
}

const char *namespace_fix_sep(struct namespace *ns, const char *name)
{
	char *ret, *p;

	if (ns->sep == ns->real_sep)
		return name;

	ret = p_strdup(unsafe_data_stack_pool, name);
	for (p = ret; *p != '\0'; p++) {
		if (*p == ns->sep)
			*p = ns->real_sep;
	}
	return ret;
}

static struct namespace *
namespace_find_int(struct namespace *namespaces, const char **mailbox,
		   int show_hidden)
{
#define CHECK_VISIBILITY(ns, show_hidden) \
	((!(ns)->hidden) || (show_hidden))
        struct namespace *ns = namespaces;
	const char *box = *mailbox;
	struct namespace *best = NULL;
	size_t best_len = 0;
	bool inbox;

	inbox = strncasecmp(box, "INBOX", 5) == 0;
	if (inbox && box[5] == '\0') {
		/* find the INBOX namespace */
		*mailbox = "INBOX";
		while (ns != NULL) {
			if (ns->inbox && CHECK_VISIBILITY(ns, show_hidden))
				return ns;
			if (*ns->prefix == '\0')
				best = ns;
			ns = ns->next;
		}
		return best;
	}

	for (; ns != NULL; ns = ns->next) {
		if (ns->prefix_len >= best_len &&
		    (strncmp(ns->prefix, box, ns->prefix_len) == 0 ||
		     (inbox && strncmp(ns->prefix, "INBOX", 5) == 0 &&
		      strncmp(ns->prefix+5, box+5, ns->prefix_len-5) == 0)) &&
		    CHECK_VISIBILITY(ns, show_hidden)) {
			best = ns;
			best_len = ns->prefix_len;
		}
	}

	if (best != NULL) {
		if (best_len > 0)
			*mailbox += best_len;
		else if (inbox && (box[5] == best->sep || box[5] == '\0'))
			*mailbox = t_strconcat("INBOX", box+5, NULL);

		*mailbox = namespace_fix_sep(best, *mailbox);
	}

	return best;
}

struct namespace *
namespace_find(struct namespace *namespaces, const char **mailbox)
{
	return namespace_find_int(namespaces, mailbox, TRUE);
}

struct namespace *
namespace_find_visible(struct namespace *namespaces, const char **mailbox)
{
	return namespace_find_int(namespaces, mailbox, FALSE);
}

struct namespace *
namespace_find_prefix(struct namespace *namespaces, const char *prefix)
{
        struct namespace *ns;
	unsigned int len = strlen(prefix);

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (ns->prefix_len == len && strcmp(ns->prefix, prefix) == 0)
			return ns;
	}
	return NULL;
}
