/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
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

	if (hook_mail_storage_created != NULL)
		hook_mail_storage_created(&ns->storage);
}

static struct namespace *
namespace_add_env(pool_t pool, const char *data, unsigned int num,
		  const char *user)
{
        struct namespace *ns;
        const char *sep, *type, *prefix;
	int inbox, hidden, subscriptions;

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

	if (prefix == NULL)
		prefix = "";

	ns->prefix = p_strdup(pool, prefix);
	ns->inbox = inbox;
	ns->hidden = hidden;
	ns->subscriptions = subscriptions;
	ns->storage = mail_storage_create_with_data(data, user);
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
	const char *mail, *data;
	unsigned int i;

        namespaces = NULL; ns_p = &namespaces;

	/* first try NAMESPACE_* environments */
	for (i = 1; ; i++) {
		t_push();
		data = getenv(t_strdup_printf("NAMESPACE_%u", i));
		t_pop();

		if (data == NULL)
			break;

		t_push();
		*ns_p = namespace_add_env(pool, data, i, user);
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
	ns->storage = mail_storage_create_with_data(mail, user);
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

	ns->type = NAMESPACE_PRIVATE;
	ns->inbox = TRUE;
	ns->subscriptions = TRUE;
	ns->prefix = "";
	namespace_init_storage(ns);
	return ns;
}

void namespace_deinit(struct namespace *namespaces)
{
	while (namespaces != NULL) {
		mail_storage_destroy(namespaces->storage);
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

struct namespace *
namespace_find(struct namespace *namespaces, const char **mailbox)
{
        struct namespace *ns = namespaces;
	const char *box = *mailbox;
	struct namespace *best = NULL;
	size_t best_len = 0;
	int inbox;

	inbox = strncasecmp(box, "INBOX", 5) == 0;
	if (inbox && box[5] == '\0') {
		/* find the INBOX namespace */
		*mailbox = "INBOX";
		while (ns != NULL) {
			if (ns->inbox)
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
		      strncmp(ns->prefix+5, box+5, ns->prefix_len-5) == 0))) {
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
