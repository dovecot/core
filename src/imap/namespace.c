/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "namespace.h"

#include <stdlib.h>

static struct namespace *
namespace_add_env(pool_t pool, const char *data, unsigned int num,
		  const char *user)
{
        struct namespace *ns;
        const char *sep, *type, *prefix;
	int inbox;

	ns = p_new(pool, struct namespace, 1);

	sep = getenv(t_strdup_printf("NAMESPACE_%u_SEP", num));
	type = getenv(t_strdup_printf("NAMESPACE_%u_TYPE", num));
	prefix = getenv(t_strdup_printf("NAMESPACE_%u_PREFIX", num));
	inbox = getenv(t_strdup_printf("NAMESPACE_%u_INBOX", num)) != NULL;

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
	ns->storage = mail_storage_create_with_data(data, user, ns->prefix,
						    sep != NULL ? *sep : '\0');
	if (ns->storage == NULL) {
		i_fatal("Failed to create storage for '%s' with data: %s",
			ns->prefix, data);
	}

	if (hook_mail_storage_created != NULL)
		hook_mail_storage_created(&ns->storage);

	ns->hierarchy_sep = ns->storage->hierarchy_sep;
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
	ns->storage = mail_storage_create_with_data(mail, user, NULL, '\0');
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
	ns->prefix = p_strdup(pool, "");
	ns->hierarchy_sep = ns->storage->hierarchy_sep;
	if (hook_mail_storage_created != NULL)
		hook_mail_storage_created(&ns->storage);

	return ns;
}

void namespace_deinit(struct namespace *namespaces)
{
	while (namespaces != NULL) {
		mail_storage_destroy(namespaces->storage);
		namespaces = namespaces->next;
	}
}

struct namespace *
namespace_find(struct namespace *namespaces, const char *mailbox)
{
	struct namespace *best = NULL;
	size_t len, best_len = 0;
	int inbox;

	inbox = strncasecmp(mailbox, "INBOX", 5) == 0;
	if (inbox && mailbox[5] == '\0') {
		/* find the INBOX namespace */
		while (namespaces != NULL) {
			if (namespaces->inbox)
				return namespaces;
			if (namespaces->prefix == NULL)
				best = namespaces;
			namespaces = namespaces->next;
		}
		return best;
	}

	while (namespaces != NULL) {
		len = namespaces->prefix == NULL ? 0 :
			strlen(namespaces->prefix);
		if (len >= best_len &&
		    (strncmp(namespaces->prefix, mailbox, len) == 0 ||
		     (inbox && strncmp(namespaces->prefix, "INBOX", 5) == 0 &&
		      mailbox[5] == namespaces->hierarchy_sep &&
		      namespaces->prefix[5] == namespaces->hierarchy_sep &&
		      strncmp(namespaces->prefix+6, mailbox+6, len-6) == 0))) {
			best = namespaces;
			best_len = len;
		}
		namespaces = namespaces->next;
	}

	return best;
}
