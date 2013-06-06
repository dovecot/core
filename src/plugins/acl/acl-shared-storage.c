/* Copyright (c) 2008-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "var-expand.h"
#include "acl-plugin.h"
#include "acl-lookup-dict.h"
#include "acl-shared-storage.h"
#include "index/shared/shared-storage.h"

#define SHARED_NS_RETRY_SECS (60*60)

static bool acl_ns_prefix_exists(struct mail_namespace *ns)
{
	struct mailbox *box;
	const char *vname;
	enum mailbox_existence existence;
	bool ret;

	if (ns->list->mail_set->mail_shared_explicit_inbox)
		return FALSE;

	vname = t_strndup(ns->prefix, ns->prefix_len-1);
	box = mailbox_alloc(ns->list, vname, 0);
	ret = mailbox_exists(box, FALSE, &existence) == 0 &&
		existence == MAILBOX_EXISTENCE_SELECT;
	mailbox_free(&box);
	return ret;
}

static void
acl_shared_namespace_add(struct mail_namespace *ns,
			 struct mail_storage *storage, const char *userdomain)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ '\0', NULL, NULL }
	};
	struct shared_storage *sstorage = (struct shared_storage *)storage;
	struct mail_namespace *new_ns = ns;
	struct var_expand_table *tab;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	const char *p, *mailbox;
	string_t *str;

	if (strcmp(ns->user->username, userdomain) == 0) {
		/* skip ourself */
		return;
	}

	p = strchr(userdomain, '@');

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));
	tab[0].value = userdomain;
	tab[1].value = p == NULL ? userdomain : t_strdup_until(userdomain, p);
	tab[2].value = p == NULL ? "" : p + 1;

	str = t_str_new(128);
	var_expand(str, sstorage->ns_prefix_pattern, tab);
	mailbox = str_c(str);
	if (shared_storage_get_namespace(&new_ns, &mailbox) < 0)
		return;

	/* check if there are any mailboxes really visible to us */
	iter = mailbox_list_iter_init(new_ns->list, "*",
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL)
		break;
	(void)mailbox_list_iter_deinit(&iter);

	if (info == NULL && !acl_ns_prefix_exists(new_ns)) {
		/* no visible mailboxes, remove the namespace */
		mail_namespace_destroy(new_ns);
	}
}

int acl_shared_namespaces_add(struct mail_namespace *ns)
{
	struct acl_user *auser = ACL_USER_CONTEXT(ns->user);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ns->list);
	struct mail_storage *storage = mail_namespace_get_default_storage(ns);
	struct acl_lookup_dict_iter *iter;
	const char *name;

	i_assert(ns->type == MAIL_NAMESPACE_TYPE_SHARED);
	i_assert(strcmp(storage->name, SHARED_STORAGE_NAME) == 0);

	if (ioloop_time < alist->last_shared_add_check + SHARED_NS_RETRY_SECS) {
		/* already added, don't bother rechecking */
		return 0;
	}
	alist->last_shared_add_check = ioloop_time;

	iter = acl_lookup_dict_iterate_visible_init(auser->acl_lookup_dict);
	while ((name = acl_lookup_dict_iterate_visible_next(iter)) != NULL) {
		T_BEGIN {
			acl_shared_namespace_add(ns, storage, name);
		} T_END;
	}
	return acl_lookup_dict_iterate_visible_deinit(&iter);
}
