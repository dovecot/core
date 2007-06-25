#ifndef __MAIL_NAMESPACE_H
#define __MAIL_NAMESPACE_H

enum namespace_type {
	NAMESPACE_PRIVATE,
	NAMESPACE_SHARED,
	NAMESPACE_PUBLIC
};

struct mail_namespace {
	struct mail_namespace *next;

        enum namespace_type type;
	char sep, real_sep, sep_str[3];

	const char *prefix;
	size_t prefix_len;

	bool inbox, hidden, list_prefix, subscriptions;
	struct mailbox_list *list;
	/* FIXME: we should support multiple storages in one namespace */
	struct mail_storage *storage;
};

int mail_namespaces_init(pool_t pool, const char *user,
			 struct mail_namespace **namespaces_r);
struct mail_namespace *mail_namespaces_init_empty(pool_t pool);
void mail_namespaces_deinit(struct mail_namespace **namespaces);

/* Update hierarchy separators in given name to real_sep characters. */
const char *mail_namespace_fix_sep(struct mail_namespace *ns, const char *name);

/* Returns namespace based on the mailbox name's prefix. Updates mailbox to
   be a valid name inside the namespace (prefix is skipped, hierarchy separator
   is changed to real_sep). If no namespaces were found, returns NULL. */
struct mail_namespace *
mail_namespace_find(struct mail_namespace *namespaces, const char **mailbox);
/* Like above, but ignore hidden namespaces. */
struct mail_namespace *
mail_namespace_find_visible(struct mail_namespace *namespaces,
			    const char **mailbox);
/* Returns TRUE if the given namespace matches the mailbox's prefix.
   Updates mailbox name to be a valid name inside the namespace. */
bool mail_namespace_update_name(struct mail_namespace *ns,
				const char **mailbox);

/* Find a namespace with given prefix. */
struct mail_namespace *
mail_namespace_find_prefix(struct mail_namespace *namespaces,
			   const char *prefix);

#endif
