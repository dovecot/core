#ifndef __MAIL_NAMESPACE_H
#define __MAIL_NAMESPACE_H

enum namespace_type {
	NAMESPACE_PRIVATE,
	NAMESPACE_SHARED,
	NAMESPACE_PUBLIC
};

enum namespace_flags {
	/* Namespace contains the INBOX mailbox (there can be only one) */
	NAMESPACE_FLAG_INBOX	= 0x01,
	/* Namespace is visible only by explicitly using its full prefix */
	NAMESPACE_FLAG_HIDDEN	= 0x02,
	/* Namespace is visible with LIST */
	NAMESPACE_FLAG_LIST	= 0x04
};

struct mail_namespace {
	/* Namespaces are sorted by their prefix length, "" comes first */
	struct mail_namespace *next;

        enum namespace_type type;
	char sep, real_sep, sep_str[3];
	enum namespace_flags flags;

	const char *prefix;
	size_t prefix_len;

	struct mailbox_list *list;
	/* FIXME: we should support multiple storages in one namespace */
	struct mail_storage *storage;
};

/* Called after namespaces has been created */
extern void (*hook_mail_namespaces_created)(struct mail_namespace *namespaces);

int mail_namespaces_init(pool_t pool, const char *user,
			 struct mail_namespace **namespaces_r);
struct mail_namespace *mail_namespaces_init_empty(pool_t pool);
void mail_namespaces_deinit(struct mail_namespace **namespaces);

/* Update hierarchy separators in given name to real_sep characters. */
const char *mail_namespace_fix_sep(struct mail_namespace *ns, const char *name);
/* Returns the hierarchy separator for mailboxes that are listed at root. */
char mail_namespace_get_root_sep(struct mail_namespace *namespaces);

/* Returns namespace based on the mailbox name's prefix. Updates mailbox to
   be a valid name inside the namespace (prefix is skipped, hierarchy separator
   is changed to real_sep). If no namespaces were found, returns NULL. */
struct mail_namespace *
mail_namespace_find(struct mail_namespace *namespaces, const char **mailbox);
/* Like above, but ignore hidden namespaces. */
struct mail_namespace *
mail_namespace_find_visible(struct mail_namespace *namespaces,
			    const char **mailbox);
/* Returns the INBOX namespace */
struct mail_namespace *
mail_namespace_find_inbox(struct mail_namespace *namespaces);
/* Returns TRUE if the given namespace matches the mailbox's prefix.
   Updates mailbox name to be a valid name inside the namespace. */
bool mail_namespace_update_name(struct mail_namespace *ns,
				const char **mailbox);

/* Find a namespace with given prefix. */
struct mail_namespace *
mail_namespace_find_prefix(struct mail_namespace *namespaces,
			   const char *prefix);
/* Like _find_prefix(), but ignore trailing separator */
struct mail_namespace *
mail_namespace_find_prefix_nosep(struct mail_namespace *namespaces,
				 const char *prefix);

#endif
