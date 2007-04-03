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

	bool inbox, hidden, subscriptions;
	struct mail_storage *storage;
};

int mail_namespaces_init(pool_t pool, const char *user,
			 struct mail_namespace **namespaces_r);
struct mail_namespace *mail_namespaces_init_empty(pool_t pool);
void mail_namespaces_deinit(struct mail_namespace **namespaces);

const char *mail_namespace_fix_sep(struct mail_namespace *ns, const char *name);

struct mail_namespace *
mail_namespace_find(struct mail_namespace *namespaces, const char **mailbox);
struct mail_namespace *
mail_namespace_find_visible(struct mail_namespace *namespaces,
			    const char **mailbox);
struct mail_namespace *
mail_namespace_find_prefix(struct mail_namespace *namespaces,
			   const char *prefix);

#endif
