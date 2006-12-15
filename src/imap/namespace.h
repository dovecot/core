#ifndef __NAMESPACE_H
#define __NAMESPACE_H

enum namespace_type {
	NAMESPACE_PRIVATE,
	NAMESPACE_SHARED,
	NAMESPACE_PUBLIC
};

struct namespace {
	struct namespace *next;

        enum namespace_type type;
	char sep, real_sep, sep_str[3];

	const char *prefix;
	size_t prefix_len;

	bool inbox, hidden, subscriptions;
	struct mail_storage *storage;
};

struct namespace *namespace_init(pool_t pool, const char *user);
void namespace_deinit(struct namespace *namespaces);

const char *namespace_fix_sep(struct namespace *ns, const char *name);

struct namespace *
namespace_find(struct namespace *namespaces, const char **mailbox);
struct namespace *
namespace_find_visible(struct namespace *namespaces, const char **mailbox);
struct namespace *
namespace_find_prefix(struct namespace *namespaces, const char *prefix);

#endif
