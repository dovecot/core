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
	char hierarchy_sep;
	char *prefix;
	struct mail_storage *storage;
};

struct namespace *namespace_init(pool_t pool, const char *user);
void namespace_deinit(struct namespace *namespaces);

struct namespace *
namespace_find(struct namespace *namespaces, const char *mailbox);

#endif
