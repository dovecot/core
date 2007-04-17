/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mailbox-list-private.h"
#include "quota-private.h"
#include "quota-fs.h"
#include <stdlib.h>

#define RULE_NAME_ALL_MAILBOXES "*"

struct quota_root_iter {
	struct quota *quota;
	struct mailbox *box;

	unsigned int i;
};

unsigned int quota_module_id = 0;

extern struct quota_backend quota_backend_dict;
extern struct quota_backend quota_backend_dirsize;
extern struct quota_backend quota_backend_fs;
extern struct quota_backend quota_backend_maildir;

static const struct quota_backend *quota_backends[] = {
#ifdef HAVE_FS_QUOTA
	&quota_backend_fs,
#endif
	&quota_backend_dict,
	&quota_backend_dirsize,
	&quota_backend_maildir
};
#define QUOTA_CLASS_COUNT (sizeof(quota_backends)/sizeof(quota_backends[0]))

static int quota_default_test_alloc(struct quota_transaction_context *ctx,
				    uoff_t size, bool *too_large_r);

struct quota *quota_init(void)
{
	struct quota *quota;

	quota = i_new(struct quota, 1);
	quota->test_alloc = quota_default_test_alloc;
	quota->debug = getenv("DEBUG") != NULL;
	i_array_init(&quota->roots, 4);
	i_array_init(&quota->storages, 8);

	return quota;
}

void quota_deinit(struct quota **_quota)
{
	struct quota *quota = *_quota;
	struct quota_root **root;

	*_quota = NULL;
	while (array_count(&quota->roots) > 0) {
		root = array_idx_modifiable(&quota->roots, 0);
		quota_root_deinit(root);
	}

	array_free(&quota->roots);
	array_free(&quota->storages);
	i_free(quota);
}

static const struct quota_backend *quota_backend_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < QUOTA_CLASS_COUNT; i++) {
		if (strcmp(quota_backends[i]->name, name) == 0)
			return quota_backends[i];
	}

	return NULL;
}

struct quota_root *quota_root_init(struct quota *quota, const char *root_def)
{
	struct quota_root *root;
	const struct quota_backend *backend;
	const char *p, *args, *backend_name;

	t_push();

	/* <backend>[:<quota root name>[:<backend args>]] */
	p = strchr(root_def, ':');
	if (p == NULL) {
		backend_name = root_def;
		args = NULL;
	} else {
		backend_name = t_strdup_until(root_def, p);
		args = p + 1;
	}

	backend = quota_backend_find(backend_name);
	if (backend == NULL)
		i_fatal("Unknown quota backend: %s", backend_name);
	
	t_pop();

	root = backend->v.alloc();
	root->quota = quota;
	root->backend = *backend;
	root->pool = pool_alloconly_create("quota root", 512);

	if (args != NULL) {
		/* save root's name */
		p = strchr(args, ':');
		if (p == NULL) {
			root->name = p_strdup(root->pool, args);
			args = NULL;
		} else {
			root->name = p_strdup_until(root->pool, args, p);
			args = p + 1;
		}
	} else {
		root->name = "";
	}

	i_array_init(&root->rules, 4);
	array_create(&root->quota_module_contexts, default_pool,
		     sizeof(void *), 5);

	array_append(&quota->roots, &root, 1);

	if (backend->v.init != NULL) {
		if (backend->v.init(root, args) < 0) {
			quota_root_deinit(&root);
			return NULL;
		}
	}
	return root;
}

void quota_root_deinit(struct quota_root **_root)
{
	struct quota_root *root = *_root;
	pool_t pool = root->pool;
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&root->quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i] == root)
			array_delete(&root->quota->roots, i, 1);
	}
	*_root = NULL;

	array_free(&root->rules);
	array_free(&root->quota_module_contexts);

	root->backend.v.deinit(root);
	pool_unref(pool);
}

static struct quota_rule *
quota_root_rule_find(struct quota_root *root, const char *name)
{
	struct quota_rule *rules;
	unsigned int i, count;

	rules = array_get_modifiable(&root->rules, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(rules[i].mailbox_name, name) == 0)
			return &rules[i];
	}
	return NULL;
}

int quota_root_add_rule(struct quota_root *root, const char *rule_def,
			const char **error_r)
{
	struct quota_rule *rule;
	const char **args;
	int ret = 0;

	if (*rule_def == '\0') {
		*error_r = "Empty rule";
		return -1;
	}

	/* <mailbox name>:<quota limits> */
	t_push();
        args = t_strsplit(rule_def, ":");

	rule = quota_root_rule_find(root, *args);
	if (rule == NULL) {
		if (strcmp(*args, RULE_NAME_ALL_MAILBOXES) == 0)
			rule = &root->default_rule;
		else {
			rule = array_append_space(&root->rules);
			rule->mailbox_name = p_strdup(root->pool, *args);
		}
	}

	for (args++; *args != NULL; args++) {
		if (strncmp(*args, "storage=", 8) == 0)
			rule->bytes_limit = strtoll(*args + 8, NULL, 10) * 1024;
		else if (strncmp(*args, "messages=", 9) == 0)
			rule->count_limit = strtoll(*args + 9, NULL, 10);
		else {
			*error_r = p_strdup_printf(root->pool,
					"Invalid rule limit: %s", *args);
			ret = -1;
			break;
		}
	}

	if (root->quota->debug) {
		i_info("Quota rule: root=%s mailbox=%s "
		       "storage=%lldkB messages=%lld", root->name,
		       rule->mailbox_name != NULL ? rule->mailbox_name : "",
		       (long long)rule->bytes_limit / 1024,
		       (long long)rule->count_limit);
	}

	t_pop();
	return ret;
}

static bool quota_root_get_rule_limits(struct quota_root *root,
				       const char *mailbox_name,
				       uint64_t *bytes_limit_r,
				       uint64_t *count_limit_r)
{
	struct quota_rule *rule;
	int64_t bytes_limit, count_limit;
	bool found;

	bytes_limit = root->default_rule.bytes_limit;
	count_limit = root->default_rule.count_limit;

	/* if default rule limits are 0, this rule applies only to specific
	   mailboxes */
	found = bytes_limit != 0 || count_limit != 0;

	rule = quota_root_rule_find(root, mailbox_name);
	if (rule != NULL) {
		bytes_limit += rule->bytes_limit;
		count_limit += rule->count_limit;
		found = TRUE;
	}

	*bytes_limit_r = bytes_limit <= 0 ? 0 : bytes_limit;
	*count_limit_r = count_limit <= 0 ? 0 : count_limit;
	return found;
}

void quota_add_user_storage(struct quota *quota, struct mail_storage *storage)
{
	struct quota_root *const *roots;
	struct mail_storage *const *storages;
	struct quota_backend **backends;
	const char *path, *path2;
	unsigned int i, j, count;
	bool is_file;

	/* first check if there already exists a storage with the exact same
	   path. we don't want to count them twice. */
	path = mail_storage_get_mailbox_path(storage, "", &is_file);
	if (path != NULL) {
		storages = array_get(&quota->storages, &count);
		for (i = 0; i < count; i++) {
			path2 = mail_storage_get_mailbox_path(storages[i], "",
							      &is_file);
			if (path2 != NULL && strcmp(path, path2) == 0) {
				/* duplicate */
				return;
			}
		}
	}

	array_append(&quota->storages, &storage, 1);

	roots = array_get(&quota->roots, &count);
	/* @UNSAFE: get different backends into one array */
	backends = t_new(struct quota_backend *, count + 1);
	for (i = 0; i < count; i++) {
		for (j = 0; backends[j] != NULL; j++) {
			if (backends[j]->name == roots[i]->backend.name)
				break;
		}
		if (backends[j] == NULL)
			backends[j] = &roots[i]->backend;
	}

	for (i = 0; backends[i] != NULL; i++) {
		if (backends[i]->v.storage_added != NULL)
			backends[i]->v.storage_added(quota, storage);
	}
}

void quota_remove_user_storage(struct quota *quota,
			       struct mail_storage *storage)
{
	struct mail_storage *const *storages;
	unsigned int i, count;
	
	storages = array_get(&quota->storages, &count);
	for (i = 0; i < count; i++) {
		if (storages[i] == storage) {
			array_delete(&quota->storages, i, 1);
			break;
		}
	}
}

struct quota_root_iter *
quota_root_iter_init(struct quota *quota, struct mailbox *box)
{
	struct quota_root_iter *iter;

	iter = i_new(struct quota_root_iter, 1);
	iter->quota = quota;
	iter->box = box;
	return iter;
}

struct quota_root *quota_root_iter_next(struct quota_root_iter *iter)
{
	struct quota_root *const *roots, *root = NULL;
	unsigned int count;
	uint64_t value, limit;
	int ret;

	roots = array_get(&iter->quota->roots, &count);
	if (iter->i >= count)
		return NULL;

	for (; iter->i < count; iter->i++) {
		ret = quota_get_resource(roots[iter->i], "",
					 QUOTA_NAME_STORAGE_KILOBYTES,
					 &value, &limit);
		if (ret == 0) {
			ret = quota_get_resource(roots[iter->i], "",
						 QUOTA_NAME_MESSAGES,
						 &value, &limit);
		}
		if (ret > 0) {
			root = roots[iter->i];
			break;
		}
	}

	iter->i++;
	return root;
}

void quota_root_iter_deinit(struct quota_root_iter **_iter)
{
	struct quota_root_iter *iter = *_iter;

	*_iter = NULL;
	i_free(iter);
}

struct quota_root *quota_root_lookup(struct quota *quota, const char *name)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(roots[i]->name, name) == 0)
			return roots[i];
	}
	return NULL;
}

const char *quota_root_get_name(struct quota_root *root)
{
	return root->name;
}

const char *const *quota_root_get_resources(struct quota_root *root)
{
	return root->backend.v.get_resources(root);
}

int quota_get_resource(struct quota_root *root, const char *mailbox_name,
		       const char *name, uint64_t *value_r, uint64_t *limit_r)
{
	uint64_t bytes_limit, count_limit;
	bool kilobytes = FALSE;
	int ret;

	if (strcmp(name, QUOTA_NAME_STORAGE_KILOBYTES) == 0) {
		name = QUOTA_NAME_STORAGE_BYTES;
		kilobytes = TRUE;
	}

	(void)quota_root_get_rule_limits(root, mailbox_name,
					 &bytes_limit, &count_limit);
	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*limit_r = bytes_limit;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*limit_r = count_limit;
	else
		*limit_r = 0;

	ret = root->backend.v.get_resource(root, name, value_r, limit_r);
	if (kilobytes && ret > 0) {
		*value_r /= 1024;
		*limit_r /= 1024;
	}
	return ret <= 0 ? ret :
		(*limit_r == 0 ? 0 : 1);
}

int quota_set_resource(struct quota_root *root __attr_unused__,
		       const char *name __attr_unused__,
		       uint64_t value __attr_unused__, const char **error_r)
{
	/* the quota information comes from userdb (or even config file),
	   so there's really no way to support this until some major changes
	   are done */
	*error_r = MAILBOX_LIST_ERR_NO_PERMISSION;
	return -1;
}

struct quota_transaction_context *quota_transaction_begin(struct quota *quota,
							  struct mailbox *box)
{
	struct quota_transaction_context *ctx;
	struct quota_root *const *roots;
	const char *mailbox_name;
	unsigned int i, count;
	uint64_t current, limit, left;
	int ret;

	mailbox_name = mailbox_get_name(box);
	
	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = quota;
	ctx->box = box;
	ctx->bytes_left = (uint64_t)-1;
	ctx->count_left = (uint64_t)-1;

	if (quota->counting) {
		/* we got here through quota_count_storage() */
		return ctx;
	}

	/* find the lowest quota limits from all roots and use them */
	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		ret = quota_get_resource(roots[i], mailbox_name,
					 QUOTA_NAME_STORAGE_BYTES,
					 &current, &limit);
		if (ret > 0) {
			left = limit < current ? 0 : limit - current;
			if (ctx->bytes_left > left)
				ctx->bytes_left = left;
		} else if (ret < 0) {
			ctx->failed = TRUE;
			break;
		}
		
		ret = quota_get_resource(roots[i], mailbox_name,
					 QUOTA_NAME_MESSAGES, &current, &limit);
		if (ret > 0) {
			left = limit < current ? 0 : limit - current;
			if (ctx->count_left > left)
				ctx->count_left = left;
		} else if (ret < 0) {
			ctx->failed = TRUE;
			break;
		}
	}
	return ctx;
}

int quota_transaction_commit(struct quota_transaction_context **_ctx)
{
	struct quota_transaction_context *ctx = *_ctx;
	struct quota_root *const *roots;
	unsigned int i, count;
	int ret = 0;

	*_ctx = NULL;

	if (ctx->failed)
		ret = -1;
	else {
		roots = array_get(&ctx->quota->roots, &count);
		for (i = 0; i < count; i++) {
			if (roots[i]->backend.v.update(roots[i], ctx) < 0)
				ret = -1;
		}
	}

	i_free(ctx);
	return ret;
}

void quota_transaction_rollback(struct quota_transaction_context **_ctx)
{
	struct quota_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx);
}

int quota_try_alloc(struct quota_transaction_context *ctx,
		    struct mail *mail, bool *too_large_r)
{
	int ret;

	ret = quota_test_alloc(ctx, mail_get_physical_size(mail), too_large_r);
	if (ret <= 0)
		return ret;

	quota_alloc(ctx, mail);
	return 1;
}

int quota_test_alloc(struct quota_transaction_context *ctx,
		     uoff_t size, bool *too_large_r)
{
	return ctx->quota->test_alloc(ctx, size, too_large_r);
}

static int quota_default_test_alloc(struct quota_transaction_context *ctx,
				    uoff_t size, bool *too_large_r)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	*too_large_r = FALSE;

	if (ctx->failed)
		return -1;
	if (ctx->count_left != 0 && ctx->bytes_left >= ctx->bytes_used + size)
		return 1;

	roots = array_get(&ctx->quota->roots, &count);
	for (i = 0; i < count; i++) {
		uint64_t bytes_limit, count_limit;

		if (!quota_root_get_rule_limits(roots[i],
						mailbox_get_name(ctx->box),
						&bytes_limit, &count_limit))
			continue;

		/* if size is bigger than any limit, then
		   it is bigger than the lowest limit */
		if (size > bytes_limit) {
			*too_large_r = TRUE;
			break;
		}
	}

	return 0;
}

void quota_alloc(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_used += size;

	ctx->count_used++;
}

void quota_free(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size == (uoff_t)-1)
		quota_recalculate(ctx);
	else
		quota_free_bytes(ctx, size);
}

void quota_free_bytes(struct quota_transaction_context *ctx,
		      uoff_t physical_size)
{
	ctx->bytes_used -= physical_size;
	ctx->count_used--;
}

void quota_recalculate(struct quota_transaction_context *ctx)
{
	ctx->recalculate = TRUE;
}
