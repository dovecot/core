/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mailbox-list-private.h"
#include "maildir-storage.h"
#include "quota-private.h"
#include "quota-fs.h"

#include <ctype.h>
#include <stdlib.h>
#include <sys/wait.h>

#define DEFAULT_QUOTA_EXCEEDED_MSG "Quota exceeded"
#define RULE_NAME_DEFAULT_FORCE "*"
#define RULE_NAME_DEFAULT_NONFORCE "?"

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

static int quota_default_test_alloc(struct quota_transaction_context *ctx,
				    uoff_t size, bool *too_large_r);

struct quota *quota_init(void)
{
	struct quota *quota;

	quota = i_new(struct quota, 1);
	quota->test_alloc = quota_default_test_alloc;
	quota->debug = getenv("DEBUG") != NULL;
	quota->quota_exceeded_msg = getenv("QUOTA_EXCEEDED_MESSAGE");
	if (quota->quota_exceeded_msg == NULL)
		quota->quota_exceeded_msg = DEFAULT_QUOTA_EXCEEDED_MSG;
	i_array_init(&quota->roots, 4);
	i_array_init(&quota->storages, 8);

	return quota;
}

void quota_deinit(struct quota **_quota)
{
	struct quota *quota = *_quota;
	struct quota_root **root_p, *root;

	*_quota = NULL;
	while (array_count(&quota->roots) > 0) {
		root_p = array_idx_modifiable(&quota->roots, 0);
		root = *root_p;
		quota_root_deinit(&root);
	}

	array_free(&quota->roots);
	array_free(&quota->storages);
	i_free(quota);
}

static const struct quota_backend *quota_backend_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(quota_backends); i++) {
		if (strcmp(quota_backends[i]->name, name) == 0)
			return quota_backends[i];
	}

	return NULL;
}

struct quota_root *quota_root_init(struct quota *quota, const char *root_def)
{
	struct quota_root *root;
	const struct quota_backend *backend;
	const char *p, *args, *backend_name, *const *tmp;

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

	if (quota->debug) {
		i_info("Quota root: name=%s backend=%s args=%s",
		       root->name, backend_name, args == NULL ? "" : args);
	}

	i_array_init(&root->rules, 4);
	i_array_init(&root->warning_rules, 4);
	array_create(&root->quota_module_contexts, default_pool,
		     sizeof(void *), 5);

	array_append(&quota->roots, &root, 1);

	if (backend->v.init != NULL) {
		if (backend->v.init(root, args) < 0) {
			quota_root_deinit(&root);
			return NULL;
		}
	} else if (args != NULL) {
		tmp = t_strsplit_spaces(args, " ");
		for (; *tmp != NULL; tmp++) {
			if (strcmp(*tmp, "noenforcing") == 0)
				root->no_enforcing = TRUE;
			else
				break;
		}
		if (*tmp != NULL) {
			i_fatal("Quota root %s backend %s: "
				"Unknown parameter: %s",
				root->name, backend_name, *tmp);
		}
	}
	return root;
}

void quota_root_deinit(struct quota_root **_root)
{
	struct quota_root *root = *_root;
	pool_t pool = root->pool;
	struct quota_root *const *roots;
	struct quota_warning_rule *warnings;
	unsigned int i, count;

	*_root = NULL;

	roots = array_get(&root->quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i] == root) {
			array_delete(&root->quota->roots, i, 1);
			break;
		}
	}

	warnings = array_get_modifiable(&root->warning_rules, &count);
	for (i = 0; i < count; i++)
		i_free(warnings[i].command);
	array_free(&root->warning_rules);

	array_free(&root->rules);
	array_free(&root->quota_module_contexts);

	root->backend.v.deinit(root);
	pool_unref(&pool);
}

struct quota_rule *
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

static int
quota_rule_parse_percentage(struct quota_root *root, struct quota_rule *rule,
			    int64_t *limit, const char **error_r)
{
	int64_t percentage = *limit;

	if (percentage <= 0 || percentage >= -1U) {
		*error_r = p_strdup_printf(root->pool,
			"Invalid rule percentage: %lld", (long long)percentage);
		return -1;
	}

	if (rule == &root->default_rule) {
		*error_r = "Default rule can't be a percentage";
		return -1;
	}

	if (limit == &rule->bytes_limit)
		rule->bytes_percent = percentage;
	else if (limit == &rule->count_limit)
		rule->count_percent = percentage;
	else
		i_unreached();
	return 0;
}

static void
quota_rule_recalculate_relative_rules(struct quota_rule *rule,
				      const struct quota_rule *default_rule)
{
	if (rule->bytes_percent > 0) {
		rule->bytes_limit = default_rule->bytes_limit *
			rule->bytes_percent / 100;
	}
	if (rule->count_percent > 0) {
		rule->count_limit = default_rule->count_limit *
			rule->count_percent / 100;
	}
}

void quota_root_recalculate_relative_rules(struct quota_root *root)
{
	struct quota_rule *rules;
	struct quota_warning_rule *warning_rules;
	unsigned int i, count;

	rules = array_get_modifiable(&root->rules, &count);
	for (i = 0; i < count; i++) {
		quota_rule_recalculate_relative_rules(&rules[i],
						      &root->default_rule);
	}

	warning_rules = array_get_modifiable(&root->warning_rules, &count);
	for (i = 0; i < count; i++) {
		quota_rule_recalculate_relative_rules(&warning_rules[i].rule,
						      &root->default_rule);
	}
}

static int
quota_rule_parse_limits(struct quota_root *root, struct quota_rule *rule,
			const char *limits, bool allow_negative,
			const char **error_r)
{
	const char **args;
	char *p;
	uint64_t multiply;
	int64_t *limit;

	args = t_strsplit(limits, ":");
	for (; *args != NULL; args++) {
		multiply = 1;
		limit = NULL;
		if (strncmp(*args, "storage=", 8) == 0) {
			multiply = 1024;
			limit = &rule->bytes_limit;
			*limit = strtoll(*args + 8, &p, 10);
		} else if (strncmp(*args, "bytes=", 6) == 0) {
			limit = &rule->bytes_limit;
			*limit = strtoll(*args + 6, &p, 10);
		} else if (strncmp(*args, "messages=", 9) == 0) {
			limit = &rule->count_limit;
			*limit = strtoll(*args + 9, &p, 10);
		} else {
			*error_r = p_strdup_printf(root->pool,
					"Unknown rule limit name: %s", *args);
			return -1;
		}

		switch (i_toupper(*p)) {
		case '\0':
			/* default */
			break;
		case 'B':
			multiply = 1;
			break;
		case 'K':
			multiply = 1024;
			break;
		case 'M':
			multiply = 1024*1024;
			break;
		case 'G':
			multiply = 1024*1024*1024;
			break;
		case 'T':
			multiply = 1024ULL*1024*1024*1024;
			break;
		case '%':
			multiply = 0;
			if (quota_rule_parse_percentage(root, rule, limit,
							error_r) < 0)
				return -1;
			break;
		default:
			*error_r = p_strdup_printf(root->pool,
					"Invalid rule limit value: %s", *args);
			return -1;
		}
		*limit *= multiply;
	}
	if (!allow_negative) {
		if (rule->bytes_limit < 0) {
			*error_r = "Bytes limit can't be negative";
			return -1;
		}
		if (rule->count_limit < 0) {
			*error_r = "Count limit can't be negative";
			return -1;
		}
	}
	return 0;
}

int quota_root_add_rule(struct quota_root *root, const char *rule_def,
			const char **error_r)
{
	struct quota_rule *rule;
	const char *p, *mailbox_name;
	int ret = 0;

	p = strchr(rule_def, ':');
	if (p == NULL) {
		*error_r = "Invalid rule";
		return -1;
	}

	/* <mailbox name>:<quota limits> */
	mailbox_name = t_strdup_until(rule_def, p++);

	rule = quota_root_rule_find(root, mailbox_name);
	if (rule == NULL) {
		if (strcmp(mailbox_name, RULE_NAME_DEFAULT_NONFORCE) == 0)
			rule = &root->default_rule;
		else if (strcmp(mailbox_name, RULE_NAME_DEFAULT_FORCE) == 0) {
			rule = &root->default_rule;
			root->force_default_rule = TRUE;
		} else {
			rule = array_append_space(&root->rules);
			rule->mailbox_name = p_strdup(root->pool, mailbox_name);
		}
	}

	if (strcmp(p, "ignore") == 0) {
		rule->ignore = TRUE;
		if (root->quota->debug) {
			i_info("Quota rule: root=%s mailbox=%s ignored",
			       root->name, mailbox_name);
		}
		return 0;
	}

	if (strncmp(p, "backend=", 8) == 0) {
		if (!root->backend.v.parse_rule(root, rule, p + 8, error_r))
			ret = -1;
	} else {
		bool allow_negative = rule != &root->default_rule;

		if (quota_rule_parse_limits(root, rule, p,
					    allow_negative, error_r) < 0)
			ret = -1;
	}

	quota_root_recalculate_relative_rules(root);
	if (root->quota->debug) {
		i_info("Quota rule: root=%s mailbox=%s "
		       "bytes=%lld (%u%%) messages=%lld (%u%%)", root->name,
		       mailbox_name,
		       (long long)rule->bytes_limit, rule->bytes_percent,
		       (long long)rule->count_limit, rule->count_percent);
	}
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
		if (!rule->ignore) {
			bytes_limit += rule->bytes_limit;
			count_limit += rule->count_limit;
		} else {
			bytes_limit = 0;
			count_limit = 0;
		}
		found = TRUE;
	}

	*bytes_limit_r = bytes_limit <= 0 ? 0 : bytes_limit;
	*count_limit_r = count_limit <= 0 ? 0 : count_limit;
	return found;
}

static void quota_maildir_storage_set(struct mail_storage *storage)
{
	/* FIXME: a bit ugly location for this code. */
	if (strcmp(storage->name, "maildir") == 0) {
		/* For newly generated filenames add ,S=size. */
		struct maildir_storage *mstorage =
			(struct maildir_storage *)storage;

		mstorage->save_size_in_filename = TRUE;
	}
}

void quota_add_user_storage(struct quota *quota, struct mail_storage *storage)
{
	struct quota_root *const *roots;
	struct mail_storage *const *storages;
	struct quota_backend **backends;
	const char *path, *path2;
	unsigned int i, j, count;
	bool is_file;

	quota_maildir_storage_set(storage);

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

int quota_root_add_warning_rule(struct quota_root *root, const char *rule_def,
				const char **error_r)
{
	struct quota_warning_rule *warning;
	struct quota_rule rule;
	const char *p;
	int ret;

	p = strchr(rule_def, ' ');
	if (p == NULL) {
		*error_r = "No command specified";
		return -1;
	}

	memset(&rule, 0, sizeof(rule));
	ret = quota_rule_parse_limits(root, &rule, t_strdup_until(rule_def, p),
				      TRUE, error_r);
	if (ret < 0)
		return -1;

	warning = array_append_space(&root->warning_rules);
	warning->command = i_strdup(p+1);
	warning->rule = rule;

	quota_root_recalculate_relative_rules(root);
	if (root->quota->debug) {
		i_info("Quota warning: bytes=%llu (%u%%) "
		       "messages=%llu (%u%%) command=%s",
		       (unsigned long long)warning->rule.bytes_limit,
		       warning->rule.bytes_percent,
		       (unsigned long long)warning->rule.count_limit,
		       warning->rule.count_percent, warning->command);
	}
	return 0;
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

	/* Get the value first. This call may also update quota limits if
	   they're defined externally. */
	ret = root->backend.v.get_resource(root, name, value_r);
	if (ret <= 0)
		return ret;

	(void)quota_root_get_rule_limits(root, mailbox_name,
					 &bytes_limit, &count_limit);
	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*limit_r = bytes_limit;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*limit_r = count_limit;
	else
		*limit_r = 0;

	if (kilobytes) {
		*value_r /= 1024;
		*limit_r /= 1024;
	}
	return *limit_r == 0 ? 0 : 1;
}

int quota_set_resource(struct quota_root *root ATTR_UNUSED,
		       const char *name ATTR_UNUSED,
		       uint64_t value ATTR_UNUSED, const char **error_r)
{
	/* the quota information comes from userdb (or even config file),
	   so there's really no way to support this until some major changes
	   are done */
	*error_r = MAIL_ERRSTR_NO_PERMISSION;
	return -1;
}

struct quota_transaction_context *quota_transaction_begin(struct quota *quota,
							  struct mailbox *box)
{
	struct quota_transaction_context *ctx;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = quota;
	ctx->box = box;
	ctx->bytes_left = (uint64_t)-1;
	ctx->count_left = (uint64_t)-1;
	return ctx;
}

static int quota_transaction_set_limits(struct quota_transaction_context *ctx)
{
	struct quota_root *const *roots;
	const char *mailbox_name;
	unsigned int i, count;
	uint64_t current, limit, left;
	int ret;

	ctx->limits_set = TRUE;
	mailbox_name = mailbox_get_name(ctx->box);

	/* find the lowest quota limits from all roots and use them */
	roots = array_get(&ctx->quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->no_enforcing) {
			/* we don't care what the current quota is */
			continue;
		}

		ret = quota_get_resource(roots[i], mailbox_name,
					 QUOTA_NAME_STORAGE_BYTES,
					 &current, &limit);
		if (ret > 0) {
			current += ctx->bytes_used;
			left = limit < current ? 0 : limit - current;
			if (ctx->bytes_left > left)
				ctx->bytes_left = left;
		} else if (ret < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		
		ret = quota_get_resource(roots[i], mailbox_name,
					 QUOTA_NAME_MESSAGES, &current, &limit);
		if (ret > 0) {
			current += ctx->count_used;
			left = limit < current ? 0 : limit - current;
			if (ctx->count_left > left)
				ctx->count_left = left;
		} else if (ret < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	}
	return 0;
}

static void quota_warning_execute(const char *cmd)
{
	int ret = system(cmd);

	if (ret < 0) {
		i_error("system(%s) failed: %m", cmd);
	} else if (WIFSIGNALED(ret)) {
		i_error("system(%s) died with signal %d", cmd, WTERMSIG(ret));
	} else if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
		i_error("system(%s) exited with status %d",
			cmd, WIFEXITED(ret) ? WEXITSTATUS(ret) : ret);
	}
}

static void quota_warnings_execute(struct quota_transaction_context *ctx,
				   struct quota_root *root)
{
	struct quota_warning_rule *warnings;
	unsigned int i, count;
	uint64_t bytes_current, bytes_before, bytes_limit;
	uint64_t count_current, count_before, count_limit;

	warnings = array_get_modifiable(&root->warning_rules, &count);
	if (count == 0)
		return;

	if (quota_get_resource(root, "", QUOTA_NAME_STORAGE_BYTES,
			       &bytes_current, &bytes_limit) < 0)
		return;
	if (quota_get_resource(root, "", QUOTA_NAME_MESSAGES,
			       &count_current, &count_limit) < 0)
		return;

	bytes_before = bytes_current - ctx->bytes_used;
	count_before = count_current - ctx->count_used;
	for (i = 0; i < count; i++) {
		if ((bytes_before < (uint64_t)warnings[i].rule.bytes_limit &&
		     bytes_current >= (uint64_t)warnings[i].rule.bytes_limit) ||
		    (count_before < (uint64_t)warnings[i].rule.count_limit &&
		     count_current >= (uint64_t)warnings[i].rule.count_limit)) {
			quota_warning_execute(warnings[i].command);
			break;
		}
	}
}

int quota_transaction_commit(struct quota_transaction_context **_ctx)
{
	struct quota_transaction_context *ctx = *_ctx;
	struct quota_rule *rule;
	struct quota_root *const *roots;
	unsigned int i, count;
	const char *mailbox_name;
	int ret = 0;

	*_ctx = NULL;

	if (ctx->failed)
		ret = -1;
	else if (ctx->bytes_used != 0 || ctx->count_used != 0 ||
		 ctx->recalculate) {
		mailbox_name = mailbox_get_name(ctx->box);
		roots = array_get(&ctx->quota->roots, &count);
		for (i = 0; i < count; i++) {
			rule = quota_root_rule_find(roots[i], mailbox_name);
			if (rule != NULL && rule->ignore) {
				/* mailbox not included in quota */
				continue;
			}

			if (roots[i]->backend.v.update(roots[i], ctx) < 0)
				ret = -1;
		}
		/* execute quota warnings after all updates. this makes it
		   work correctly regardless of whether backend.get_resource()
		   returns updated values before backend.update() or not */
		for (i = 0; i < count; i++)
			quota_warnings_execute(ctx, roots[i]);
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
	uoff_t size;
	int ret;

	if (mail_get_physical_size(mail, &size) < 0)
		return -1;

	ret = quota_test_alloc(ctx, size, too_large_r);
	if (ret <= 0)
		return ret;

	quota_alloc(ctx, mail);
	return 1;
}

int quota_test_alloc(struct quota_transaction_context *ctx,
		     uoff_t size, bool *too_large_r)
{
	if (ctx->failed)
		return -1;

	if (!ctx->limits_set) {
		if (quota_transaction_set_limits(ctx) < 0)
			return -1;
	}
	return ctx->quota->test_alloc(ctx, size, too_large_r);
}

static int quota_default_test_alloc(struct quota_transaction_context *ctx,
				    uoff_t size, bool *too_large_r)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	*too_large_r = FALSE;

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

	if (mail_get_physical_size(mail, &size) == 0)
		ctx->bytes_used += size;

	ctx->count_used++;
}

void quota_free(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	if (mail_get_physical_size(mail, &size) < 0)
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
