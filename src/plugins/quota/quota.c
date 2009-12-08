/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mailbox-list-private.h"
#include "quota-private.h"
#include "quota-fs.h"

#include <ctype.h>
#include <stdlib.h>
#include <sys/wait.h>

#define DEFAULT_QUOTA_EXCEEDED_MSG \
	"Quota exceeded (mailbox for user is full)"
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

static void quota_root_add_rules(struct mail_user *user, const char *root_name, 
				 struct quota_root_settings *root_set)
{
	const char *rule_name, *rule, *error;
	unsigned int i;

	rule_name = t_strconcat(root_name, "_rule", NULL);
	for (i = 2;; i++) {
		rule = mail_user_plugin_getenv(user, rule_name);
		if (rule == NULL)
			break;

		if (quota_root_add_rule(root_set, rule, &error) < 0) {
			i_fatal("Quota root %s: Invalid rule %s: %s",
				root_name, rule, error);
		}
		rule_name = t_strdup_printf("%s_rule%d", root_name, i);
	}
}

static void
quota_root_add_warning_rules(struct mail_user *user, const char *root_name,
			     struct quota_root_settings *root_set)
{
	const char *rule_name, *rule, *error;
	unsigned int i;

	rule_name = t_strconcat(root_name, "_warning", NULL);
	for (i = 2;; i++) {
		rule = mail_user_plugin_getenv(user, rule_name);
		if (rule == NULL)
			break;

		if (quota_root_add_warning_rule(root_set, rule, &error) < 0) {
			i_fatal("Quota root %s: Invalid warning rule: %s",
				root_name, rule);
		}
		rule_name = t_strdup_printf("%s_warning%d", root_name, i);
	}
}

struct quota_settings *quota_user_read_settings(struct mail_user *user)
{
	struct quota_settings *quota_set;
	struct quota_root_settings *root_set;
	char root_name[6 + MAX_INT_STRLEN];
	const char *env;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("quota settings", 1024);
	quota_set = p_new(pool, struct quota_settings, 1);
	quota_set->pool = pool;
	quota_set->test_alloc = quota_default_test_alloc;
	quota_set->debug = user->mail_debug;
	quota_set->quota_exceeded_msg =
		mail_user_plugin_getenv(user, "quota_exceeded_message");
	if (quota_set->quota_exceeded_msg == NULL)
		quota_set->quota_exceeded_msg = DEFAULT_QUOTA_EXCEEDED_MSG;

	p_array_init(&quota_set->root_sets, pool, 4);
	i_strocpy(root_name, "quota", sizeof(root_name));
	for (i = 2;; i++) {
		env = mail_user_plugin_getenv(user, root_name);
		if (env == NULL)
			break;

		root_set = quota_root_settings_init(quota_set, env);
		if (root_set == NULL) {
			i_fatal("Couldn't create quota root %s: %s",
				root_name, env);
		}
		quota_root_add_rules(user, root_name, root_set);
		quota_root_add_warning_rules(user, root_name, root_set);

		i_snprintf(root_name, sizeof(root_name), "quota%d", i);
	}

	return quota_set;
}

void quota_settings_deinit(struct quota_settings **_quota_set)
{
	struct quota_settings *quota_set = *_quota_set;

	*_quota_set = NULL;

	pool_unref(&quota_set->pool);
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

struct quota_root_settings *
quota_root_settings_init(struct quota_settings *quota_set, const char *root_def)
{
	struct quota_root_settings *root_set;
	const struct quota_backend *backend;
	const char *p, *args, *backend_name;

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
	if (backend == NULL) {
		i_error("Unknown quota backend: %s", backend_name);
		return NULL;
	}
	
	root_set = p_new(quota_set->pool, struct quota_root_settings, 1);
	root_set->set = quota_set;
	root_set->backend = backend;

	if (args != NULL) {
		/* save root's name */
		p = strchr(args, ':');
		if (p == NULL) {
			root_set->name = p_strdup(quota_set->pool, args);
			args = NULL;
		} else {
			root_set->name =
				p_strdup_until(quota_set->pool, args, p);
			args = p + 1;
		}
	} else {
		root_set->name = "";
	}
	root_set->args = p_strdup(quota_set->pool, args);

	if (quota_set->debug) {
		i_debug("Quota root: name=%s backend=%s args=%s",
			root_set->name, backend_name, args == NULL ? "" : args);
	}

	p_array_init(&root_set->rules, quota_set->pool, 4);
	p_array_init(&root_set->warning_rules, quota_set->pool, 4);
	array_append(&quota_set->root_sets, &root_set, 1);
	return root_set;
}

static struct quota_root *
quota_root_init(struct quota_root_settings *root_set, struct quota *quota)
{
	struct quota_root *root;
	const char *const *tmp;

	root = root_set->backend->v.alloc();
	root->resource_ret = -1;
	root->pool = pool_alloconly_create("quota root", 512);
	root->set = root_set;
	root->quota = quota;
	root->backend = *root_set->backend;
	root->bytes_limit = root_set->default_rule.bytes_limit;
	root->count_limit = root_set->default_rule.count_limit;

	array_create(&root->quota_module_contexts, root->pool,
		     sizeof(void *), 10);

	if (root->backend.v.init != NULL) {
		if (root->backend.v.init(root, root_set->args) < 0)
			i_fatal("Quota root %s init() failed", root_set->name);
	} else if (root_set->args != NULL) {
		tmp = t_strsplit_spaces(root_set->args, " ");
		for (; *tmp != NULL; tmp++) {
			if (strcmp(*tmp, "noenforcing") == 0)
				root->no_enforcing = TRUE;
			else
				break;
		}
		if (*tmp != NULL) {
			i_fatal("Quota root %s backend %s: "
				"Unknown parameter: %s",
				root_set->name, root->backend.name, *tmp);
		}
	}
	return root;
}

static void quota_root_deinit(struct quota_root *root)
{
	pool_t pool = root->pool;

	root->backend.v.deinit(root);
	pool_unref(&pool);
}

struct quota *quota_init(struct quota_settings *quota_set,
			 struct mail_user *user)
{
	struct quota *quota;
	struct quota_root *root;
	struct quota_root_settings *const *root_sets;
	unsigned int i, count;

	quota = i_new(struct quota, 1);
	quota->user = user;
	quota->set = quota_set;
	i_array_init(&quota->roots, 8);

	root_sets = array_get(&quota_set->root_sets, &count);
	i_array_init(&quota->namespaces, count);
	for (i = 0; i < count; i++) {
		root = quota_root_init(root_sets[i], quota);
		array_append(&quota->roots, &root, 1);
	}
	return quota;
}

void quota_deinit(struct quota **_quota)
{
	struct quota *quota = *_quota;
	struct quota_root *const *roots;
	unsigned int i, count;

	*_quota = NULL;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++)
		quota_root_deinit(roots[i]);
	array_free(&quota->roots);
	array_free(&quota->namespaces);
	i_free(quota);
}

struct quota_rule *
quota_root_rule_find(struct quota_root_settings *root_set, const char *name)
{
	struct quota_rule *rule;

	array_foreach_modifiable(&root_set->rules, rule) {
		if (strcmp(rule->mailbox_name, name) == 0)
			return rule;
	}
	return NULL;
}

static int
quota_rule_parse_percentage(struct quota_root_settings *root_set,
			    struct quota_rule *rule,
			    int64_t *limit, const char **error_r)
{
	int64_t percentage = *limit;

	if (percentage <= 0 || percentage >= -1U) {
		*error_r = p_strdup_printf(root_set->set->pool,
			"Invalid rule percentage: %lld", (long long)percentage);
		return -1;
	}

	if (rule == &root_set->default_rule) {
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
				      int64_t bytes_limit, int64_t count_limit)
{
	if (rule->bytes_percent > 0) {
		rule->bytes_limit = bytes_limit * rule->bytes_percent / 100;
	}
	if (rule->count_percent > 0) {
		rule->count_limit = count_limit *
			rule->count_percent / 100;
	}
}

void quota_root_recalculate_relative_rules(struct quota_root_settings *root_set,
					   int64_t bytes_limit,
					   int64_t count_limit)
{
	struct quota_rule *rule;
	struct quota_warning_rule *warning_rule;

	array_foreach_modifiable(&root_set->rules, rule) {
		quota_rule_recalculate_relative_rules(rule, bytes_limit,
						      count_limit);
	}

	array_foreach_modifiable(&root_set->warning_rules, warning_rule) {
		quota_rule_recalculate_relative_rules(&warning_rule->rule,
						      bytes_limit, count_limit);
	}
}

static int
quota_rule_parse_limits(struct quota_root_settings *root_set,
			struct quota_rule *rule, const char *limits,
			bool allow_negative, const char **error_r)
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
			*error_r = p_strdup_printf(root_set->set->pool,
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
			if (quota_rule_parse_percentage(root_set, rule, limit,
							error_r) < 0)
				return -1;
			break;
		default:
			*error_r = p_strdup_printf(root_set->set->pool,
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

int quota_root_add_rule(struct quota_root_settings *root_set,
			const char *rule_def, const char **error_r)
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

	rule = quota_root_rule_find(root_set, mailbox_name);
	if (rule == NULL) {
		if (strcmp(mailbox_name, RULE_NAME_DEFAULT_NONFORCE) == 0)
			rule = &root_set->default_rule;
		else if (strcmp(mailbox_name, RULE_NAME_DEFAULT_FORCE) == 0) {
			rule = &root_set->default_rule;
			root_set->force_default_rule = TRUE;
		} else {
			rule = array_append_space(&root_set->rules);
			rule->mailbox_name =
				p_strdup(root_set->set->pool, mailbox_name);
		}
	}

	if (strcmp(p, "ignore") == 0) {
		rule->ignore = TRUE;
		if (root_set->set->debug) {
			i_debug("Quota rule: root=%s mailbox=%s ignored",
				root_set->name, mailbox_name);
		}
		return 0;
	}

	if (strncmp(p, "backend=", 8) == 0) {
		if (!root_set->backend->v.parse_rule(root_set, rule,
						     p + 8, error_r))
			ret = -1;
	} else {
		bool allow_negative = rule != &root_set->default_rule;

		if (quota_rule_parse_limits(root_set, rule, p,
					    allow_negative, error_r) < 0)
			ret = -1;
	}

	quota_root_recalculate_relative_rules(root_set,
					      root_set->default_rule.bytes_limit,
					      root_set->default_rule.count_limit);
	if (root_set->set->debug) {
		i_debug("Quota rule: root=%s mailbox=%s "
			"bytes=%lld%s messages=%lld%s", root_set->name,
			mailbox_name, (long long)rule->bytes_limit,
			rule->bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", rule->bytes_percent),
			(long long)rule->count_limit,
			rule->count_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", rule->count_percent));
	}
	return ret;
}

static int quota_root_get_rule_limits(struct quota_root *root,
				      const char *mailbox_name,
				      uint64_t *bytes_limit_r,
				      uint64_t *count_limit_r)
{
	struct quota_rule *rule;
	int64_t bytes_limit, count_limit;
	bool found;

	if (!root->set->force_default_rule) {
		if (root->backend.v.init_limits != NULL) {
			if (root->backend.v.init_limits(root) < 0)
				return -1;
		}
	}

	bytes_limit = root->bytes_limit;
	count_limit = root->count_limit;

	/* if default rule limits are 0, this rule applies only to specific
	   mailboxes */
	found = bytes_limit != 0 || count_limit != 0;

	rule = quota_root_rule_find(root->set, mailbox_name);
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
	return found ? 1 : 0;
}

void quota_add_user_namespace(struct quota *quota, struct mail_namespace *ns)
{
	struct quota_root *const *roots;
	struct mail_namespace *const *namespaces;
	struct quota_backend **backends;
	const char *path, *path2;
	unsigned int i, j, count;

	/* first check if there already exists a namespace with the exact same
	   path. we don't want to count them twice. */
	path = mailbox_list_get_path(ns->list, NULL,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (path != NULL) {
		namespaces = array_get(&quota->namespaces, &count);
		for (i = 0; i < count; i++) {
			path2 = mailbox_list_get_path(namespaces[i]->list, NULL,
				     	MAILBOX_LIST_PATH_TYPE_MAILBOX);
			if (strcmp(path, path2) == 0) {
				/* duplicate */
				return;
			}
		}
	}

	array_append(&quota->namespaces, &ns, 1);

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
		if (backends[i]->v.namespace_added != NULL)
			backends[i]->v.namespace_added(quota, ns);
	}
}

void quota_remove_user_namespace(struct mail_namespace *ns)
{
	struct quota *quota;
	struct mail_namespace *const *namespaces;
	unsigned int i, count;

	quota = ns->owner != NULL ?
		quota_get_mail_user_quota(ns->owner) :
		quota_get_mail_user_quota(ns->user);
	if (quota == NULL) {
		/* no quota for this namespace */
		return;
	}

	namespaces = array_get(&quota->namespaces, &count);
	for (i = 0; i < count; i++) {
		if (namespaces[i] == ns) {
			array_delete(&quota->namespaces, i, 1);
			break;
		}
	}
}

int quota_root_add_warning_rule(struct quota_root_settings *root_set,
				const char *rule_def, const char **error_r)
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
	ret = quota_rule_parse_limits(root_set, &rule,
				      t_strdup_until(rule_def, p),
				      TRUE, error_r);
	if (ret < 0)
		return -1;

	warning = array_append_space(&root_set->warning_rules);
	warning->command = i_strdup(p+1);
	warning->rule = rule;

	quota_root_recalculate_relative_rules(root_set,
					      root_set->default_rule.bytes_limit,
					      root_set->default_rule.count_limit);
	if (root_set->set->debug) {
		i_debug("Quota warning: bytes=%llu%s "
			"messages=%llu%s command=%s",
			(unsigned long long)warning->rule.bytes_limit,
			warning->rule.bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", warning->rule.bytes_percent),
			(unsigned long long)warning->rule.count_limit,
			warning->rule.count_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", warning->rule.count_percent),
			warning->command);
	}
	return 0;
}

struct quota_root_iter *
quota_root_iter_init(struct mailbox *box)
{
	struct quota_root_iter *iter;

	iter = i_new(struct quota_root_iter, 1);
	iter->quota = box->list->ns->owner != NULL ?
		quota_get_mail_user_quota(box->list->ns->owner) :
		quota_get_mail_user_quota(box->list->ns->user);
	iter->box = box;
	return iter;
}

bool quota_root_is_namespace_visible(struct quota_root *root,
				     struct mail_namespace *ns)
{
	if (root->ns != NULL) {
		if (root->ns != ns)
			return FALSE;
	} else {
		if (ns->owner == NULL)
			return FALSE;
	}
	return TRUE;
}

static bool
quota_root_is_visible(struct quota_root *root, struct mailbox *box,
		      bool enforce)
{
	if (root->no_enforcing && enforce) {
		/* we don't want to include this root in quota enforcing */
		return FALSE;
	}
	if (!quota_root_is_namespace_visible(root, box->list->ns))
		return FALSE;
	if (array_count(&root->quota->roots) == 1) {
		/* a single quota root: don't bother checking further */
		return TRUE;
	}
	return root->backend.v.match_box == NULL ? TRUE :
		root->backend.v.match_box(root, box);
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
		if (!quota_root_is_visible(roots[iter->i], iter->box, FALSE))
			continue;

		ret = roots[iter->i]->resource_ret;
		if (ret == -1) {
			ret = quota_get_resource(roots[iter->i], "",
						 QUOTA_NAME_STORAGE_KILOBYTES,
						 &value, &limit);
		}
		if (ret == 0) {
			ret = quota_get_resource(roots[iter->i], "",
						 QUOTA_NAME_MESSAGES,
						 &value, &limit);
		}
		roots[iter->i]->resource_ret = ret;
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

struct quota_root *quota_root_lookup(struct mail_user *user, const char *name)
{
	struct quota *quota;
	struct quota_root *const *roots;
	unsigned int i, count;

	quota = quota_get_mail_user_quota(user);
	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(roots[i]->set->name, name) == 0)
			return roots[i];
	}
	return NULL;
}

const char *quota_root_get_name(struct quota_root *root)
{
	return root->set->name;
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

	if (quota_root_get_rule_limits(root, mailbox_name,
				       &bytes_limit, &count_limit) < 0)
		return -1;

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

struct quota_transaction_context *quota_transaction_begin(struct mailbox *box)
{
	struct quota_transaction_context *ctx;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = box->list->ns->owner != NULL ?
		quota_get_mail_user_quota(box->list->ns->owner) :
		quota_get_mail_user_quota(box->list->ns->user);
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
	uint64_t bytes_limit, count_limit, current, limit, left;
	int ret;

	ctx->limits_set = TRUE;
	mailbox_name = mailbox_get_vname(ctx->box);

	/* find the lowest quota limits from all roots and use them */
	roots = array_get(&ctx->quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (!quota_root_is_visible(roots[i], ctx->box, TRUE))
			continue;

		if (quota_root_get_rule_limits(roots[i], mailbox_name,
					       &bytes_limit,
					       &count_limit) < 0) {
			ctx->failed = TRUE;
			return -1;
		}

		if (bytes_limit > 0) {
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
		}

		if (count_limit > 0) {
			ret = quota_get_resource(roots[i], mailbox_name,
						 QUOTA_NAME_MESSAGES,
						 &current, &limit);
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
	}
	return 0;
}

static void quota_warning_execute(struct quota_root *root, const char *cmd)
{
	int ret;

	if (root->quota->set->debug)
		i_debug("quota: Executing warning: %s", cmd);

	ret = system(cmd);
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

	warnings = array_get_modifiable(&root->set->warning_rules, &count);
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
			quota_warning_execute(root, warnings[i].command);
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
		mailbox_name = mailbox_get_vname(ctx->box);
		roots = array_get(&ctx->quota->roots, &count);
		for (i = 0; i < count; i++) {
			if (!quota_root_is_visible(roots[i], ctx->box, FALSE))
				continue;

			rule = quota_root_rule_find(roots[i]->set,
						    mailbox_name);
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
	return ctx->quota->set->test_alloc(ctx, size, too_large_r);
}

static int quota_default_test_alloc(struct quota_transaction_context *ctx,
				    uoff_t size, bool *too_large_r)
{
	struct quota_root *const *roots;
	unsigned int i, count;
	int ret;

	*too_large_r = FALSE;

	if (ctx->count_left != 0 && ctx->bytes_left >= ctx->bytes_used + size)
		return 1;

	roots = array_get(&ctx->quota->roots, &count);
	for (i = 0; i < count; i++) {
		uint64_t bytes_limit, count_limit;

		if (!quota_root_is_visible(roots[i], ctx->box, TRUE))
			continue;

		ret = quota_root_get_rule_limits(roots[i],
						 mailbox_get_vname(ctx->box),
						 &bytes_limit, &count_limit);
		if (ret == 0)
			continue;
		if (ret < 0)
			return -1;

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
