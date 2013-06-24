/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "net.h"
#include "write-full.h"
#include "eacces-error.h"
#include "mailbox-list-private.h"
#include "quota-private.h"
#include "quota-fs.h"

#include <ctype.h>
#include <stdlib.h>
#include <sys/wait.h>

#define QUOTA_DEFAULT_GRACE "10%"
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
static int
quota_root_parse_grace(struct mail_user *user, const char *root_name,
		       struct quota_root_settings *root_set,
		       const char **error_r);

static const struct quota_backend *quota_backend_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(quota_backends); i++) {
		if (strcmp(quota_backends[i]->name, name) == 0)
			return quota_backends[i];
	}

	return NULL;
}

static int quota_root_add_rules(struct mail_user *user, const char *root_name,
				struct quota_root_settings *root_set,
				const char **error_r)
{
	const char *rule_name, *rule, *error;
	unsigned int i;

	rule_name = t_strconcat(root_name, "_rule", NULL);
	for (i = 2;; i++) {
		rule = mail_user_plugin_getenv(user, rule_name);
		if (rule == NULL)
			break;

		if (quota_root_add_rule(root_set, rule, &error) < 0) {
			*error_r = t_strdup_printf("Invalid rule %s: %s",
						   rule, error);
			return -1;
		}
		rule_name = t_strdup_printf("%s_rule%d", root_name, i);
	}
	return 0;
}

static int
quota_root_add_warning_rules(struct mail_user *user, const char *root_name,
			     struct quota_root_settings *root_set,
			     const char **error_r)
{
	const char *rule_name, *rule, *error;
	unsigned int i;

	rule_name = t_strconcat(root_name, "_warning", NULL);
	for (i = 2;; i++) {
		rule = mail_user_plugin_getenv(user, rule_name);
		if (rule == NULL)
			break;

		if (quota_root_add_warning_rule(root_set, rule, &error) < 0) {
			*error_r = t_strdup_printf("Invalid warning rule: %s",
						   rule);
			return -1;
		}
		rule_name = t_strdup_printf("%s_warning%d", root_name, i);
	}
	return 0;
}

static int
quota_root_settings_init(struct quota_settings *quota_set, const char *root_def,
			 struct quota_root_settings **set_r,
			 const char **error_r)
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
		*error_r = t_strdup_printf("Unknown quota backend: %s",
					   backend_name);
		return -1;
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
	*set_r = root_set;
	return 0;
}

static int
quota_root_add(struct quota_settings *quota_set, struct mail_user *user,
	       const char *env, const char *root_name, const char **error_r)
{
	struct quota_root_settings *root_set;

	if (quota_root_settings_init(quota_set, env, &root_set, error_r) < 0)
		return -1;
	if (quota_root_add_rules(user, root_name, root_set, error_r) < 0)
		return -1;
	if (quota_root_add_warning_rules(user, root_name, root_set, error_r) < 0)
		return -1;
	if (quota_root_parse_grace(user, root_name, root_set, error_r) < 0)
		return -1;
	return 0;
}

int quota_user_read_settings(struct mail_user *user,
			     struct quota_settings **set_r,
			     const char **error_r)
{
	struct quota_settings *quota_set;
	char root_name[5 + MAX_INT_STRLEN + 1];
	const char *env, *error;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("quota settings", 2048);
	quota_set = p_new(pool, struct quota_settings, 1);
	quota_set->pool = pool;
	quota_set->test_alloc = quota_default_test_alloc;
	quota_set->debug = user->mail_debug;
	quota_set->quota_exceeded_msg =
		mail_user_plugin_getenv(user, "quota_exceeded_message");
	if (quota_set->quota_exceeded_msg == NULL)
		quota_set->quota_exceeded_msg = DEFAULT_QUOTA_EXCEEDED_MSG;

	p_array_init(&quota_set->root_sets, pool, 4);
	if (i_strocpy(root_name, "quota", sizeof(root_name)) < 0)
		i_unreached();
	for (i = 2;; i++) {
		env = mail_user_plugin_getenv(user, root_name);
		if (env == NULL || *env == '\0')
			break;

		if (quota_root_add(quota_set, user, env, root_name,
				   &error) < 0) {
			*error_r = t_strdup_printf("Invalid quota root %s: %s",
						   root_name, error);
			pool_unref(&pool);
			return -1;
		}
		if (i_snprintf(root_name, sizeof(root_name), "quota%d", i) < 0)
			i_unreached();
	}
	if (array_count(&quota_set->root_sets) == 0) {
		pool_unref(&pool);
		return 0;
	}

	quota_set->initialized = TRUE;
	*set_r = quota_set;
	return 1;
}

void quota_settings_deinit(struct quota_settings **_quota_set)
{
	struct quota_settings *quota_set = *_quota_set;

	*_quota_set = NULL;

	pool_unref(&quota_set->pool);
}

static void quota_root_deinit(struct quota_root *root)
{
	pool_t pool = root->pool;

	root->backend.v.deinit(root);
	pool_unref(&pool);
}

static int
quota_root_init(struct quota_root_settings *root_set, struct quota *quota,
		struct quota_root **root_r, const char **error_r)
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
		if (root->backend.v.init(root, root_set->args) < 0) {
			*error_r = "init() failed";
			return -1;
		}
	} else if (root_set->args != NULL) {
		tmp = t_strsplit_spaces(root_set->args, " ");
		for (; *tmp != NULL; tmp++) {
			if (strcmp(*tmp, "noenforcing") == 0)
				root->no_enforcing = TRUE;
			else if (strcmp(*tmp, "ignoreunlimited") == 0)
				root->disable_unlimited_tracking = TRUE;
			else
				break;
		}
		if (*tmp != NULL) {
			*error_r = t_strdup_printf(
				"Unknown parameter for backend %s: %s",
				root->backend.name, *tmp);
			return -1;
		}
	}
	if (root_set->default_rule.bytes_limit == 0 &&
	    root_set->default_rule.count_limit == 0 &&
	    root->disable_unlimited_tracking) {
		quota_root_deinit(root);
		return 0;
	}
	*root_r = root;
	return 1;
}

int quota_init(struct quota_settings *quota_set, struct mail_user *user,
	       struct quota **quota_r, const char **error_r)
{
	struct quota *quota;
	struct quota_root *root;
	struct quota_root_settings *const *root_sets;
	unsigned int i, count;
	const char *error;
	int ret;

	quota = i_new(struct quota, 1);
	quota->user = user;
	quota->set = quota_set;
	i_array_init(&quota->roots, 8);

	root_sets = array_get(&quota_set->root_sets, &count);
	i_array_init(&quota->namespaces, count);
	for (i = 0; i < count; i++) {
		ret = quota_root_init(root_sets[i], quota, &root, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf("Quota root %s: %s",
						   root_sets[i]->name, error);
			quota_deinit(&quota);
			return -1;
		}
		if (ret > 0)
			array_append(&quota->roots, &root, 1);
	}
	*quota_r = quota;
	return 0;
}

void quota_deinit(struct quota **_quota)
{
	struct quota *quota = *_quota;
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++)
		quota_root_deinit(roots[i]);

	/* deinit quota roots before setting quser->quota=NULL */
	*_quota = NULL;

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

	if (percentage <= -100 || percentage >= UINT_MAX) {
		*error_r = "Invalid percentage";
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

static int quota_limit_parse(struct quota_root_settings *root_set,
			     struct quota_rule *rule, const char *unit,
			     uint64_t multiply, int64_t *limit,
			     const char **error_r)
{
	switch (i_toupper(*unit)) {
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
		*error_r = t_strdup_printf("Unknown unit: %s", unit);
		return -1;
	}
	*limit *= multiply;
	return 0;
}

static void
quota_rule_recalculate_relative_rules(struct quota_rule *rule,
				      int64_t bytes_limit, int64_t count_limit)
{
	if (rule->bytes_percent != 0)
		rule->bytes_limit = bytes_limit * rule->bytes_percent / 100;
	if (rule->count_percent != 0)
		rule->count_limit = count_limit * rule->count_percent / 100;
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
	quota_rule_recalculate_relative_rules(&root_set->grace_rule,
					      bytes_limit, 0);
	root_set->last_mail_max_extra_bytes = root_set->grace_rule.bytes_limit;

	if (root_set->set->debug && root_set->set->initialized) {
		i_debug("Quota root %s: Recalculated relative rules with "
			"bytes=%lld count=%lld. Now grace=%llu", root_set->name,
			(long long)bytes_limit, (long long)count_limit,
			(unsigned long long)root_set->last_mail_max_extra_bytes);
	}
}

static int
quota_rule_parse_limits(struct quota_root_settings *root_set,
			struct quota_rule *rule, const char *limits,
			const char *full_rule_def,
			bool relative_rule, const char **error_r)
{
	const char **args, *key, *value, *error;
	char *p;
	uint64_t multiply;
	int64_t *limit;

	args = t_strsplit(limits, ":");
	for (; *args != NULL; args++) {
		multiply = 1;
		limit = NULL;

		key = *args;
		value = strchr(key, '=');
		if (value == NULL)
			value = "";
		else
			key = t_strdup_until(key, value++);

		if (*value == '+') {
			if (!relative_rule) {
				*error_r = "Rule limit cannot have '+'";
				return -1;
			}
			value++;
		} else if (*value != '-' && relative_rule) {
			i_warning("quota root %s rule %s: "
				  "obsolete configuration for rule '%s' "
				  "should be changed to '%s=+%s'",
				  root_set->name, full_rule_def,
				  *args, key, value);
		}

		if (strcmp(key, "storage") == 0) {
			multiply = 1024;
			limit = &rule->bytes_limit;
			*limit = strtoll(value, &p, 10);
		} else if (strcmp(key, "bytes") == 0) {
			limit = &rule->bytes_limit;
			*limit = strtoll(value, &p, 10);
		} else if (strcmp(key, "messages") == 0) {
			limit = &rule->count_limit;
			*limit = strtoll(value, &p, 10);
		} else {
			*error_r = p_strdup_printf(root_set->set->pool,
					"Unknown rule limit name: %s", key);
			return -1;
		}

		if (quota_limit_parse(root_set, rule, p, multiply,
				      limit, &error) < 0) {
			*error_r = p_strdup_printf(root_set->set->pool,
				"Invalid rule limit value '%s': %s",
				*args, error);
			return -1;
		}
	}
	if (!relative_rule) {
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
			rule->mailbox_name = strcasecmp(mailbox_name, "INBOX") == 0 ? "INBOX" :
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
		if (root_set->backend->v.parse_rule == NULL) {
			*error_r = "backend rule not supported";
			ret = -1;
		} else if (!root_set->backend->v.parse_rule(root_set, rule,
							    p + 8, error_r))
			ret = -1;
	} else {
		bool relative_rule = rule != &root_set->default_rule;

		if (quota_rule_parse_limits(root_set, rule, p, rule_def,
					    relative_rule, error_r) < 0)
			ret = -1;
	}

	quota_root_recalculate_relative_rules(root_set,
					      root_set->default_rule.bytes_limit,
					      root_set->default_rule.count_limit);
	if (root_set->set->debug) {
		const char *rule_plus =
			rule == &root_set->default_rule ? "" : "+";

		i_debug("Quota rule: root=%s mailbox=%s "
			"bytes=%s%lld%s messages=%s%lld%s",
			root_set->name, mailbox_name,
			rule->bytes_limit > 0 ? rule_plus : "",
			(long long)rule->bytes_limit,
			rule->bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", rule->bytes_percent),
			rule->count_limit > 0 ? rule_plus : "",
			(long long)rule->count_limit,
			rule->count_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", rule->count_percent));
	}
	return ret;
}

static int
quota_root_parse_grace(struct mail_user *user, const char *root_name,
		       struct quota_root_settings *root_set,
		       const char **error_r)
{
	const char *set_name, *value, *error;
	char *p;

	set_name = t_strconcat(root_name, "_grace", NULL);
	value = mail_user_plugin_getenv(user, set_name);
	if (value == NULL) {
		/* default */
		value = QUOTA_DEFAULT_GRACE;
	}

	root_set->grace_rule.bytes_limit = strtoll(value, &p, 10);

	if (quota_limit_parse(root_set, &root_set->grace_rule, p, 1,
			      &root_set->grace_rule.bytes_limit, &error) < 0) {
		*error_r = p_strdup_printf(root_set->set->pool,
			"Invalid %s value '%s': %s", set_name, value, error);
		return -1;
	}
	quota_rule_recalculate_relative_rules(&root_set->grace_rule,
		root_set->default_rule.bytes_limit, 0);
	root_set->last_mail_max_extra_bytes = root_set->grace_rule.bytes_limit;
	if (root_set->set->debug) {
		i_debug("Quota grace: root=%s bytes=%lld%s",
			root_set->name, (long long)root_set->grace_rule.bytes_limit,
			root_set->grace_rule.bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", root_set->grace_rule.bytes_percent));
	}
	return 0;
}

static int quota_root_get_rule_limits(struct quota_root *root,
				      const char *mailbox_name,
				      uint64_t *bytes_limit_r,
				      uint64_t *count_limit_r)
{
	struct quota_rule *rule;
	int64_t bytes_limit, count_limit;
	bool enabled;

	if (!root->set->force_default_rule) {
		if (root->backend.v.init_limits != NULL) {
			if (root->backend.v.init_limits(root) < 0)
				return -1;
		}
	}

	bytes_limit = root->bytes_limit;
	count_limit = root->count_limit;

	/* if default rule limits are 0, user has unlimited quota.
	   ignore any specific quota rules */
	enabled = bytes_limit != 0 || count_limit != 0;

	(void)mail_namespace_find_unalias(root->quota->user->namespaces,
					  &mailbox_name);
	rule = enabled ? quota_root_rule_find(root->set, mailbox_name) : NULL;
	if (rule != NULL) {
		if (!rule->ignore) {
			bytes_limit += rule->bytes_limit;
			count_limit += rule->count_limit;
		} else {
			bytes_limit = 0;
			count_limit = 0;
		}
	}

	*bytes_limit_r = bytes_limit <= 0 ? 0 : bytes_limit;
	*count_limit_r = count_limit <= 0 ? 0 : count_limit;
	return enabled ? 1 : 0;
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
	if (mailbox_list_get_root_path(ns->list, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				       &path)) {
		namespaces = array_get(&quota->namespaces, &count);
		for (i = 0; i < count; i++) {
			if (mailbox_list_get_root_path(namespaces[i]->list,
				MAILBOX_LIST_PATH_TYPE_MAILBOX, &path2) &&
			    strcmp(path, path2) == 0) {
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
	const char *p, *q;
	int ret;
	bool reverse = FALSE;

	p = strchr(rule_def, ' ');
	if (p == NULL || p[1] == '\0') {
		*error_r = "No command specified";
		return -1;
	}

	if (*rule_def == '+') {
		/* warn when exceeding quota */
		q = rule_def+1;
	} else if (*rule_def == '-') {
		/* warn when going below quota */
		q = rule_def+1;
		reverse = TRUE;
	} else {
		/* default: same as '+' */
		q = rule_def;
	}

	memset(&rule, 0, sizeof(rule));
	ret = quota_rule_parse_limits(root_set, &rule, t_strdup_until(q, p),
				      rule_def, FALSE, error_r);
	if (ret < 0)
		return -1;

	warning = array_append_space(&root_set->warning_rules);
	warning->command = p_strdup(root_set->set->pool, p+1);
	warning->rule = rule;
	warning->reverse = reverse;

	quota_root_recalculate_relative_rules(root_set,
					      root_set->default_rule.bytes_limit,
					      root_set->default_rule.count_limit);
	if (root_set->set->debug) {
		i_debug("Quota warning: bytes=%llu%s "
			"messages=%llu%s reverse=%s command=%s",
			(unsigned long long)warning->rule.bytes_limit,
			warning->rule.bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", warning->rule.bytes_percent),
			(unsigned long long)warning->rule.count_limit,
			warning->rule.count_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", warning->rule.count_percent),
			warning->reverse ? "yes" : "no",
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
	struct mailbox_list *list = ns->list;
	struct mail_storage *storage;

	/* this check works as long as there is only one storage per list */
	if (mailbox_list_get_storage(&list, "", &storage) == 0 &&
	    (storage->class_flags & MAIL_STORAGE_CLASS_FLAG_NOQUOTA) != 0)
		return FALSE;

	if (root->ns_prefix != NULL) {
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
	i_assert(ctx->quota != NULL);

	ctx->box = box;
	ctx->bytes_ceil = (uint64_t)-1;
	ctx->bytes_ceil2 = (uint64_t)-1;
	ctx->count_ceil = (uint64_t)-1;

	if (box->storage->user->dsyncing) {
		/* ignore quota for dsync */
		ctx->limits_set = TRUE;
	}
	return ctx;
}

static int quota_transaction_set_limits(struct quota_transaction_context *ctx)
{
	struct quota_root *const *roots;
	const char *mailbox_name;
	unsigned int i, count;
	uint64_t bytes_limit, count_limit, current, limit, diff;
	bool use_grace;
	int ret;

	ctx->limits_set = TRUE;
	mailbox_name = mailbox_get_vname(ctx->box);
	/* use last_mail_max_extra_bytes only for LDA/LMTP */
	use_grace = (ctx->box->flags & MAILBOX_FLAG_POST_SESSION) != 0;

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
				if (limit <= current) {
					/* over quota */
					ctx->bytes_ceil = 0;
					ctx->bytes_ceil2 = 0;
					diff = current - limit;
					if (ctx->bytes_over < diff)
						ctx->bytes_over = diff;
				} else {
					diff = limit - current;
					if (ctx->bytes_ceil2 > diff)
						ctx->bytes_ceil2 = diff;
					diff += !use_grace ? 0 :
						roots[i]->set->last_mail_max_extra_bytes;
					if (ctx->bytes_ceil > diff)
						ctx->bytes_ceil = diff;
				}
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
				if (limit < current) {
					ctx->count_ceil = 0;
					diff = current - limit;
					if (ctx->count_over < diff)
						ctx->count_over = diff;
				} else {
					diff = limit - current;
					if (ctx->count_ceil > diff)
						ctx->count_ceil = diff;
				}
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
	const char *socket_path, *const *args;
	string_t *str;
	int fd;

	if (root->quota->set->debug)
		i_debug("quota: Executing warning: %s", cmd);

	args = t_strsplit_spaces(cmd, " ");
	socket_path = args[0];
	args++;

	if (*socket_path != '/') {
		socket_path = t_strconcat(root->quota->user->set->base_dir, "/",
					  socket_path, NULL);
	}
	if ((fd = net_connect_unix_with_retries(socket_path, 1000)) < 0) {
		if (errno == EACCES) {
			i_error("quota: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			i_error("quota: net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return;
	}

	str = t_str_new(1024);
	str_append(str, "VERSION\tscript\t3\t0\nnoreply\n");
	for (; *args != NULL; args++) {
		str_append(str, *args);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');

	net_set_nonblock(fd, FALSE);
	if (write_full(fd, str_data(str), str_len(str)) < 0)
		i_error("write(%s) failed: %m", socket_path);
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", socket_path);
}

static bool
quota_warning_match(const struct quota_warning_rule *w,
		    uint64_t bytes_before, uint64_t bytes_current,
		    uint64_t count_before, uint64_t count_current)
{
#define QUOTA_EXCEEDED(before, current, limit) \
	((before) < (uint64_t)(limit) && (current) >= (uint64_t)(limit))
	if (!w->reverse) {
		/* over quota (default) */
		return QUOTA_EXCEEDED(bytes_before, bytes_current, w->rule.bytes_limit) ||
			QUOTA_EXCEEDED(count_before, count_current, w->rule.count_limit);
	} else {
		return QUOTA_EXCEEDED(bytes_current, bytes_before, w->rule.bytes_limit) ||
			QUOTA_EXCEEDED(count_current, count_before, w->rule.count_limit);
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
		if (quota_warning_match(&warnings[i],
					bytes_before, bytes_current,
					count_before, count_current)) {
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
		 ctx->recalculate) T_BEGIN {
		ARRAY(struct quota_root *) warn_roots;

		mailbox_name = mailbox_get_vname(ctx->box);
		(void)mail_namespace_find_unalias(
			ctx->box->storage->user->namespaces, &mailbox_name);

		roots = array_get(&ctx->quota->roots, &count);
		t_array_init(&warn_roots, count);
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
			else if (!ctx->sync_transaction)
				array_append(&warn_roots, &roots[i], 1);
		}
		/* execute quota warnings after all updates. this makes it
		   work correctly regardless of whether backend.get_resource()
		   returns updated values before backend.update() or not.
		   warnings aren't executed when dsync bring the user over,
		   because the user probably already got the warning on the
		   other replica. */
		array_foreach(&warn_roots, roots)
			quota_warnings_execute(ctx, *roots);
	} T_END;

	i_free(ctx);
	return ret;
}

void quota_transaction_rollback(struct quota_transaction_context **_ctx)
{
	struct quota_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx);
}

static bool quota_is_over(struct quota_transaction_context *ctx, uoff_t size)
{
	if ((ctx->count_used < 0 ||
	     (uint64_t)ctx->count_used + 1 <= ctx->count_ceil) &&
	    ((ctx->bytes_used < 0 && size <= ctx->bytes_ceil) ||
	     (uint64_t)ctx->bytes_used + size <= ctx->bytes_ceil))
		return FALSE;
	else
		return TRUE;
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
	/* this is a virtual function mainly for trash plugin and similar,
	   which may automatically delete mails to stay under quota. */
	return ctx->quota->set->test_alloc(ctx, size, too_large_r);
}

static int quota_default_test_alloc(struct quota_transaction_context *ctx,
				    uoff_t size, bool *too_large_r)
{
	struct quota_root *const *roots;
	unsigned int i, count;
	int ret;

	*too_large_r = FALSE;

	if (!quota_is_over(ctx, size))
		return 1;

	/* limit reached. only thing left to do now is to set too_large_r. */
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

	ctx->bytes_ceil = ctx->bytes_ceil2;
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
