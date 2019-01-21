/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "ioloop.h"
#include "net.h"
#include "write-full.h"
#include "eacces-error.h"
#include "wildcard-match.h"
#include "dict.h"
#include "mailbox-list-private.h"
#include "quota-private.h"
#include "quota-fs.h"
#include "llist.h"
#include "program-client.h"
#include "settings-parser.h"

#include <sys/wait.h>

#define DEFAULT_QUOTA_EXCEEDED_MSG \
	"Quota exceeded (mailbox for user is full)"
#define QUOTA_LIMIT_SET_PATH DICT_PATH_PRIVATE"quota/limit/"

/* How many seconds after the userdb lookup do we still want to execute the
   quota_over_script. This applies to quota_over_flag_lazy_check=yes and also
   after unhibernating IMAP connections. */
#define QUOTA_OVER_FLAG_MAX_DELAY_SECS 10

struct quota_root_iter {
	struct quota *quota;
	struct mailbox *box;

	unsigned int i;
};

unsigned int quota_module_id = 0;

extern struct quota_backend quota_backend_count;
extern struct quota_backend quota_backend_dict;
extern struct quota_backend quota_backend_dirsize;
extern struct quota_backend quota_backend_fs;
extern struct quota_backend quota_backend_imapc;
extern struct quota_backend quota_backend_maildir;

static const struct quota_backend *quota_internal_backends[] = {
#ifdef HAVE_FS_QUOTA
	&quota_backend_fs,
#endif
	&quota_backend_count,
	&quota_backend_dict,
	&quota_backend_dirsize,
	&quota_backend_imapc,
	&quota_backend_maildir
};

static ARRAY(const struct quota_backend*) quota_backends;

static void hidden_param_handler(struct quota_root *_root, const char *param_value);
static void ignoreunlim_param_handler(struct quota_root *_root, const char *param_value);
static void noenforcing_param_handler(struct quota_root *_root, const char *param_value);
static void ns_param_handler(struct quota_root *_root, const char *param_value);

struct quota_param_parser quota_param_hidden = {.param_name = "hidden", .param_handler = hidden_param_handler};
struct quota_param_parser quota_param_ignoreunlimited = {.param_name = "ignoreunlimited", .param_handler = ignoreunlim_param_handler};
struct quota_param_parser quota_param_noenforcing = {.param_name = "noenforcing", .param_handler = noenforcing_param_handler};
struct quota_param_parser quota_param_ns = {.param_name = "ns=", .param_handler = ns_param_handler};

static enum quota_alloc_result quota_default_test_alloc(
		struct quota_transaction_context *ctx, uoff_t size,
		const char **error_r);
static void quota_over_flag_check_root(struct quota_root *root);

static const struct quota_backend *quota_backend_find(const char *name)
{
	const struct quota_backend *const *backend;

	array_foreach(&quota_backends, backend) {
		if (strcmp((*backend)->name, name) == 0)
			return *backend;
	}

	return NULL;
}

void quota_backend_register(const struct quota_backend *backend)
{
	i_assert(quota_backend_find(backend->name) == NULL);
	array_append(&quota_backends, &backend, 1);
}

void quota_backend_unregister(const struct quota_backend *backend)
{
	for(unsigned int i = 0; i < array_count(&quota_backends); i++) {
		const struct quota_backend *const *be =
			array_idx(&quota_backends, i);
		if (strcmp((*be)->name, backend->name) == 0) {
			array_delete(&quota_backends, i, 1);
			return;
		}
	}

	i_unreached();
}

void quota_backends_register(void);
void quota_backends_unregister(void);

void quota_backends_register(void)
{
	i_array_init(&quota_backends, 8);
	array_append(&quota_backends, quota_internal_backends,
		     N_ELEMENTS(quota_internal_backends));
}

void quota_backends_unregister(void)
{
	for(size_t i = 0; i < N_ELEMENTS(quota_internal_backends); i++) {
		quota_backend_unregister(quota_internal_backends[i]);
	}

	i_assert(array_count(&quota_backends) == 0);
	array_free(&quota_backends);

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
quota_root_parse_set(struct mail_user *user, const char *root_name,
		     struct quota_root_settings *root_set,
		     const char **error_r)
{
	const char *name, *value;

	name = t_strconcat(root_name, "_set", NULL);
	value = mail_user_plugin_getenv(user, name);
	if (value == NULL)
		return 0;

	if (!str_begins(value, "dict:")) {
		*error_r = t_strdup_printf("%s supports only dict backend", name);
		return -1;
	}
	root_set->limit_set = p_strdup(root_set->set->pool, value+5);
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
	const char *set_name, *value;

	if (quota_root_settings_init(quota_set, env, &root_set, error_r) < 0)
		return -1;
	root_set->set_name = p_strdup(quota_set->pool, root_name);
	if (quota_root_add_rules(user, root_name, root_set, error_r) < 0)
		return -1;
	if (quota_root_add_warning_rules(user, root_name, root_set, error_r) < 0)
		return -1;
	if (quota_root_parse_set(user, root_name, root_set, error_r) < 0)
		return -1;

	set_name = t_strconcat(root_name, "_grace", NULL);
	value = mail_user_plugin_getenv(user, set_name);
	if (quota_root_parse_grace(root_set, value, error_r) < 0) {
		*error_r = t_strdup_printf("Invalid %s value '%s': %s",
					   set_name, value, *error_r);
		return -1;
	}
	return 0;
}

const char *quota_alloc_result_errstr(enum quota_alloc_result res,
		struct quota_transaction_context *qt)
{
	switch (res) {
	case QUOTA_ALLOC_RESULT_OK:
		return "OK";
	case QUOTA_ALLOC_RESULT_BACKGROUND_CALC:
		return "Blocked by an ongoing background quota calculation";
	case QUOTA_ALLOC_RESULT_TEMPFAIL:
		return "Internal quota calculation error";
	case QUOTA_ALLOC_RESULT_OVER_MAXSIZE:
		return "Mail size is larger than the maximum size allowed by "
		       "server configuration";
	case QUOTA_ALLOC_RESULT_OVER_QUOTA_LIMIT:
	case QUOTA_ALLOC_RESULT_OVER_QUOTA:
		return qt->quota->set->quota_exceeded_msg;
	}
	i_unreached();
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
	quota_set->vsizes = mail_user_plugin_getenv_bool(user, "quota_vsizes");

	const char *max_size = mail_user_plugin_getenv(user,
						       "quota_max_mail_size");
	if (max_size != NULL) {
		const char *error = NULL;
		if (settings_get_size(max_size, &quota_set->max_mail_size,
					&error) < 0) {
			*error_r = t_strdup_printf("quota_max_mail_size: %s",
					error);
			return -1;
		}
	}

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
	if (quota_set->max_mail_size == 0 &&
	    array_count(&quota_set->root_sets) == 0) {
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

	if (root->limit_set_dict != NULL)
		dict_deinit(&root->limit_set_dict);
	root->backend.v.deinit(root);
	pool_unref(&pool);
}

int quota_root_default_init(struct quota_root *root, const char *args,
			    const char **error_r)
{
	const struct quota_param_parser default_params[] = {
		quota_param_hidden,
		quota_param_ignoreunlimited,
		quota_param_noenforcing,
		quota_param_ns,
		{.param_name = NULL}
	};
	return quota_parse_parameters(root, &args, error_r, default_params, TRUE);
}

static int
quota_root_init(struct quota_root_settings *root_set, struct quota *quota,
		struct quota_root **root_r, const char **error_r)
{
	struct quota_root *root;

	root = root_set->backend->v.alloc();
	root->pool = pool_alloconly_create("quota root", 512);
	root->set = root_set;
	root->quota = quota;
	root->backend = *root_set->backend;
	root->bytes_limit = root_set->default_rule.bytes_limit;
	root->count_limit = root_set->default_rule.count_limit;

	array_create(&root->quota_module_contexts, root->pool,
		     sizeof(void *), 10);

	if (root->backend.v.init != NULL) {
		if (root->backend.v.init(root, root_set->args, error_r) < 0) {
			*error_r = t_strdup_printf("%s quota init failed: %s",
					root->backend.name, *error_r);
			return -1;
		}
	} else {
		if (quota_root_default_init(root, root_set->args, error_r) < 0)
			return -1;
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

static int quota_root_get_rule_limits(struct quota_root *root,
				      const char *mailbox_name,
				      uint64_t *bytes_limit_r,
				      uint64_t *count_limit_r,
				      bool *ignored_r,
				      const char **error_r)
{
	struct quota_rule *rule;
	int64_t bytes_limit, count_limit;
	int ret;

	*ignored_r = FALSE;

	if (!root->set->force_default_rule) {
		if (root->backend.v.init_limits != NULL) {
			const char *error;
			if (root->backend.v.init_limits(root, &error) < 0) {
				*error_r = t_strdup_printf(
					"Initializing limits failed for quota backend: %s",
					error);
				return -1;
			}
		}
	}

	bytes_limit = root->bytes_limit;
	count_limit = root->count_limit;

	/* if default rule limits are 0, user has unlimited quota.
	   ignore any specific quota rules */
	if (bytes_limit != 0 || count_limit != 0) {
		(void)mail_namespace_find_unalias(root->quota->user->namespaces,
						  &mailbox_name);
		rule = quota_root_rule_find(root->set, mailbox_name);
		ret = 1;
	} else {
		rule = NULL;
		ret = 0;
	}

	if (rule != NULL) {
		if (!rule->ignore) {
			bytes_limit += rule->bytes_limit;
			count_limit += rule->count_limit;
		} else {
			bytes_limit = 0;
			count_limit = 0;
			*ignored_r = TRUE;
		}
	}

	*bytes_limit_r = bytes_limit <= 0 ? 0 : bytes_limit;
	*count_limit_r = count_limit <= 0 ? 0 : count_limit;
	return ret;
}

static bool
quota_is_duplicate_namespace(struct quota *quota, struct mail_namespace *ns)
{
	struct mail_namespace *const *namespaces;
	unsigned int i, count;
	const char *path, *path2;

	if (!mailbox_list_get_root_path(ns->list,
					MAILBOX_LIST_PATH_TYPE_MAILBOX, &path))
		path = NULL;

	namespaces = array_get(&quota->namespaces, &count);
	for (i = 0; i < count; i++) {
		/* count namespace aliases only once. don't rely only on
		   alias_for != NULL, because the alias might have been
		   explicitly added as the wanted quota namespace. */
		if (ns->alias_for == namespaces[i] ||
		    namespaces[i]->alias_for == ns)
			continue;

		if (path != NULL &&
		    mailbox_list_get_root_path(namespaces[i]->list,
				MAILBOX_LIST_PATH_TYPE_MAILBOX, &path2) &&
		    strcmp(path, path2) == 0) {
			/* duplicate path */
			if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0)
				return TRUE;

			/* this is inbox=yes namespace, but the earlier one
			   that had the same location was inbox=no. we need to
			   include the INBOX also in quota calculations, so we
			   can't just ignore this namespace. but since we've
			   already called backend's namespace_added(), we can't
			   just remove it either. so just mark the old one as
			   unwanted namespace.

			   an alternative would be to do a bit larger change so
			   namespaces wouldn't be added until
			   mail_namespaces_created() hook is called */
			i_assert(quota->unwanted_ns == NULL);
			quota->unwanted_ns = namespaces[i];
			return FALSE;
		}
	}
	return FALSE;
}

void quota_add_user_namespace(struct quota *quota, struct mail_namespace *ns)
{
	struct quota_root *const *roots;
	struct quota_backend **backends;
	unsigned int i, j, count;

	/* first check if there already exists a namespace with the exact same
	   path. we don't want to count them twice. */
	if (quota_is_duplicate_namespace(quota, ns))
		return;

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

struct quota_root_iter *
quota_root_iter_init_user(struct mail_user *user)
{
	struct quota_root_iter *iter;

	iter = i_new(struct quota_root_iter, 1);
	iter->quota = quota_get_mail_user_quota(user);
	return iter;
}

struct quota_root_iter *
quota_root_iter_init(struct mailbox *box)
{
	struct quota_root_iter *iter;
	struct mail_user *user;

	user = box->list->ns->owner != NULL ?
		box->list->ns->owner : box->list->ns->user;
	iter = quota_root_iter_init_user(user);
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
	if (root->quota->unwanted_ns == ns)
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
quota_root_is_visible(struct quota_root *root, struct mailbox *box)
{
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

	if (iter->quota == NULL)
		return NULL;

	roots = array_get(&iter->quota->roots, &count);
	if (iter->i >= count)
		return NULL;

	for (; iter->i < count; iter->i++) {
		if (iter->box != NULL &&
		    !quota_root_is_visible(roots[iter->i], iter->box))
			continue;

		root = roots[iter->i];
		break;
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
	if (quota == NULL)
		return NULL;
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
	/* if we haven't checked the quota_over_flag yet, do it now */
	quota_over_flag_check_root(root);

	return root->backend.v.get_resources(root);
}

bool quota_root_is_hidden(struct quota_root *root)
{
	return root->hidden;
}

enum quota_get_result
quota_get_resource(struct quota_root *root, const char *mailbox_name,
		   const char *name, uint64_t *value_r, uint64_t *limit_r,
		   const char **error_r)
{
	const char *error;
	uint64_t bytes_limit, count_limit;
	bool ignored, kilobytes = FALSE;
	enum quota_get_result ret;

	*value_r = *limit_r = 0;

	if (strcmp(name, QUOTA_NAME_STORAGE_KILOBYTES) == 0) {
		name = QUOTA_NAME_STORAGE_BYTES;
		kilobytes = TRUE;
	}

	/* Get the value first. This call may also update quota limits if
	   they're defined externally. */
	ret = root->backend.v.get_resource(root, name, value_r, &error);
	if (ret == QUOTA_GET_RESULT_UNLIMITED)
		i_panic("Quota backend %s returned QUOTA_GET_RESULT_UNLIMITED "
			"while getting resource %s from box %s",
			root->backend.name, name, mailbox_name);
	else if (ret != QUOTA_GET_RESULT_LIMITED) {
		*error_r = t_strdup_printf(
			"quota-%s: %s", root->set->backend->name, error);
		return ret;
	}

	if (quota_root_get_rule_limits(root, mailbox_name,
				       &bytes_limit, &count_limit,
				       &ignored, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to get quota root rule limits for mailbox %s: %s",
			mailbox_name, error);
		return QUOTA_GET_RESULT_INTERNAL_ERROR;
	}

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*limit_r = bytes_limit;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*limit_r = count_limit;
	else
		*limit_r = 0;

	if (kilobytes) {
		*value_r = (*value_r + 1023) / 1024;
		*limit_r = (*limit_r + 1023) / 1024;
	}
	return *limit_r == 0 ? QUOTA_GET_RESULT_UNLIMITED : QUOTA_GET_RESULT_LIMITED;
}

int quota_set_resource(struct quota_root *root, const char *name,
		       uint64_t value, const char **client_error_r)
{
	struct dict_transaction_context *trans;
	const char *key, *error;

	if (root->set->limit_set == NULL) {
		*client_error_r = MAIL_ERRSTR_NO_PERMISSION;
		return -1;
	}
	if (strcasecmp(name, QUOTA_NAME_STORAGE_KILOBYTES) == 0)
		key = "storage";
	else if (strcasecmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		key = "bytes";
	else if (strcasecmp(name, QUOTA_NAME_MESSAGES) == 0)
		key = "messages";
	else {
		*client_error_r = t_strdup_printf(
			"Unsupported resource name: %s", name);
		return -1;
	}

	if (root->limit_set_dict == NULL) {
		struct dict_settings set;

		i_zero(&set);
		set.username = root->quota->user->username;
		set.base_dir = root->quota->user->set->base_dir;
		if (mail_user_get_home(root->quota->user, &set.home_dir) <= 0)
			set.home_dir = NULL;
		if (dict_init(root->set->limit_set, &set,
			      &root->limit_set_dict, &error) < 0) {
			i_error("dict_init() failed: %s", error);
			*client_error_r = "Internal quota limit update error";
			return -1;
		}
	}

	trans = dict_transaction_begin(root->limit_set_dict);
	key = t_strdup_printf(QUOTA_LIMIT_SET_PATH"%s", key);
	dict_set(trans, key, dec2str(value));
	if (dict_transaction_commit(&trans, &error) < 0) {
		i_error("dict_transaction_commit() failed: %s", error);
		*client_error_r = "Internal quota limit update error";
		return -1;
	}
	return 0;
}

struct quota_transaction_context *quota_transaction_begin(struct mailbox *box)
{
	struct quota_transaction_context *ctx;
	struct quota_root *const *rootp;
	const struct quota_rule *rule;
	const char *mailbox_name;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = box->list->ns->owner != NULL ?
		quota_get_mail_user_quota(box->list->ns->owner) :
		quota_get_mail_user_quota(box->list->ns->user);
	i_assert(ctx->quota != NULL);

	ctx->box = box;
	ctx->bytes_ceil = (uint64_t)-1;
	ctx->bytes_ceil2 = (uint64_t)-1;
	ctx->count_ceil = (uint64_t)-1;

	mailbox_name = mailbox_get_vname(box);
	(void)mail_namespace_find_unalias(box->storage->user->namespaces,
					  &mailbox_name);

	ctx->auto_updating = TRUE;
	array_foreach(&ctx->quota->roots, rootp) {
		if (!quota_root_is_visible(*rootp, ctx->box))
			continue;

		rule = quota_root_rule_find((*rootp)->set, mailbox_name);
		if (rule != NULL && rule->ignore) {
			/* This mailbox isn't included in quota. This means
			   it's also not included in quota_warnings, so make
			   sure it's fully ignored. */
			continue;
		}

		/* If there are reverse quota_warnings, we'll need to track
		   how many bytes were expunged even with auto_updating roots.
		   (An alternative could be to get the current quota usage
		   before and after the expunges, but that's more complicated
		   and probably isn't any better.) */
		if (!(*rootp)->auto_updating ||
		    (*rootp)->set->have_reverse_warnings)
			ctx->auto_updating = FALSE;
	}

	if (box->storage->user->dsyncing) {
		/* ignore quota for dsync */
		ctx->limits_set = TRUE;
	}
	return ctx;
}

int quota_transaction_set_limits(struct quota_transaction_context *ctx,
				 enum quota_get_result *error_result_r,
				 const char **error_r)
{
	struct quota_root *const *roots;
	const char *mailbox_name, *error;
	unsigned int i, count;
	uint64_t bytes_limit, count_limit, current, limit, diff;
	bool use_grace, ignored;
	enum quota_get_result ret;

	if (ctx->limits_set)
		return 0;
	ctx->limits_set = TRUE;
	mailbox_name = mailbox_get_vname(ctx->box);
	/* use quota_grace only for LDA/LMTP */
	use_grace = (ctx->box->flags & MAILBOX_FLAG_POST_SESSION) != 0;
	ctx->no_quota_updates = TRUE;

	/* find the lowest quota limits from all roots and use them */
	roots = array_get(&ctx->quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (!quota_root_is_visible(roots[i], ctx->box) ||
		    (roots[i]->no_enforcing && ctx->auto_updating))
			continue;
		else if (roots[i]->no_enforcing) {
			bytes_limit = (uint64_t)-1;
			count_limit = (uint64_t)-1;
			ignored = FALSE;
		} else if (quota_root_get_rule_limits(roots[i], mailbox_name,
						      &bytes_limit, &count_limit,
						      &ignored, &error) < 0) {
			ctx->failed = TRUE;
			*error_result_r = QUOTA_GET_RESULT_INTERNAL_ERROR;
			*error_r = t_strdup_printf(
				"Failed to get quota root rule limits for %s: %s",
				mailbox_name, error);
			return -1;
		}
		if (!ignored)
			ctx->no_quota_updates = FALSE;

		if (bytes_limit > 0) {
			ret = quota_get_resource(roots[i], mailbox_name,
						 QUOTA_NAME_STORAGE_BYTES,
						 &current, &limit, &error);
			if (roots[i]->no_enforcing) {
				ctx->bytes_ceil = (uint64_t)-1;
				ctx->bytes_ceil2 = (uint64_t)-1;
			} else if (ret == QUOTA_GET_RESULT_LIMITED) {
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
			} else if (ret <= QUOTA_GET_RESULT_INTERNAL_ERROR) {
				ctx->failed = TRUE;
				*error_result_r = ret;
				*error_r = t_strdup_printf(
					"Failed to get quota resource "
					QUOTA_NAME_STORAGE_BYTES" for %s: %s",
					mailbox_name, error);
				return -1;
			}
		}

		if (count_limit > 0) {
			ret = quota_get_resource(roots[i], mailbox_name,
						 QUOTA_NAME_MESSAGES,
						 &current, &limit, &error);
			if (roots[i]->no_enforcing) {
				ctx->count_ceil = (uint64_t)-1;
			} else if (ret == QUOTA_GET_RESULT_LIMITED) {
				if (limit <= current) {
					/* over quota */
					ctx->count_ceil = 0;
					diff = current - limit;
					if (ctx->count_over < diff)
						ctx->count_over = diff;
				} else {
					diff = limit - current;
					if (ctx->count_ceil > diff)
						ctx->count_ceil = diff;
				}
			} else if (ret <= QUOTA_GET_RESULT_INTERNAL_ERROR) {
				ctx->failed = TRUE;
				*error_result_r = ret;
				*error_r = t_strdup_printf(
					"Failed to get quota resource "
					QUOTA_NAME_MESSAGES" for %s: %s",
					mailbox_name, error);
				return -1;
			}
		}
	}
	return 0;
}

static void quota_warning_execute(struct quota_root *root, const char *cmd,
				  const char *last_arg, const char *reason)
{
	const char *socket_path, *const *args, *error, *scheme, *ptr;

	struct program_client_settings set = {
		.client_connect_timeout_msecs = 1000,
	};
	struct program_client *pc;

	restrict_access_init(&set.restrict_set);

	if (root->quota->set->debug)
		i_debug("quota: Executing warning: %s (because %s)", cmd, reason);

	args = t_strsplit_spaces(cmd, " ");
	if (last_arg != NULL) {
		unsigned int count = str_array_length(args);
		const char **new_args = t_new(const char *, count + 2);

		memcpy(new_args, args, sizeof(const char *) * count);
		new_args[count] = last_arg;
		args = new_args;
	}
	socket_path = args[0];

	if ((ptr = strchr(socket_path, ':')) != NULL) {
		scheme = t_strcut(socket_path, ':');
		socket_path = ptr+1;
	} else {
		scheme = "unix";
	}

	if (*socket_path != '/' &&
	    strcmp(scheme, "unix") == 0)
		socket_path =
			t_strconcat(root->quota->user->set->base_dir,
				    "/", socket_path, NULL);

	socket_path = t_strdup_printf("%s:%s", scheme, socket_path);

	args++;

	if (program_client_create(socket_path, args, &set, TRUE,
				  &pc, &error) < 0) {
		i_error("program_client_create(%s) failed: %s", socket_path,
			error);
		return;
	}

	(void)program_client_run(pc);

	program_client_destroy(&pc);
}

static void quota_warnings_execute(struct quota_transaction_context *ctx,
				   struct quota_root *root)
{
	struct quota_warning_rule *warnings;
	unsigned int i, count;
	uint64_t bytes_current, bytes_before, bytes_limit;
	uint64_t count_current, count_before, count_limit;
	const char *reason, *error;

	warnings = array_get_modifiable(&root->set->warning_rules, &count);
	if (count == 0)
		return;

	if (quota_get_resource(root, "", QUOTA_NAME_STORAGE_BYTES,
			       &bytes_current, &bytes_limit, &error) == QUOTA_GET_RESULT_INTERNAL_ERROR) {
		i_error("Failed to get quota resource "QUOTA_NAME_STORAGE_BYTES
			": %s", error);
		return;
	}
	if (quota_get_resource(root, "", QUOTA_NAME_MESSAGES,
			       &count_current, &count_limit, &error) == QUOTA_GET_RESULT_INTERNAL_ERROR) {
		i_error("Failed to get quota resource "QUOTA_NAME_MESSAGES
			": %s", error);
		return;
	}

	if (ctx->bytes_used > 0 && bytes_current < (uint64_t)ctx->bytes_used)
		bytes_before = 0;
	else
		bytes_before = bytes_current - ctx->bytes_used;

	if (ctx->count_used > 0 && count_current < (uint64_t)ctx->count_used)
		count_before = 0;
	else
		count_before = count_current - ctx->count_used;
	for (i = 0; i < count; i++) {
		if (quota_warning_match(&warnings[i],
					bytes_before, bytes_current,
					count_before, count_current,
					&reason)) {
			quota_warning_execute(root, warnings[i].command,
					      NULL, reason);
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
		 ctx->recalculate != QUOTA_RECALCULATE_DONT) T_BEGIN {
		ARRAY(struct quota_root *) warn_roots;

		mailbox_name = mailbox_get_vname(ctx->box);
		(void)mail_namespace_find_unalias(
			ctx->box->storage->user->namespaces, &mailbox_name);

		roots = array_get(&ctx->quota->roots, &count);
		t_array_init(&warn_roots, count);
		for (i = 0; i < count; i++) {
			if (!quota_root_is_visible(roots[i], ctx->box))
				continue;

			rule = quota_root_rule_find(roots[i]->set,
						    mailbox_name);
			if (rule != NULL && rule->ignore) {
				/* mailbox not included in quota */
				continue;
			}

			const char *error;
			if (roots[i]->backend.v.update(roots[i], ctx, &error) < 0) {
				i_error("Failed to update quota for %s: %s",
					mailbox_name, error);
				ret = -1;
			}
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

static bool quota_over_flag_init_root(struct quota_root *root,
				      const char **quota_over_script_r,
				      const char **quota_over_flag_r,
				      bool *status_r)
{
	const char *name, *flag_mask;

	*quota_over_flag_r = NULL;
	*status_r = FALSE;

	name = t_strconcat(root->set->set_name, "_over_script", NULL);
	*quota_over_script_r = mail_user_plugin_getenv(root->quota->user, name);
	if (*quota_over_script_r == NULL) {
		if (root->quota->set->debug) {
			i_debug("quota: quota_over_flag check: "
				"%s unset - skipping", name);
		}
		return FALSE;
	}

	/* e.g.: quota_over_flag_value=TRUE or quota_over_flag_value=*  */
	name = t_strconcat(root->set->set_name, "_over_flag_value", NULL);
	flag_mask = mail_user_plugin_getenv(root->quota->user, name);
	if (flag_mask == NULL) {
		if (root->quota->set->debug) {
			i_debug("quota: quota_over_flag check: "
				"%s unset - skipping", name);
		}
		return FALSE;
	}

	/* compare quota_over_flag's value (that comes from userdb) to
	   quota_over_flag_value and save the result. */
	name = t_strconcat(root->set->set_name, "_over_flag", NULL);
	*quota_over_flag_r = mail_user_plugin_getenv(root->quota->user, name);
	*status_r = *quota_over_flag_r != NULL &&
		wildcard_match_icase(*quota_over_flag_r, flag_mask);
	return TRUE;
}

static void quota_over_flag_check_root(struct quota_root *root)
{
	const char *quota_over_script, *quota_over_flag, *error;
	const char *const *resources;
	unsigned int i;
	uint64_t value, limit;
	bool cur_overquota = FALSE;
	bool quota_over_status;
	enum quota_get_result ret;

	if (root->quota_over_flag_checked)
		return;
	if (root->quota->user->session_create_time +
	    QUOTA_OVER_FLAG_MAX_DELAY_SECS < ioloop_time) {
		/* userdb's quota_over_flag lookup is too old. */
		if (root->quota->set->debug) {
			i_debug("quota: quota_over_flag check: "
				"Flag lookup time is too old - skipping");
		}
		return;
	}
	if (root->quota->user->session_restored) {
		/* we don't know whether the quota_over_script was executed
		   before hibernation. just assume that it was, so we don't
		   unnecessarily call it too often. */
		if (root->quota->set->debug) {
			i_debug("quota: quota_over_flag check: "
				"Session was already hibernated - skipping");
		}
		return;
	}
	root->quota_over_flag_checked = TRUE;
	if (!quota_over_flag_init_root(root, &quota_over_script,
				       &quota_over_flag, &quota_over_status))
		return;

	resources = quota_root_get_resources(root);
	for (i = 0; resources[i] != NULL; i++) {
		ret = quota_get_resource(root, "", resources[i], &value,
					 &limit, &error);
		if (ret == QUOTA_GET_RESULT_INTERNAL_ERROR) {
			/* can't reliably verify this */
			i_error("quota: Quota %s lookup failed - can't verify quota_over_flag: %s",
				resources[i], error);
			return;
		}
		if (root->quota->set->debug) {
			i_debug("quota: quota_over_flag check: %s ret=%d value=%"PRIu64" limit=%"PRIu64,
				resources[i], ret, value, limit);
		}
		if (ret == QUOTA_GET_RESULT_LIMITED && value >= limit)
			cur_overquota = TRUE;
	}
	if (root->quota->set->debug) {
		i_debug("quota: quota_over_flag=%d(%s) vs currently overquota=%d",
			quota_over_status ? 1 : 0,
			quota_over_flag == NULL ? "(null)" : quota_over_flag,
			cur_overquota ? 1 : 0);
	}
	if (cur_overquota != quota_over_status) {
		quota_warning_execute(root, quota_over_script, quota_over_flag,
				      "quota_over_flag mismatch");
	}
}

void quota_over_flag_check_startup(struct quota *quota)
{
	struct quota_root *const *roots;
	unsigned int i, count;
	const char *name;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		name = t_strconcat(roots[i]->set->set_name, "_over_flag_lazy_check", NULL);
		if (!mail_user_plugin_getenv_bool(roots[i]->quota->user, name))
			quota_over_flag_check_root(roots[i]);
	}
}

void quota_transaction_rollback(struct quota_transaction_context **_ctx)
{
	struct quota_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx);
}

static int quota_get_mail_size(struct quota_transaction_context *ctx,
			       struct mail *mail, uoff_t *size_r)
{
	if (ctx->quota->set->vsizes)
		return mail_get_virtual_size(mail, size_r);
	else
		return mail_get_physical_size(mail, size_r);
}

enum quota_alloc_result quota_try_alloc(struct quota_transaction_context *ctx,
					struct mail *mail, const char **error_r)
{
	uoff_t size;
	const char *error;
	enum quota_get_result error_res;

	if (quota_transaction_set_limits(ctx, &error_res, error_r) < 0) {
		if (error_res == QUOTA_GET_RESULT_BACKGROUND_CALC)
			return QUOTA_ALLOC_RESULT_BACKGROUND_CALC;
		return QUOTA_ALLOC_RESULT_TEMPFAIL;
	}

	if (ctx->no_quota_updates)
		return QUOTA_ALLOC_RESULT_OK;

	if (quota_get_mail_size(ctx, mail, &size) < 0) {
		enum mail_error err;
		error = mailbox_get_last_internal_error(mail->box, &err);

		if (err == MAIL_ERROR_EXPUNGED) {
			/* mail being copied was already expunged. it'll fail,
			   so just return success for the quota allocated. */
			return QUOTA_ALLOC_RESULT_OK;
		}
		*error_r = t_strdup_printf(
			"Failed to get mail size (box=%s, uid=%u): %s",
			mail->box->vname, mail->uid, error);
		return QUOTA_ALLOC_RESULT_TEMPFAIL;
	}

	enum quota_alloc_result ret = quota_test_alloc(ctx, size, error_r);
	if (ret != QUOTA_ALLOC_RESULT_OK)
		return ret;
	/* with quota_try_alloc() we want to keep track of how many bytes
	   we've been adding/removing, so disable auto_updating=TRUE
	   optimization. this of course doesn't work perfectly if
	   quota_alloc() or quota_free_bytes() was already used within the same
	   transaction, but that doesn't normally happen. */
	ctx->auto_updating = FALSE;
	quota_alloc(ctx, mail);
	return QUOTA_ALLOC_RESULT_OK;
}

enum quota_alloc_result quota_test_alloc(struct quota_transaction_context *ctx,
					 uoff_t size, const char **error_r)
{
	if (ctx->failed) {
		*error_r = "Quota transaction has failed earlier";
		return QUOTA_ALLOC_RESULT_TEMPFAIL;
	}

	enum quota_get_result error_res;
	if (quota_transaction_set_limits(ctx, &error_res, error_r) < 0) {
		if (error_res == QUOTA_GET_RESULT_BACKGROUND_CALC)
			return QUOTA_ALLOC_RESULT_BACKGROUND_CALC;
		return QUOTA_ALLOC_RESULT_TEMPFAIL;
	}

	uoff_t max_size = ctx->quota->set->max_mail_size;
	if (max_size > 0 && size > max_size) {
		*error_r = t_strdup_printf(
			"Requested allocation size %"PRIuUOFF_T" exceeds max "
			"mail size %"PRIuUOFF_T, size, max_size);
		return QUOTA_ALLOC_RESULT_OVER_MAXSIZE;
	}

	if (ctx->no_quota_updates)
		return QUOTA_ALLOC_RESULT_OK;
	/* this is a virtual function mainly for trash plugin and similar,
	   which may automatically delete mails to stay under quota. */
	return ctx->quota->set->test_alloc(ctx, size, error_r);
}

static enum quota_alloc_result quota_default_test_alloc(
			struct quota_transaction_context *ctx, uoff_t size,
			const char **error_r)
{
	struct quota_root *const *roots;
	unsigned int i, count;
	bool ignore;
	int ret;

	if (!quota_transaction_is_over(ctx, size))
		return QUOTA_ALLOC_RESULT_OK;

	/* limit reached. */
	roots = array_get(&ctx->quota->roots, &count);
	for (i = 0; i < count; i++) {
		uint64_t bytes_limit, count_limit;

		if (!quota_root_is_visible(roots[i], ctx->box) ||
		    roots[i]->no_enforcing)
			continue;

		const char *error;
		ret = quota_root_get_rule_limits(roots[i],
						 mailbox_get_vname(ctx->box),
						 &bytes_limit, &count_limit,
						 &ignore, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Failed to get quota root rule limits: %s",
				error);
			return QUOTA_ALLOC_RESULT_TEMPFAIL;
		}

		/* if size is bigger than any limit, then
		   it is bigger than the lowest limit */
		if (bytes_limit > 0 && size > bytes_limit) {
			*error_r = t_strdup_printf(
				"Allocating %"PRIuUOFF_T" bytes would exceed quota limit",
				size);
			return QUOTA_ALLOC_RESULT_OVER_QUOTA_LIMIT;
		}
	}
	*error_r = t_strdup_printf(
		"Allocating %"PRIuUOFF_T" bytes would exceed quota", size);
	return QUOTA_ALLOC_RESULT_OVER_QUOTA;
}

void quota_alloc(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	if (!ctx->auto_updating) {
		if (quota_get_mail_size(ctx, mail, &size) == 0)
			ctx->bytes_used += size;
	}

	ctx->bytes_ceil = ctx->bytes_ceil2;
	ctx->count_used++;
}

void quota_free_bytes(struct quota_transaction_context *ctx,
		      uoff_t physical_size)
{
	ctx->bytes_used -= physical_size;
	ctx->count_used--;
}

void quota_recalculate(struct quota_transaction_context *ctx,
		       enum quota_recalculate recalculate)
{
	ctx->recalculate = recalculate;
}

static void hidden_param_handler(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	_root->hidden = TRUE;
}

static void ignoreunlim_param_handler(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	_root->disable_unlimited_tracking = TRUE;
}

static void noenforcing_param_handler(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	_root->no_enforcing = TRUE;
}

static void ns_param_handler(struct quota_root *_root, const char *param_value)
{
	_root->ns_prefix = p_strdup(_root->pool, param_value);
}

int quota_parse_parameters(struct quota_root *root, const char **args, const char **error_r,
			   const struct quota_param_parser *valid_params, bool fail_on_unknown)
{
	const char *tmp_param_name, *tmp_param_val;
	size_t tmp_param_len;

	while (*args != NULL && (*args)[0] != '\0') {
		for (; valid_params->param_name != NULL; ++valid_params) {
			tmp_param_name = valid_params->param_name;
			tmp_param_len = strlen(valid_params->param_name);
			i_assert(*args != NULL);
			if (strncmp(*args, tmp_param_name, tmp_param_len) == 0) {
				tmp_param_val = NULL;
				*args += tmp_param_len;
				if (tmp_param_name[tmp_param_len - 1] == '=') {
					const char *next_colon = strchr(*args, ':');
					tmp_param_val = (next_colon == NULL)?
						t_strdup(*args):
						t_strdup_until(*args, next_colon);
					*args = (next_colon == NULL) ? NULL : next_colon + 1;
				}
				else if ((*args)[0] == '\0' ||
					 (*args)[0] == ':') {
					*args = ((*args)[0] == ':') ? *args + 1 : NULL;
					/* in case parameter is a boolean second parameter
					 * string parameter value will be ignored by param_handler
					 * we just need some non-NULL value
					 * to indicate that argument is to be processed */
					tmp_param_val = "";
				}
				if (tmp_param_val != NULL) {
					valid_params->param_handler(root, tmp_param_val);
					break;
				}
			}
		}
		if (valid_params->param_name == NULL) {
			if (fail_on_unknown) {
				*error_r = t_strdup_printf(
					"Unknown parameter for backend %s: %s",
					root->backend.name, *args);
				return -1;
			}
			else {
				break;
			}
		}
	}
	return 0;
}
