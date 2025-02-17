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
#include "settings.h"
#include "mailbox-list-private.h"
#include "quota-private.h"
#include "quota-fs.h"
#include "llist.h"
#include "program-client.h"
#include "str-parse.h"

#include <sys/wait.h>

/* How many seconds after the userdb lookup do we still want to execute the
   quota_status_script. This applies to quota_over_status_lazy_check=yes and
   also after unhibernating IMAP connections. */
#define QUOTA_OVER_STATUS_MAX_DELAY_SECS 10

struct quota_root_iter {
	struct quota *quota;
	struct mailbox *box;

	unsigned int i;
};

unsigned int quota_module_id = 0;

extern struct quota_backend quota_backend_count;
extern struct quota_backend quota_backend_fs;
extern struct quota_backend quota_backend_imapc;
extern struct quota_backend quota_backend_maildir;

static const struct quota_backend *quota_internal_backends[] = {
#ifdef HAVE_FS_QUOTA
	&quota_backend_fs,
#endif
	&quota_backend_count,
	&quota_backend_imapc,
	&quota_backend_maildir
};

static ARRAY(const struct quota_backend*) quota_backends;

static enum quota_alloc_result quota_default_test_alloc(
		struct quota_transaction_context *ctx, uoff_t size,
		const char **error_r);
static void quota_over_status_check_root(struct quota_root *root);
static struct quota_root *
quota_root_find(struct quota *quota, const char *name);

const struct quota_backend *quota_backend_find(const char *name)
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
	array_push_back(&quota_backends, &backend);
}

void quota_backend_unregister(const struct quota_backend *backend)
{
	for(unsigned int i = 0; i < array_count(&quota_backends); i++) {
		const struct quota_backend *be =
			array_idx_elem(&quota_backends, i);
		if (strcmp(be->name, backend->name) == 0) {
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
		return qt->set->quota_exceeded_message;
	case QUOTA_ALLOC_RESULT_OVER_QUOTA_MAILBOX_LIMIT:
		return "Too many messages in the mailbox";
	}
	i_unreached();
}

static void quota_root_deinit(struct quota_root *root)
{
	pool_t pool = root->pool;

	event_unref(&root->backend.event);
	settings_free(root->set);
	root->backend.v.deinit(root);
	pool_unref(&pool);
}

static int
quota_root_settings_get(struct quota_root *root, struct event *set_event,
			const struct quota_root_settings **set_r,
			const char **error_r)
{
	if (set_event == NULL)
		set_event = root->backend.event;
	return settings_get_filter(set_event, "quota", root->set_filter_name,
				   &quota_root_setting_parser_info, 0,
				   set_r, error_r);
}

static int quota_root_has_under_warnings(struct quota_root *root)
{
	const struct quota_root_settings *set;
	const char *warn_name, *error;

	if (!array_is_created(&root->set->quota_warnings))
		return 0;
	array_foreach_elem(&root->set->quota_warnings, warn_name) {
		if (settings_get_filter(root->backend.event,
					"quota_warning", warn_name,
					&quota_root_setting_parser_info, 0,
					&set, &error) < 0) {
			e_error(root->backend.event, "%s", error);
			return -1;
		}
		bool under = strcmp(set->quota_warning_threshold,
				    QUOTA_WARNING_THRESHOLD_UNDER) == 0;
		settings_free(set);
		if (under)
			return 1;
	}
	return 0;
}

static int
quota_root_init(struct quota *quota, struct event *set_event, const char *root_name,
		struct quota_root **root_r, const char **error_r)
{
	const struct quota_root_settings *root_set;
	struct quota_root *root;

	if (settings_get_filter(set_event, "quota", root_name,
				&quota_root_setting_parser_info, 0,
				&root_set, error_r) < 0)
		return -1;

	/* If a quota root exists already with the same name, assume it's the
	   same as this one. Don't add duplicates. */
	root = quota_root_find(quota, root_set->quota_name);
	if (root != NULL) {
		settings_free(root_set);
		*root_r = root;
		return 1;
	}

	root = root_set->backend->v.alloc();
	root->pool = pool_alloconly_create("quota root", 512);
	root->quota = quota;
	root->backend = *root_set->backend;
	root->set_filter_name = p_strdup(root->pool, root_name);
	p_array_init(&root->namespaces, root->pool, 4);
	settings_free(root_set);

	array_create(&root->quota_module_contexts, root->pool,
		     sizeof(void *), 10);

	const char *backend_filter =
		t_strdup_printf("quota_%s", root->backend.name);
	root->backend.event = event_create(quota->event);
	event_set_append_log_prefix(root->backend.event,
		t_strdup_printf("quota-%s: ", root->backend.name));
	event_add_str(root->backend.event, "quota", root_name);
	settings_event_add_filter_name(root->backend.event, backend_filter);
	settings_event_add_list_filter_name(root->backend.event, "quota",
					    root_name);
	event_drop_parent_log_prefixes(root->backend.event, 1);

	/* Lookup settings again with quota_backend filter name */
	set_event = event_create(set_event);
	settings_event_add_filter_name(set_event, backend_filter);
	if (settings_get_filter(set_event, "quota", root_name,
				&quota_root_setting_parser_info, 0,
				&root->set, error_r) < 0) {
		event_unref(&set_event);
		return -1;
	}
	event_unref(&set_event);

	root->bytes_limit = root->set->quota_storage_size > INT64_MAX ? 0 :
		root->set->quota_storage_size;
	root->count_limit = root->set->quota_message_count;

	if (root->backend.v.init(root, error_r) < 0) {
		*error_r = t_strdup_printf("%s quota init failed: %s",
					   root->backend.name, *error_r);

		event_unref(&root->backend.event);
		settings_free(root->set);
		pool_unref(&root->pool);
		return -1;
	}
	if (root->set->quota_storage_size == 0 &&
	    root->set->quota_message_count == 0 &&
	    root->set->quota_ignore_unlimited) {
		quota_root_deinit(root);
		return 0;
	}

	/* If a quota backend needs virtual size instead of physical size,
	   use this for all backends. This is not ideal, but works. */
	if (root->set->backend->use_vsize)
		quota->vsizes = TRUE;

	array_push_back(&quota->all_roots, &root);
	*root_r = root;
	return 1;
}

int quota_init(struct mail_user *user, struct quota **quota_r,
	       const char **error_r)
{
	struct quota *quota;
	struct quota_root *root;
	const struct quota_settings *set;
	const char *root_name;
	const char *error;
	int ret;

	if (settings_get(user->event, &quota_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	quota = i_new(struct quota, 1);
	quota->event = event_create(user->event);
	event_set_append_log_prefix(quota->event, "quota: ");
	quota->user = user;
	quota->test_alloc = quota_default_test_alloc;
	i_array_init(&quota->global_private_roots, 8);
	i_array_init(&quota->all_roots, 8);

	if (array_is_created(&set->quota_roots)) {
		array_foreach_elem(&set->quota_roots, root_name) {
			ret = quota_root_init(quota, quota->event, root_name,
					      &root, &error);
			if (ret < 0) {
				*error_r = t_strdup_printf("Quota root %s: %s",
							   root_name, error);
				settings_free(set);
				quota_deinit(&quota);
				return -1;
			}
			if (ret > 0)
				array_push_back(&quota->global_private_roots, &root);
		}
	}
	settings_free(set);
	*quota_r = quota;
	return 0;
}

void quota_deinit(struct quota **_quota)
{
	struct quota *quota = *_quota;
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->all_roots, &count);
	for (i = 0; i < count; i++)
		quota_root_deinit(roots[i]);

	/* deinit quota roots before setting quser->quota=NULL */
	*_quota = NULL;

	array_free(&quota->global_private_roots);
	array_free(&quota->all_roots);
	event_unref(&quota->event);
	i_free(quota);
}

static int
quota_root_get_rule_limits(struct quota_root *root, struct event *set_event,
			   uint64_t *bytes_limit_r, uint64_t *count_limit_r,
			   bool *ignored_r, const char **error_r)
{
	const struct quota_root_settings *set;

	if (quota_root_settings_get(root, set_event, &set, error_r) < 0)
		return -1;

	if (set->quota_ignore) {
		*bytes_limit_r = 0;
		*count_limit_r = 0;
		*ignored_r = TRUE;
	} else {
		uint64_t bytes_limit, count_limit;

		if (set->quota_storage_size != 0)
			bytes_limit = set->quota_storage_size;
		else {
			/* unlimited quota in configuration - see if the quota
			   backend has a limit set. */
			bytes_limit = root->bytes_limit;
		}
		if (bytes_limit == 0 || bytes_limit > INT64_MAX)
			*bytes_limit_r = 0;
		else {
			if (set->quota_storage_percentage == 100)
				*bytes_limit_r = bytes_limit;
			else {
				*bytes_limit_r = bytes_limit / 100.0 *
					set->quota_storage_percentage;
			}
			if (*bytes_limit_r <= INT64_MAX &&
			    set->quota_storage_extra <= INT64_MAX - *bytes_limit_r)
				*bytes_limit_r += set->quota_storage_extra;
			else
				*bytes_limit_r = 0;
		}

		if (set->quota_message_count != 0)
			count_limit = set->quota_message_count;
		else
			count_limit = root->count_limit;

		if (count_limit == 0 || set->quota_message_percentage == 100)
			*count_limit_r = count_limit;
		else {
			*count_limit_r = count_limit / 100.0 *
				set->quota_message_percentage;
		}
		*ignored_r = FALSE;
	}

	settings_free(set);
	return 0;
}

static bool
quota_is_duplicate_namespace(struct quota_root *root, struct mail_namespace *ns)
{
	struct mail_namespace *const *namespaces;
	unsigned int i, count;
	const char *path, *path2;

	if (!mailbox_list_get_root_path(ns->list,
					MAILBOX_LIST_PATH_TYPE_MAILBOX, &path))
		path = NULL;

	namespaces = array_get(&root->namespaces, &count);
	for (i = 0; i < count; i++) {
		/* Count namespace aliases only once. Don't rely only on
		   non-empty alias_for, because the alias might have been
		   explicitly added as the wanted quota namespace. We can't
		   use ns->alias_for pointer comparisons directly, because they
		   are set later. */
		if (strcmp(ns->set->alias_for, namespaces[i]->set->name) == 0 ||
		    strcmp(namespaces[i]->set->alias_for, ns->set->name) == 0)
			return TRUE;

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
			   entirely remove it either.

			   an alternative would be to do a bit larger change so
			   namespaces wouldn't be added until
			   mail_namespaces_created() hook is called */
			array_delete(&root->namespaces, i, 1);
			return FALSE;
		}
	}
	return FALSE;
}

void quota_add_user_namespace(struct quota *quota, const char *root_name,
			      struct mail_namespace *ns)
{
	struct quota_root *root;
	const char *error;

	int ret = quota_root_init(quota, ns->list->event, root_name,
				  &root, &error);
	if (ret == 0)
		return;
	if (ret < 0) {
		e_error(ns->list->event, "Quota root %s: %s", root_name, error);
		return;
	}
	/* first check if there already exists a namespace with the
	   exact same path. we don't want to count them twice. */
	if (quota_is_duplicate_namespace(root, ns))
		return;

	array_push_back(&root->namespaces, &ns);

	if (root->backend.v.namespace_added != NULL)
		root->backend.v.namespace_added(root, ns);
}

void quota_remove_user_namespace(struct mail_namespace *ns)
{
	struct quota *quota;
	struct quota_root *root;
	unsigned int i;

	quota = ns->owner != NULL ?
		quota_get_mail_user_quota(ns->owner) :
		quota_get_mail_user_quota(ns->user);
	if (quota == NULL) {
		/* no quota for this namespace */
		return;
	}

	array_foreach_elem(&quota->all_roots, root) {
		if (array_lsearch_ptr_idx(&root->namespaces, ns, &i))
			array_delete(&root->namespaces, i, 1);
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

static bool
quota_root_is_visible(struct quota_root *root, struct mailbox *box)
{
	if (root->quota->user == box->storage->user) {
		if (array_lsearch_ptr(&root->namespaces, box->list->ns) == NULL)
			return FALSE;
	} else {
		/* This is a shared mailbox. The quota user is the actual owner
		   of the mailbox, but the mailbox is accessed via another
		   user. Currently each shared namespace gets its own owner
		   mail_user, even when the same user has multiple shared
		   namespaces. So we don't need to verify whether the namespace
		   matches - there is always only one. */
		i_assert(box->list->ns->type == MAIL_NAMESPACE_TYPE_SHARED);
	}
	if (array_count(&root->quota->all_roots) == 1) {
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

	roots = array_get(&iter->quota->all_roots, &count);
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

static struct quota_root *
quota_root_find(struct quota *quota, const char *name)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->all_roots, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(roots[i]->set->quota_name, name) == 0)
			return roots[i];
	}
	return NULL;
}

struct quota_root *quota_root_lookup(struct mail_user *user, const char *name)
{
	struct quota *quota;

	quota = quota_get_mail_user_quota(user);
	if (quota == NULL)
		return NULL;
	return quota_root_find(quota, name);
}

const char *quota_root_get_name(struct quota_root *root)
{
	return root->set->quota_name;
}

const char *const *quota_root_get_resources(struct quota_root *root)
{
	/* if we haven't checked the quota_over_status yet, do it now */
	quota_over_status_check_root(root);

	return root->backend.v.get_resources(root);
}

bool quota_root_is_hidden(struct quota_root *root)
{
	return root->set->quota_hidden;
}

enum quota_get_result
quota_get_resource(struct quota_root *root, struct mailbox *box,
		   const char *name, uint64_t *value_r, uint64_t *limit_r,
		   const char **error_r)
{
	const char *error;
	struct event *set_event;
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
			root->backend.name, name, box == NULL ? "" :
			mailbox_get_vname(box));
	else if (ret != QUOTA_GET_RESULT_LIMITED) {
		*error_r = t_strdup_printf(
			"quota-%s: %s", root->set->backend->name, error);
		return ret;
	}

	if (box != NULL)
		set_event = box->event;
	else if (array_is_empty(&root->namespaces))
		set_event = NULL;
	else {
		struct mail_namespace *ns =
			array_idx_elem(&root->namespaces, 0);
		set_event = ns->list->event;
	}

	if (quota_root_get_rule_limits(root, set_event,
				       &bytes_limit, &count_limit,
				       &ignored, error_r) < 0)
		return -1;

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

struct quota_transaction_context *quota_transaction_begin(struct mailbox *box)
{
	struct quota_transaction_context *ctx;
	struct quota_root *const *rootp;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = box->list->ns->owner != NULL ?
		quota_get_mail_user_quota(box->list->ns->owner) :
		quota_get_mail_user_quota(box->list->ns->user);
	i_assert(ctx->quota != NULL);

	ctx->box = box;
	ctx->bytes_ceil = (uint64_t)-1;
	ctx->bytes_ceil2 = (uint64_t)-1;
	ctx->count_ceil = (uint64_t)-1;

	ctx->auto_updating = TRUE;
	array_foreach(&ctx->quota->all_roots, rootp) {
		if (!quota_root_is_visible(*rootp, ctx->box))
			continue;

		const struct quota_root_settings *set = NULL;
		const char *error;
		if (quota_root_settings_get(*rootp, box->event,
					    &set, &error) < 0) {
			e_error(ctx->box->event, "%s", error);
			ctx->failed = TRUE;
		} else if (set->quota_ignore) {
			/* This mailbox isn't included in quota. This means
			   it's also not included in quota_warnings, so make
			   sure it's fully ignored. */
			settings_free(set);
			continue;
		} else {
			settings_free(set);
		}

		/* If there are reverse quota_warnings, we'll need to track
		   how many bytes were expunged even with auto_updating roots.
		   (An alternative could be to get the current quota usage
		   before and after the expunges, but that's more complicated
		   and probably isn't any better.) */
		if (!(*rootp)->auto_updating ||
		    quota_root_has_under_warnings(*rootp) != 0)
			ctx->auto_updating = FALSE;
	}

	if (box->storage->user->dsyncing) {
		/* ignore quota for dsync */
		ctx->limits_set = TRUE;
		ctx->set = quota_get_unlimited_set();
	}
	return ctx;
}

int quota_transaction_set_limits(struct quota_transaction_context *ctx,
				 enum quota_get_result *error_result_r,
				 const char **error_r)
{
	struct quota_root *const *roots;
	const char *error;
	unsigned int i, count;
	uint64_t bytes_limit, count_limit, current, limit, diff;
	bool use_grace, ignored;
	enum quota_get_result ret;

	if (ctx->limits_set)
		return 0;
	ctx->limits_set = TRUE;
	/* use quota_grace only for LDA/LMTP */
	use_grace = (ctx->box->flags & MAILBOX_FLAG_POST_SESSION) != 0;
	ctx->no_quota_updates = TRUE;

	i_assert(ctx->set == NULL);
	if (settings_get(ctx->box->event, &quota_setting_parser_info,
			 0, &ctx->set, error_r) < 0) {
		ctx->failed = TRUE;
		*error_result_r = QUOTA_GET_RESULT_INTERNAL_ERROR;
		return -1;
	}

	/* find the lowest quota limits from all roots and use them */
	roots = array_get(&ctx->quota->all_roots, &count);
	for (i = 0; i < count; i++) {
		/* make sure variables get initialized */
		bytes_limit = count_limit = 0;
		if (!quota_root_is_visible(roots[i], ctx->box))
			continue;
		else if (!roots[i]->set->quota_enforce) {
			ignored = FALSE;
		} else if (quota_root_get_rule_limits(roots[i], ctx->box->event,
						      &bytes_limit, &count_limit,
						      &ignored, error_r) < 0) {
			ctx->failed = TRUE;
			*error_result_r = QUOTA_GET_RESULT_INTERNAL_ERROR;
			return -1;
		}
		if (!ignored)
			ctx->no_quota_updates = FALSE;

		if (bytes_limit > 0) {
			ret = quota_get_resource(roots[i], ctx->box,
						 QUOTA_NAME_STORAGE_BYTES,
						 &current, &limit, &error);
			if (ret == QUOTA_GET_RESULT_LIMITED) {
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
						roots[i]->set->quota_storage_grace;
					if (ctx->bytes_ceil > diff)
						ctx->bytes_ceil = diff;
				}
			} else if (ret <= QUOTA_GET_RESULT_INTERNAL_ERROR) {
				ctx->failed = TRUE;
				*error_result_r = ret;
				*error_r = t_strdup_printf(
					"Failed to get quota resource "
					QUOTA_NAME_STORAGE_BYTES" for %s: %s",
					mailbox_get_vname(ctx->box), error);
				return -1;
			}
		}

		if (count_limit > 0) {
			ret = quota_get_resource(roots[i], ctx->box,
						 QUOTA_NAME_MESSAGES,
						 &current, &limit, &error);
			if (ret == QUOTA_GET_RESULT_LIMITED) {
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
					mailbox_get_vname(ctx->box), error);
				return -1;
			}
		}
	}

	if (ctx->set->quota_mailbox_message_count != SET_UINT_UNLIMITED) {
		struct mailbox_status status;
		mailbox_get_open_status(ctx->box, STATUS_MESSAGES, &status);
		if (status.messages <= ctx->set->quota_mailbox_message_count) {
			diff = ctx->set->quota_mailbox_message_count - status.messages;
			if (ctx->count_ceil > diff)
				ctx->count_ceil = diff;
		} else {
			/* over quota */
			ctx->count_ceil = 0;
			diff = status.messages - ctx->set->quota_mailbox_message_count;
			if (ctx->count_over < diff)
				ctx->count_over = diff;
		}
	}
	return 0;
}

static void
quota_warning_execute(struct event *event, const char *last_arg,
		      const char *reason)
{
	const char *const append_args[] = { last_arg, NULL };
	struct program_client_parameters params = {
		.client_connect_timeout_msecs = 1000,
		.no_reply = TRUE,
		.append_args = append_args,
	};
	struct program_client *pc;
	const char *error;

	e_debug(event, "Executing because: %s", reason);

	if (program_client_create_auto(event, &params, &pc, &error) <= 0) {
		e_error(event, "%s", error);
		return;
	}
	(void)program_client_run(pc);
	program_client_destroy(&pc);
}

static void quota_warnings_execute(struct quota_transaction_context *ctx,
				   struct quota_root *root)
{
	const struct quota_root_settings *set;
	uint64_t bytes_current, bytes_before, bytes_limit;
	uint64_t count_current, count_before, count_limit;
	const char *warn_name, *reason, *error;

	if (array_is_empty(&root->set->quota_warnings))
		return;

	if (quota_get_resource(root, NULL, QUOTA_NAME_STORAGE_BYTES,
			       &bytes_current, &bytes_limit, &error) == QUOTA_GET_RESULT_INTERNAL_ERROR) {
		e_error(root->backend.event,
			"Failed to get quota resource "QUOTA_NAME_STORAGE_BYTES
			": %s", error);
		return;
	}
	if (quota_get_resource(root, NULL, QUOTA_NAME_MESSAGES,
			       &count_current, &count_limit, &error) == QUOTA_GET_RESULT_INTERNAL_ERROR) {
		e_error(root->backend.event,
			"Failed to get quota resource "QUOTA_NAME_MESSAGES
			": %s", error);
		return;
	}

	if (ctx->bytes_used > 0 && bytes_current < (uint64_t)ctx->bytes_used)
		bytes_before = 0;
	else
		bytes_before = (int64_t)bytes_current - ctx->bytes_used;

	if (ctx->count_used > 0 && count_current < (uint64_t)ctx->count_used)
		count_before = 0;
	else
		count_before = (int64_t)count_current - ctx->count_used;

	array_foreach_elem(&root->set->quota_warnings, warn_name) {
		if (settings_get_filter(root->backend.event,
					"quota_warning", warn_name,
					&quota_root_setting_parser_info, 0,
					&set, &error) < 0) {
			e_error(root->backend.event, "%s", error);
			return;
		}
		if (quota_warning_match(set, bytes_before, bytes_current,
					count_before, count_current,
					&reason)) {
			struct event *event = event_create(root->backend.event);
			event_set_ptr(event, SETTINGS_EVENT_FILTER_NAME,
				      p_strdup_printf(event_get_pool(event),
						      "quota_warning/%s",
						      warn_name));
			event_set_append_log_prefix(event, t_strdup_printf(
				"quota_warning %s: ", warn_name));
			quota_warning_execute(event, NULL, reason);
			event_unref(&event);
			settings_free(set);
			break;
		}
		settings_free(set);
	}
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
	else if (ctx->bytes_used != 0 || ctx->count_used != 0 ||
		 ctx->recalculate != QUOTA_RECALCULATE_DONT) T_BEGIN {
		ARRAY(struct quota_root *) warn_roots;

		roots = array_get(&ctx->quota->all_roots, &count);
		t_array_init(&warn_roots, count);
		for (i = 0; i < count; i++) {
			if (!quota_root_is_visible(roots[i], ctx->box))
				continue;

			const struct quota_root_settings *set = NULL;
			const char *error;
			if (quota_root_settings_get(roots[i], ctx->box->event,
						    &set, &error) < 0) {
				e_error(ctx->box->event, "%s", error);
				ret = -1;
			} else if (set->quota_ignore) {
				/* mailbox not included in quota */
				settings_free(set);
				continue;
			}
			settings_free(set);

			if (roots[i]->backend.v.update(roots[i], ctx, &error) < 0) {
				e_error(ctx->box->event,
					"Failed to update quota: %s", error);
				ret = -1;
			}
			else if (!ctx->sync_transaction)
				array_push_back(&warn_roots, &roots[i]);
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

	settings_free(ctx->set);
	i_free(ctx);
	return ret;
}

static bool
quota_over_status_init_root(struct quota_root *root, bool *status_r)
{
	*status_r = FALSE;

	/* e.g.: quota_over_status_mask=TRUE or quota_over_status_mask=*  */
	if (root->set->quota_over_status_mask[0] == '\0') {
		e_debug(root->backend.event, "quota_over_status check: "
			"quota_over_mask unset - skipping");
		return FALSE;
	}

	/* compare quota_over_status_current's value (that comes from userdb) to
	   quota_over_status_mask and save the result. */
	*status_r = root->set->quota_over_status_current[0] != '\0' &&
		wildcard_match_icase(root->set->quota_over_status_current,
				     root->set->quota_over_status_mask);
	return TRUE;
}

static void quota_over_status_check_root(struct quota_root *root)
{
	const char *error, *const *resources;
	unsigned int i;
	uint64_t value, limit;
	bool cur_overquota = FALSE;
	bool quota_over_status;
	enum quota_get_result ret;

	if (root->quota_over_status_checked)
		return;
	if (root->quota->user->session_create_time +
	    QUOTA_OVER_STATUS_MAX_DELAY_SECS < ioloop_time) {
		/* userdb's quota_over_status lookup is too old. */
		e_debug(root->backend.event, "quota_over_status check: "
			"Status lookup time is too old - skipping");
		return;
	}
	if (root->quota->user->session_restored) {
		/* we don't know whether the quota_over_script was executed
		   before hibernation. just assume that it was, so we don't
		   unnecessarily call it too often. */
		e_debug(root->backend.event, "quota_over_status check: "
			"Session was already hibernated - skipping");
		return;
	}
	root->quota_over_status_checked = TRUE;
	if (!quota_over_status_init_root(root, &quota_over_status))
		return;

	resources = quota_root_get_resources(root);
	for (i = 0; resources[i] != NULL; i++) {
		ret = quota_get_resource(root, NULL, resources[i], &value,
					 &limit, &error);
		if (ret == QUOTA_GET_RESULT_INTERNAL_ERROR) {
			/* can't reliably verify this */
			e_error(root->backend.event, "Quota %s lookup failed -"
				"can't verify quota_over_status: %s",
				resources[i], error);
			return;
		}
		e_debug(root->backend.event, "quota_over_status check: %s ret=%d"
			"value=%"PRIu64" limit=%"PRIu64, resources[i], ret,
			value, limit);
		if (ret == QUOTA_GET_RESULT_LIMITED && value >= limit)
			cur_overquota = TRUE;
	}
	e_debug(root->backend.event, "quota_over_status=%d(%s) vs currently overquota=%d",
		quota_over_status ? 1 : 0,
		root->set->quota_over_status_current,
		cur_overquota ? 1 : 0);
	if (cur_overquota != quota_over_status) {
		struct event *event = event_create(root->backend.event);
		settings_event_add_filter_name(event, "quota_over_status");
		event_set_append_log_prefix(event, "quota_over_status: ");
		quota_warning_execute(event,
				      root->set->quota_over_status_current,
				      "quota_over_status mismatch");
		event_unref(&event);
	}
}

void quota_over_status_check_startup(struct quota *quota)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->all_roots, &count);
	for (i = 0; i < count; i++) {
		if (!roots[i]->set->quota_over_status_lazy_check)
			quota_over_status_check_root(roots[i]);
	}
}

void quota_transaction_rollback(struct quota_transaction_context **_ctx)
{
	struct quota_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	settings_free(ctx->set);
	i_free(ctx);
}

static int quota_get_mail_size(struct quota_transaction_context *ctx,
			       struct mail *mail, uoff_t *size_r)
{
	if (ctx->quota->vsizes)
		return mail_get_virtual_size(mail, size_r);
	else
		return mail_get_physical_size(mail, size_r);
}

static void quota_alloc_with_size(struct quota_transaction_context *ctx,
				  uoff_t size)
{
	ctx->bytes_used += size;
	ctx->bytes_ceil = ctx->bytes_ceil2;
	ctx->count_used++;
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
		error = mail_get_last_internal_error(mail, &err);

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
	quota_alloc_with_size(ctx, size);
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

	uoff_t max_size = ctx->set->quota_mail_size;
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
	return ctx->quota->test_alloc(ctx, size, error_r);
}

static enum quota_alloc_result quota_default_test_alloc(
			struct quota_transaction_context *ctx, uoff_t size,
			const char **error_r)
{
	struct quota_root *const *roots;
	unsigned int i, count;
	bool ignore;

	if (!quota_transaction_is_over(ctx, size))
		return QUOTA_ALLOC_RESULT_OK;

	if (ctx->set->quota_mailbox_message_count != SET_UINT_UNLIMITED) {
		struct mailbox_status status;
		mailbox_get_open_status(ctx->box, STATUS_MESSAGES, &status);
		unsigned int new_count = status.messages + ctx->count_used;
		if (new_count >= ctx->set->quota_mailbox_message_count)
			return QUOTA_ALLOC_RESULT_OVER_QUOTA_MAILBOX_LIMIT;
	}

	/* limit reached. */
	roots = array_get(&ctx->quota->all_roots, &count);
	for (i = 0; i < count; i++) {
		uint64_t bytes_limit, count_limit;

		if (!quota_root_is_visible(roots[i], ctx->box) ||
		    !roots[i]->set->quota_enforce)
			continue;

		if (quota_root_get_rule_limits(roots[i], ctx->box->event,
					       &bytes_limit, &count_limit,
					       &ignore, error_r) < 0) {
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
	uoff_t size = 0;

	if (!ctx->auto_updating) {
		(void)quota_get_mail_size(ctx, mail, &size);
	}

	quota_alloc_with_size(ctx, size);
}

void quota_free_bytes(struct quota_transaction_context *ctx,
		      uoff_t physical_size)
{
	i_assert(physical_size <= INT64_MAX);
	ctx->bytes_used -= (int64_t)physical_size;
	ctx->count_used--;
}

void quota_recalculate(struct quota_transaction_context *ctx,
		       enum quota_recalculate recalculate)
{
	ctx->recalculate = recalculate;
}
