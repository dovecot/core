/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "imap-arg.h"
#include "imapc-storage.h"
#include "mailbox-list-private.h"
#include "quota-private.h"

struct imapc_quota_refresh_root {
	const char *name;
	unsigned int order;

	uint64_t bytes_cur, count_cur;
	uint64_t bytes_limit, count_limit;
};

struct imapc_quota_refresh {
	pool_t pool;
	const char *box_name;
	ARRAY(struct imapc_quota_refresh_root) roots;
};

struct imapc_quota_root {
	struct quota_root root;
	const char *box_name, *root_name;

	struct mail_namespace *imapc_ns;
	struct imapc_storage_client *client;
	bool initialized;

	uint64_t bytes_last, count_last;

	struct timeval last_refresh;
	struct imapc_quota_refresh refresh;
};

extern struct quota_backend quota_backend_imapc;

static struct quota_root *imapc_quota_alloc(void)
{
	struct imapc_quota_root *root;

	root = i_new(struct imapc_quota_root, 1);
	return &root->root;
}

static void handle_box_param(struct quota_root *_root, const char *param_value)
{
	((struct imapc_quota_root *)_root)->box_name = p_strdup(_root->pool, param_value);
}

static void handle_root_param(struct quota_root *_root, const char *param_value)
{
	((struct imapc_quota_root *)_root)->root_name = p_strdup(_root->pool, param_value);
}

static int imapc_quota_init(struct quota_root *_root, const char *args,
			    const char **error_r)
{
	struct imapc_quota_root *root = (struct imapc_quota_root *)_root;
	const struct quota_param_parser imapc_params[] = {
		{.param_name = "box=", .param_handler = handle_box_param},
		{.param_name = "root=", .param_handler = handle_root_param},
		quota_param_ns,
		{.param_name = NULL}
	};

	_root->auto_updating = TRUE;

	if (quota_parse_parameters(_root, &args, error_r, imapc_params, TRUE) < 0)
		return -1;

	if (root->box_name == NULL && root->root_name == NULL)
		root->box_name = "INBOX";
	/* we'll never try to enforce the quota - it's just a lot of
	   unnecessary remote GETQUOTA calls. */
	_root->no_enforcing = TRUE;
	return 0;
}

static void imapc_quota_deinit(struct quota_root *_root)
{
	i_free(_root);
}

static void
imapc_quota_root_namespace_added(struct quota_root *_root,
				 struct mail_namespace *ns)
{
	struct imapc_quota_root *root = (struct imapc_quota_root *)_root;

	if (root->imapc_ns == NULL)
		root->imapc_ns = ns;
}

static struct imapc_quota_refresh *
imapc_quota_root_refresh_find(struct imapc_storage_client *client)
{
	struct imapc_storage *storage = client->_storage;
	struct quota *quota;
	struct quota_root *const *rootp;

	i_assert(storage != NULL);
	quota = quota_get_mail_user_quota(storage->storage.user);
	i_assert(quota != NULL);

	/* find the quota root that is being refreshed */
	array_foreach(&quota->roots, rootp) {
		if ((*rootp)->backend.name == quota_backend_imapc.name) {
			struct imapc_quota_root *root =
				(struct imapc_quota_root *)*rootp;

			if (root->refresh.pool != NULL)
				return &root->refresh;
		}
	}
	return NULL;
}

static struct imapc_quota_refresh_root *
imapc_quota_refresh_root_get(struct imapc_quota_refresh *refresh,
			     const char *root_name)
{
	struct imapc_quota_refresh_root *refresh_root;

	array_foreach_modifiable(&refresh->roots, refresh_root) {
		if (strcmp(refresh_root->name, root_name) == 0)
			return refresh_root;
	}

	refresh_root = array_append_space(&refresh->roots);
	refresh_root->order = UINT_MAX;
	refresh_root->name = p_strdup(refresh->pool, root_name);
	refresh_root->bytes_limit = (uint64_t)-1;
	refresh_root->count_limit = (uint64_t)-1;
	return refresh_root;
}

static void imapc_untagged_quotaroot(const struct imapc_untagged_reply *reply,
				     struct imapc_storage_client *client)
{
	struct imapc_quota_refresh *refresh;
	struct imapc_quota_refresh_root *refresh_root;
	const char *mailbox_name, *root_name;
	unsigned int i;

	if (!imap_arg_get_astring(&reply->args[0], &mailbox_name))
		return;

	if ((refresh = imapc_quota_root_refresh_find(client)) == NULL ||
	    refresh->box_name == NULL ||
	    strcmp(refresh->box_name, mailbox_name) != 0) {
		/* unsolicited QUOTAROOT reply - ignore */
		return;
	}
	if (array_count(&refresh->roots) > 0) {
		/* duplicate QUOTAROOT reply - ignore */
		return;
	}

	i = 1;
	while (imap_arg_get_astring(&reply->args[i], &root_name)) {
		refresh_root = imapc_quota_refresh_root_get(refresh, root_name);
		refresh_root->order = i;
		i++;
	}
}

static void imapc_untagged_quota(const struct imapc_untagged_reply *reply,
				 struct imapc_storage_client *client)
{
	const struct imap_arg *list;
	struct imapc_quota_refresh *refresh;
	struct imapc_quota_refresh_root *refresh_root;
	const char *root_name, *resource, *value_str, *limit_str;
	uint64_t value, limit;
	unsigned int i;

	if (!imap_arg_get_astring(&reply->args[0], &root_name) ||
	    !imap_arg_get_list(&reply->args[1], &list))
		return;

	if ((refresh = imapc_quota_root_refresh_find(client)) == NULL) {
		/* unsolicited QUOTA reply - ignore */
		return;
	}
	refresh_root = imapc_quota_refresh_root_get(refresh, root_name);

	for (i = 0; list[i].type != IMAP_ARG_EOL; i += 3) {
		if (!imap_arg_get_atom(&list[i], &resource) ||
		    !imap_arg_get_atom(&list[i+1], &value_str) ||
		    !imap_arg_get_atom(&list[i+2], &limit_str) ||
		    /* RFC2087 uses 32bit number, but be ready for future */
		    str_to_uint64(value_str, &value) < 0 ||
		    str_to_uint64(limit_str, &limit) < 0)
			return;

		if (strcasecmp(resource, QUOTA_NAME_STORAGE_KILOBYTES) == 0) {
			refresh_root->bytes_cur = value * 1024;
			refresh_root->bytes_limit = limit * 1024;
		} else if (strcasecmp(resource, QUOTA_NAME_MESSAGES) == 0) {
			refresh_root->count_cur = value;
			refresh_root->count_limit = limit;
		}
	}
}

static bool imapc_quota_client_init(struct imapc_quota_root *root)
{
	struct mailbox_list *list;
	struct mail_storage *storage;

	if (root->initialized)
		return root->client != NULL;
	root->initialized = TRUE;

	list = root->imapc_ns->list;
	if (mailbox_list_get_storage(&list, "", &storage) == 0 &&
	    strcmp(storage->name, IMAPC_STORAGE_NAME) != 0) {
		/* non-imapc namespace, skip */
		if ((storage->class_flags &
		     MAIL_STORAGE_CLASS_FLAG_NOQUOTA) == 0) {
			i_warning("quota: Namespace '%s' is not imapc, "
				  "skipping for imapc quota",
				  root->imapc_ns->prefix);
		}
		return FALSE;
	}
	root->client = ((struct imapc_storage *)storage)->client;

	imapc_storage_client_register_untagged(root->client, "QUOTAROOT",
					       imapc_untagged_quotaroot);
	imapc_storage_client_register_untagged(root->client, "QUOTA",
					       imapc_untagged_quota);
	return TRUE;
}

static void imapc_quota_refresh_init(struct imapc_quota_refresh *refresh)
{
	i_assert(refresh->pool == NULL);

	refresh->pool = pool_alloconly_create("imapc quota refresh", 256);
	p_array_init(&refresh->roots, refresh->pool, 4);
}

static void
imapc_quota_refresh_update(struct quota *quota,
			   struct imapc_quota_refresh *refresh)
{
	struct quota_root *const *rootp;
	const struct imapc_quota_refresh_root *refresh_root;

	if (array_count(&refresh->roots) == 0) {
		i_error("quota: imapc didn't return any QUOTA results");
		return;
	}
	/* use the first quota root for everything */
	refresh_root = array_first(&refresh->roots);

	array_foreach(&quota->roots, rootp) {
		if ((*rootp)->backend.name == quota_backend_imapc.name) {
			struct imapc_quota_root *root =
				(struct imapc_quota_root *)*rootp;

			root->bytes_last = refresh_root->bytes_cur;
			root->count_last = refresh_root->count_cur;
			root->root.bytes_limit = refresh_root->bytes_limit;
			root->root.count_limit = refresh_root->count_limit;
		}
	}
}

static void
imapc_quota_refresh_deinit(struct quota *quota,
			   struct imapc_quota_refresh *refresh, bool success)
{
	if (success)
		imapc_quota_refresh_update(quota, refresh);
	pool_unref(&refresh->pool);
	i_zero(refresh);
}

static int
imapc_quota_refresh_root_order_cmp(const struct imapc_quota_refresh_root *root1,
				   const struct imapc_quota_refresh_root *root2)
{
	if (root1->order < root2->order)
		return -1;
	else if (root1->order > root2->order)
		return 1;
	else
		return 0;
}

static int imapc_quota_refresh_mailbox(struct imapc_quota_root *root,
				       const char **error_r)
{
	struct imapc_simple_context sctx;
	struct imapc_command *cmd;

	i_assert(root->box_name != NULL);

	/* ask quotas for the configured mailbox */
	imapc_quota_refresh_init(&root->refresh);
	root->refresh.box_name = root->box_name;

	imapc_simple_context_init(&sctx, root->client);
	cmd = imapc_client_cmd(root->client->client,
			       imapc_simple_callback, &sctx);
	imapc_command_sendf(cmd, "GETQUOTAROOT %s", root->box_name);
	imapc_simple_run(&sctx, &cmd);

	/* if there are multiple quota roots, use the first one returned by
	   the QUOTAROOT */
	array_sort(&root->refresh.roots, imapc_quota_refresh_root_order_cmp);
	imapc_quota_refresh_deinit(root->root.quota, &root->refresh,
				   sctx.ret == 0);
	if (sctx.ret < 0)
		*error_r = t_strdup_printf(
			"GETQUOTAROOT %s failed: %s",
			root->box_name,
			mail_storage_get_last_internal_error(
				&root->client->_storage->storage, NULL));

	return sctx.ret;
}

static int imapc_quota_refresh_root(struct imapc_quota_root *root,
				    const char **error_r)
{
	struct imapc_simple_context sctx;
	struct imapc_command *cmd;

	i_assert(root->root_name != NULL);

	/* ask quotas for the configured quota root */
	imapc_quota_refresh_init(&root->refresh);

	imapc_simple_context_init(&sctx, root->client);
	cmd = imapc_client_cmd(root->client->client,
			       imapc_simple_callback, &sctx);
	imapc_command_sendf(cmd, "GETQUOTA %s", root->root_name);
	imapc_simple_run(&sctx, &cmd);

	/* there shouldn't be more than one QUOTA reply, but ignore anyway
	   anything we didn't expect. */
	while (array_count(&root->refresh.roots) > 0) {
		const struct imapc_quota_refresh_root *refresh_root =
			array_first(&root->refresh.roots);
		if (strcmp(refresh_root->name, root->root_name) == 0)
			break;
		array_delete(&root->refresh.roots, 0, 1);
	}
	imapc_quota_refresh_deinit(root->root.quota, &root->refresh,
				   sctx.ret == 0);
	if (sctx.ret < 0)
		*error_r = t_strdup_printf(
			"GETQUOTA %s failed: %s",
			root->root_name,
			mail_storage_get_last_internal_error(
				&root->client->_storage->storage, NULL));
	return sctx.ret;
}

static int imapc_quota_refresh(struct imapc_quota_root *root,
			       const char **error_r)
{
	enum imapc_capability capa;
	int ret;

	if (root->imapc_ns == NULL) {
		/* imapc namespace is missing - disable this quota backend */
		return 0;
	}
	if (root->last_refresh.tv_sec == ioloop_timeval.tv_sec &&
	    root->last_refresh.tv_usec == ioloop_timeval.tv_usec)
		return 0;
	if (!imapc_quota_client_init(root))
		return 0;

	if (imapc_client_get_capabilities(root->client->client, &capa) < 0) {
		*error_r = "Failed to get server capabilities";
		return -1;
	}
	if ((capa & IMAPC_CAPABILITY_QUOTA) == 0) {
		/* no QUOTA capability - disable quota */
		i_warning("quota: Remote IMAP server doesn't support QUOTA - disabling");
		root->client = NULL;
		return 0;
	}

	if (root->root_name == NULL)
		ret = imapc_quota_refresh_mailbox(root, error_r);
	else
		ret = imapc_quota_refresh_root(root, error_r);

	/* set the last_refresh only after the refresh, because it changes
	   ioloop_timeval. */
	root->last_refresh = ioloop_timeval;
	return ret;
}

static int imapc_quota_init_limits(struct quota_root *_root,
				   const char **error_r)
{
	struct imapc_quota_root *root = (struct imapc_quota_root *)_root;

	return imapc_quota_refresh(root, error_r);
}

static void
imapc_quota_namespace_added(struct quota *quota, struct mail_namespace *ns)
{
	struct quota_root **roots;
	unsigned int i, count;

	roots = array_get_modifiable(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->backend.name == quota_backend_imapc.name &&
		    ((roots[i]->ns_prefix == NULL &&
		      ns->type == MAIL_NAMESPACE_TYPE_PRIVATE) ||
		     roots[i]->ns == ns))
			imapc_quota_root_namespace_added(roots[i], ns);
	}
}

static const char *const *
imapc_quota_root_get_resources(struct quota_root *root ATTR_UNUSED)
{
	static const char *resources_both[] = {
		QUOTA_NAME_STORAGE_KILOBYTES,
		QUOTA_NAME_MESSAGES,
		NULL
	};
	return resources_both;
}

static enum quota_get_result
imapc_quota_get_resource(struct quota_root *_root, const char *name,
			 uint64_t *value_r, const char **error_r)
{
	struct imapc_quota_root *root = (struct imapc_quota_root *)_root;

	if (imapc_quota_refresh(root, error_r) < 0)
		return QUOTA_GET_RESULT_INTERNAL_ERROR;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*value_r = root->bytes_last;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*value_r = root->count_last;
	else {
		*error_r = QUOTA_UNKNOWN_RESOURCE_ERROR_STRING;
		return QUOTA_GET_RESULT_UNKNOWN_RESOURCE;
	}
	return QUOTA_GET_RESULT_LIMITED;
}

static int
imapc_quota_update(struct quota_root *root ATTR_UNUSED,
		   struct quota_transaction_context *ctx ATTR_UNUSED,
		   const char **error_r ATTR_UNUSED)
{
	return 0;
}

struct quota_backend quota_backend_imapc = {
	.name = "imapc",

	.v = {
		.alloc = imapc_quota_alloc,
		.init = imapc_quota_init,
		.deinit = imapc_quota_deinit,
		.init_limits = imapc_quota_init_limits,
		.namespace_added = imapc_quota_namespace_added,
		.get_resources = imapc_quota_root_get_resources,
		.get_resource = imapc_quota_get_resource,
		.update = imapc_quota_update,
	}
};
