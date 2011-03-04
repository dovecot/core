/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "dict.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "quota-private.h"

#include <stdlib.h>

#define DICT_QUOTA_CURRENT_PATH DICT_PATH_PRIVATE"quota/"
#define DICT_QUOTA_CURRENT_BYTES_PATH DICT_QUOTA_CURRENT_PATH"storage"
#define DICT_QUOTA_CURRENT_COUNT_PATH DICT_QUOTA_CURRENT_PATH"messages"

struct dict_quota_root {
	struct quota_root root;
	struct dict *dict;
};

extern struct quota_backend quota_backend_dict;

static struct quota_root *dict_quota_alloc(void)
{
	struct dict_quota_root *root;

	root = i_new(struct dict_quota_root, 1);
	return &root->root;
}

static int dict_quota_init(struct quota_root *_root, const char *args)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	const char *username, *p;

	p = args == NULL ? NULL : strchr(args, ':');
	if (p == NULL) {
		i_error("dict quota: URI missing from parameters");
		return -1;
	}

	username = t_strdup_until(args, p);
	args = p+1;

	do {
		/* FIXME: pretty ugly in here. the parameters should have
		   been designed to be extensible. do it in a future version */
		if (strncmp(args, "noenforcing:", 12) == 0) {
			_root->no_enforcing = TRUE;
			args += 12;
			continue;
		}
		if (strncmp(args, "ignoreunlimited:", 16) == 0) {
			_root->disable_unlimited_tracking = TRUE;
			args += 16;
			continue;
		}
		if (strncmp(args, "ns=", 3) == 0) {
			p = strchr(args, ':');
			if (p == NULL)
				break;

			_root->ns_prefix = p_strdup_until(_root->pool,
							  args + 3, p);
			args = p + 1;
			continue;
		}
	} while (0);

	if (*username == '\0')
		username = _root->quota->user->username;

	if (_root->quota->set->debug) {
		i_debug("dict quota: user=%s, uri=%s, noenforcing=%d",
			username, args, _root->no_enforcing);
	}

	/* FIXME: we should use 64bit integer as datatype instead but before
	   it can actually be used don't bother */
	root->dict = dict_init(args, DICT_DATA_TYPE_STRING, username,
			       _root->quota->user->set->base_dir);
	return root->dict != NULL ? 0 : -1;
}

static void dict_quota_deinit(struct quota_root *_root)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;

	if (root->dict != NULL) {
		(void)dict_wait(root->dict);
		dict_deinit(&root->dict);
	}
	i_free(root);
}

static const char *const *
dict_quota_root_get_resources(struct quota_root *root ATTR_UNUSED)
{
	static const char *resources[] = {
		QUOTA_NAME_STORAGE_KILOBYTES, QUOTA_NAME_MESSAGES, NULL
	};

	return resources;
}

static int
dict_quota_count(struct dict_quota_root *root,
		 bool want_bytes, uint64_t *value_r)
{
	struct dict_transaction_context *dt;
	uint64_t bytes, count;

	if (quota_count(&root->root, &bytes, &count) < 0)
		return -1;

	T_BEGIN {
		dt = dict_transaction_begin(root->dict);
		/* these unsets are mainly necessary for pgsql, because its
		   trigger otherwise increases quota without deleting it */
		dict_unset(dt, DICT_QUOTA_CURRENT_BYTES_PATH);
		dict_unset(dt, DICT_QUOTA_CURRENT_COUNT_PATH);
		dict_set(dt, DICT_QUOTA_CURRENT_BYTES_PATH, dec2str(bytes));
		dict_set(dt, DICT_QUOTA_CURRENT_COUNT_PATH, dec2str(count));
	} T_END;

	dict_transaction_commit_async(&dt, NULL, NULL);
	*value_r = want_bytes ? bytes : count;
	return 1;
}

static int
dict_quota_get_resource(struct quota_root *_root,
			const char *name, uint64_t *value_r)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	bool want_bytes;
	int ret;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		want_bytes = TRUE;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		want_bytes = FALSE;
	else
		return 0;

	T_BEGIN {
		const char *value;

		ret = dict_lookup(root->dict, unsafe_data_stack_pool,
				  want_bytes ? DICT_QUOTA_CURRENT_BYTES_PATH :
				  DICT_QUOTA_CURRENT_COUNT_PATH, &value);
		if (ret < 0)
			*value_r = 0;
		else {
			long long tmp;

			/* recalculate quota if it's negative or if it
			   wasn't found */
			tmp = ret == 0 ? -1 : strtoll(value, NULL, 10);
			if (tmp >= 0)
				*value_r = tmp;
			else {
				ret = dict_quota_count(root, want_bytes,
						       value_r);
			}
		}
	} T_END;
	return ret;
}

static void dict_quota_update_callback(int ret, void *context)
{
	struct dict_quota_root *root = context;
	uint64_t value;

	if (ret == 0) {
		/* row doesn't exist, need to recalculate it */
		(void)dict_quota_count(root, TRUE, &value);
	} else if (ret < 0) {
		i_error("dict quota: Quota update failed, it's now desynced");
	}
}

static int
dict_quota_update(struct quota_root *_root, 
		  struct quota_transaction_context *ctx)
{
	struct dict_quota_root *root = (struct dict_quota_root *) _root;
	struct dict_transaction_context *dt;
	uint64_t value;

	if (ctx->recalculate) {
		if (dict_quota_count(root, TRUE, &value) < 0)
			return -1;
	} else {
		dt = dict_transaction_begin(root->dict);
		if (ctx->bytes_used != 0) {
			dict_atomic_inc(dt, DICT_QUOTA_CURRENT_BYTES_PATH,
					ctx->bytes_used);
		}
		if (ctx->count_used != 0) {
			dict_atomic_inc(dt, DICT_QUOTA_CURRENT_COUNT_PATH,
					ctx->count_used);
		}
		dict_transaction_commit_async(&dt, dict_quota_update_callback,
					      root);
	}
	return 0;
}

struct quota_backend quota_backend_dict = {
	"dict",

	{
		dict_quota_alloc,
		dict_quota_init,
		dict_quota_deinit,
		NULL,
		NULL,
		NULL,
		dict_quota_root_get_resources,
		dict_quota_get_resource,
		dict_quota_update,
		NULL
	}
};
