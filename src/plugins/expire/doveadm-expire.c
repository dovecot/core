/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "str.h"
#include "hash.h"
#include "dict.h"
#include "imap-match.h"
#include "expire-set.h"
#include "mail-search.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"

#define DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, doveadm_expire_mail_cmd_module)

enum expire_user_state {
	EXPIRE_USER_STATE_NONEXISTENT = 0,
	EXPIRE_USER_STATE_EXISTS = 1,
	EXPIRE_USER_STATE_SEEN = 2
};

struct expire_query {
	const char *mailbox;
	struct imap_match_glob *glob;
	time_t before_time;
};

struct doveadm_expire_mail_cmd_context {
	union doveadm_mail_cmd_module_context module_ctx;

	struct dict *dict;
	struct dict_transaction_context *trans;
	struct dict_iterate_context *iter;

	/* username => enum expire_user_state */
	HASH_TABLE(char *, void *) user_states;
	ARRAY(struct expire_query) queries;
	time_t oldest_before_time;
	bool delete_nonexistent_users;
};

const char *doveadm_expire_plugin_version = DOVECOT_ABI_VERSION;

void doveadm_expire_plugin_init(struct module *module);
void doveadm_expire_plugin_deinit(void);

static MODULE_CONTEXT_DEFINE_INIT(doveadm_expire_mail_cmd_module,
				  &doveadm_mail_cmd_module_register);
static void (*next_hook_doveadm_mail_init)(struct doveadm_mail_cmd_context *ctx);

static bool
doveadm_expire_mail_match_mailbox(struct doveadm_expire_mail_cmd_context *ectx,
				  const char *mailbox, time_t oldest_savedate)
{
	const struct expire_query *query;

	array_foreach(&ectx->queries, query) {
		if (oldest_savedate >= query->before_time)
			continue;

		if (query->glob == NULL) {
			if (strcmp(query->mailbox, mailbox) == 0)
				return TRUE;
		} else {
			if (imap_match(query->glob, mailbox) == IMAP_MATCH_YES)
				return TRUE;
		}
	}
	return FALSE;
}

static int
doveadm_expire_mail_want(struct doveadm_mail_cmd_context *ctx,
			 const char *dict_key, time_t oldest_savedate,
			 const char **username_r)
{
	struct doveadm_expire_mail_cmd_context *ectx =
		DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(ctx);
	const char *username, *mailbox;
	enum expire_user_state state;
	char *orig_username;
	void *value;

	/* dict_key = DICT_EXPIRE_PREFIX<user>/<mailbox> */
	username = dict_key + strlen(DICT_EXPIRE_PREFIX);
	mailbox = strchr(username, '/');
	if (mailbox == NULL) {
		/* invalid record, ignore */
		i_error("expire: Invalid key: %s", dict_key);
		return -1;
	}
	username = t_strdup_until(username, mailbox++);

	if (!hash_table_lookup_full(ectx->user_states, username,
				    &orig_username, &value)) {
		/* user no longer exists, delete the record */
		return -1;
	}
	state = POINTER_CAST_TO(value, enum expire_user_state);
	switch (state) {
	case EXPIRE_USER_STATE_NONEXISTENT:
		i_unreached();
	case EXPIRE_USER_STATE_EXISTS:
		break;
	case EXPIRE_USER_STATE_SEEN:
		/* seen this user already, skip the record */
		return 0;
	}

	if (!doveadm_expire_mail_match_mailbox(ectx, mailbox,
					       oldest_savedate)) {
		/* this mailbox doesn't have any matching messages */
		return 0;
	}
	state = EXPIRE_USER_STATE_SEEN;
	hash_table_update(ectx->user_states, orig_username,
			  POINTER_CAST(state));
	*username_r = orig_username;
	return 1;
}

static int
doveadm_expire_mail_cmd_get_next_user(struct doveadm_mail_cmd_context *ctx,
				      const char **username_r)
{
	struct doveadm_expire_mail_cmd_context *ectx =
		DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(ctx);
	const char *key, *value, *error;
	unsigned long oldest_savedate;
	int ret;

	while (dict_iterate(ectx->iter, &key, &value)) {
		if (str_to_ulong(value, &oldest_savedate) < 0) {
			/* invalid record */
			i_error("expire: Invalid timestamp: %s", value);
			continue;
		}
		if ((time_t)oldest_savedate > ectx->oldest_before_time) {
			if (doveadm_debug) {
				i_debug("expire: Stopping iteration on key %s "
					"(%lu > %"PRIdTIME_T")",
					key, oldest_savedate,
					ectx->oldest_before_time);
			}
			break;
		}

		T_BEGIN {
			ret = doveadm_expire_mail_want(ctx, key,
						       oldest_savedate,
						       username_r);
		} T_END;
		if (ret > 0)
			return 1;
		if (ret < 0 && ectx->delete_nonexistent_users) {
			/* user has been deleted */
			dict_unset(ectx->trans, key);
		}
	}

	/* finished */
	if (dict_iterate_deinit(&ectx->iter, &error) < 0) {
		i_error("Dictionary iteration failed: %s", error);
		return -1;
	}
	return 0;
}

static const char *const *doveadm_expire_get_patterns(void)
{
	ARRAY_TYPE(const_string) patterns;
	const char *str;
	char set_name[6+MAX_INT_STRLEN+1];
	unsigned int i;

	t_array_init(&patterns, 16);
	str = doveadm_plugin_getenv("expire");
	for (i = 2; str != NULL; i++) {
		array_append(&patterns, &str, 1);

		if (i_snprintf(set_name, sizeof(set_name), "expire%u", i) < 0)
			i_unreached();
		str = doveadm_plugin_getenv(set_name);
	}
	array_append_zero(&patterns);
	return array_idx(&patterns, 0);
}

static bool
doveadm_expire_get_or_mailboxes(struct doveadm_mail_cmd_context *ctx,
				const struct mail_search_arg *args,
				struct expire_query query)
{
	struct doveadm_expire_mail_cmd_context *ectx =
		DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(ctx);
	const struct mail_search_arg *arg;
	unsigned int query_count;

	query.mailbox = NULL;
	query_count = array_count(&ectx->queries);
	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MAILBOX_GLOB:
			query.glob = imap_match_init(ctx->pool, arg->value.str,
						     TRUE, '/');
			/* fall through */
		case SEARCH_MAILBOX:
			/* require mailbox to be in expire patterns */
			query.mailbox = p_strdup(ctx->pool, arg->value.str);
			array_push_back(&ectx->queries, &query);
			break;
		default:
			/* there are something else besides mailboxes,
			   can't optimize this. */
			array_delete(&ectx->queries, query_count,
				     array_count(&ectx->queries) - query_count);
			return FALSE;
		}
	}
	return query.mailbox != NULL;
}

static bool
doveadm_expire_analyze_and_query(struct doveadm_mail_cmd_context *ctx,
				 const struct mail_search_arg *args)
{
	struct doveadm_expire_mail_cmd_context *ectx =
		DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(ctx);
	const struct mail_search_arg *arg;
	struct expire_query query;
	bool have_or = FALSE;

	i_zero(&query);
	query.before_time = (time_t)-1;

	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_OR:
			have_or = TRUE;
			break;
		case SEARCH_MAILBOX_GLOB:
			query.glob = imap_match_init(ctx->pool, arg->value.str,
						     TRUE, '/');
			/* fall through */
		case SEARCH_MAILBOX:
			/* require mailbox to be in expire patterns */
			query.mailbox = p_strdup(ctx->pool, arg->value.str);
			break;
		case SEARCH_BEFORE:
			if (arg->value.date_type != MAIL_SEARCH_DATE_TYPE_SAVED)
				break;
			if ((arg->value.search_flags &
			     MAIL_SEARCH_ARG_FLAG_UTC_TIMES) == 0)
				break;
			query.before_time = arg->value.time;
			break;
		default:
			break;
		}
	}

	if (query.before_time == (time_t)-1) {
		/* no SAVEDBEFORE, can't optimize */
		return FALSE;
	}

	if (query.mailbox != NULL) {
		/* one mailbox */
		array_push_back(&ectx->queries, &query);
		return TRUE;
	}

	/* no MAILBOX, but check if one of the ORs lists mailboxes */
	if (!have_or)
		return FALSE;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (arg->type == SEARCH_OR &&
		    doveadm_expire_get_or_mailboxes(ctx, arg->value.subargs,
						    query))
			return TRUE;
	}
	return FALSE;
}

static bool
doveadm_expire_analyze_or_query(struct doveadm_mail_cmd_context *ctx,
				const struct mail_search_arg *args)
{
	const struct mail_search_arg *arg;

	/* all of the subqueries must have mailbox and savedbefore */
	for (arg = args; arg != NULL; arg = arg->next) {
		if (arg->type != SEARCH_SUB)
			return FALSE;

		if (!doveadm_expire_analyze_and_query(ctx, arg->value.subargs))
			return FALSE;
	}
	return TRUE;
}

static bool doveadm_expire_analyze_query(struct doveadm_mail_cmd_context *ctx)
{
	struct doveadm_expire_mail_cmd_context *ectx =
		DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(ctx);
	struct mail_search_arg *args = ctx->search_args->args;
	struct expire_set *set;
	const struct expire_query *queries;
	unsigned int i, count;

	i_assert(args != NULL);

	/* we support two kinds of queries:

	   1) mailbox-pattern savedbefore <stamp> ...
	   2) or 2*(mailbox-pattern savedbefore <stamp> ...)

	   mailbox-pattern can be:

	   a) mailbox <name>
	   b) or 2*(mailbox <name>)
	*/
	p_array_init(&ectx->queries, ctx->pool, 8);
	if (!doveadm_expire_analyze_and_query(ctx, args) &&
	    (args->type != SEARCH_OR || args->next != NULL ||
	     !doveadm_expire_analyze_or_query(ctx, args->value.subargs))) {
		if (doveadm_debug)
			i_debug("expire: Couldn't optimize search query");
		return FALSE;
	}

	/* make sure all mailboxes match expire patterns */
	set = expire_set_init(doveadm_expire_get_patterns());
	queries = array_get(&ectx->queries, &count);
	for (i = 0; i < count; i++) {
		if (!expire_set_lookup(set, queries[i].mailbox)) {
			if (doveadm_debug) {
				i_debug("expire: Couldn't optimize search query: "
					"mailbox %s not in expire database",
					queries[i].mailbox);
			}
			break;
		}
	}
	expire_set_deinit(&set);

	return i == count;
}

static void doveadm_expire_mail_cmd_deinit(struct doveadm_mail_cmd_context *ctx)
{
	struct doveadm_expire_mail_cmd_context *ectx =
		DOVEADM_EXPIRE_MAIL_CMD_CONTEXT(ctx);
	const char *error;

	if (ectx->iter != NULL) {
		if (dict_iterate_deinit(&ectx->iter, &error) < 0)
			i_error("expire: Dictionary iteration failed: %s", error);
	}
	if (dict_transaction_commit(&ectx->trans, &error) < 0)
		i_error("expire: Dictionary commit failed: %s", error);
	dict_deinit(&ectx->dict);
	hash_table_destroy(&ectx->user_states);

	ectx->module_ctx.super.deinit(ctx);
}

static void doveadm_expire_mail_init(struct doveadm_mail_cmd_context *ctx)
{
	struct doveadm_expire_mail_cmd_context *ectx;
	struct dict_settings dict_set;
	struct dict *dict;
	const struct expire_query *query;
	const char *expire_dict, *username, *value, *error;
	char *username_dup;
	enum expire_user_state state;

	if (ctx->search_args == NULL)
		return;

	expire_dict = doveadm_plugin_getenv("expire_dict");
	if (expire_dict == NULL)
		return;

	/* doveadm proxying uses expire database only locally. the remote
	   doveadm handles each user one at a time (even though
	   iterate_single_user=FALSE) */
	if (ctx->iterate_single_user || ctx->proxying) {
		if (doveadm_debug) {
			i_debug("expire: Iterating only a single user, "
				"ignoring expire database");
		}
		return;
	}

	ectx = p_new(ctx->pool, struct doveadm_expire_mail_cmd_context, 1);
	ectx->module_ctx.super = ctx->v;
	value = doveadm_plugin_getenv("expire_keep_nonexistent_users");
	ectx->delete_nonexistent_users =
		value == NULL || strcmp(value, "yes") != 0;
	MODULE_CONTEXT_SET(ctx, doveadm_expire_mail_cmd_module, ectx);

	/* we can potentially optimize this query. see if the search args
	   are valid for optimization. */
	if (!doveadm_expire_analyze_query(ctx))
		return;

	if (doveadm_debug)
		i_debug("expire: Searching only users listed in expire database");

	i_zero(&dict_set);
	dict_set.value_type = DICT_DATA_TYPE_UINT32;
	dict_set.username = "";
	dict_set.base_dir = doveadm_settings->base_dir;
	if (dict_init(expire_dict, &dict_set, &dict, &error) < 0) {
		i_error("dict_init(%s) failed, not using it: %s",
			expire_dict, error);
		return;
	}

	ectx->oldest_before_time = (time_t)-1;
	array_foreach(&ectx->queries, query) {
		if (ectx->oldest_before_time > query->before_time ||
		    ectx->oldest_before_time == (time_t)-1)
			ectx->oldest_before_time = query->before_time;
	}

	ctx->v.deinit = doveadm_expire_mail_cmd_deinit;
	ctx->v.get_next_user = doveadm_expire_mail_cmd_get_next_user;

	hash_table_create(&ectx->user_states, ctx->pool, 0, str_hash, strcmp);
	while (mail_storage_service_all_next(ctx->storage_service, &username) > 0) {
		username_dup = p_strdup(ctx->pool, username);
		state = EXPIRE_USER_STATE_EXISTS;
		hash_table_insert(ectx->user_states, username_dup,
				  POINTER_CAST(state));
	}

	ectx->dict = dict;
	ectx->trans = dict_transaction_begin(dict);
	ectx->iter = dict_iterate_init(dict, DICT_EXPIRE_PREFIX,
				       DICT_ITERATE_FLAG_RECURSE |
				       DICT_ITERATE_FLAG_SORT_BY_VALUE);
}

void doveadm_expire_plugin_init(struct module *module ATTR_UNUSED)
{
	next_hook_doveadm_mail_init = hook_doveadm_mail_init;
	hook_doveadm_mail_init = doveadm_expire_mail_init;
}

void doveadm_expire_plugin_deinit(void)
{
	i_assert(hook_doveadm_mail_init == doveadm_expire_mail_init);
	hook_doveadm_mail_init = next_hook_doveadm_mail_init;
}
