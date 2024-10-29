/* Copyright (c) 2016-2018 Dovecot authors */

#include "lib.h"

#if defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD)

#include "array.h"
#include "module-dir.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "var-expand.h"
#include "connection.h"
#include "llist.h"
#include "ldap-client.h"
#include "dict.h"
#include "dict-private.h"
#include "settings.h"
#include "dict-ldap-settings.h"

static const char *LDAP_ESCAPE_CHARS = "*,\\#+<>;\"()= ";

struct ldap_dict;
struct key_value {
	/* pre lower-cased */
	const char *key_lcase;

	const char *value;
};

struct dict_ldap_op {
	struct ldap_dict *dict;
	struct event *event;
	const struct dict_ldap_map_settings *map;
	ARRAY_TYPE(const_string) pattern_values;
	ARRAY(struct key_value) attribute_values;

	const char *username;
	bool private;
	pool_t pool;
	unsigned long txid;
	struct dict_lookup_result res;
	dict_lookup_callback_t *callback;
	void *callback_ctx;
};

struct ldap_dict {
	struct dict dict;
	const struct dict_ldap_settings *set;

	const char *uri;
	const char *base_dn;
	enum ldap_scope scope;

	pool_t pool;
	struct event *event;

	struct ldap_client *client;

	unsigned long last_txid;
	unsigned int pending;

	struct ldap_dict *prev,*next;
};

static
void ldap_dict_lookup_async(struct dict *dict,
			    const struct dict_op_settings *set, const char *key,
			    dict_lookup_callback_t *callback, void *context);


static bool
dict_ldap_map_match(const struct dict_ldap_map_settings *map, const char *path,
		    ARRAY_TYPE(const_string) *values)
{
	const char *pat, *attribute, *p;
	size_t len;

	array_clear(values);
	pat = map->parsed_pattern;
	while (*pat != '\0' && *path != '\0') {
		if (*pat == '$') {
			/* variable */
			pat++;
			if (*pat == '\0') {
				/* pattern ended with this variable,
				   it'll match the rest of the path */
				len = strlen(path);
				array_push_back(values, &path);
				path += len;
				return TRUE;
			}
			/* pattern matches until the next '/' in path */
			p = strchr(path, '/');
			if (p != NULL) {
				attribute = t_strdup_until(path, p);
				array_push_back(values, &attribute);
				path = p;
			} else {
				/* no '/' anymore, but it'll still match a
				   partial */
				array_push_back(values, &path);
				path += strlen(path);
				pat++;
			}
		} else if (*pat == *path) {
			pat++;
			path++;
		} else {
			return FALSE;
		}
	}

	return *pat == '\0' && *path == '\0';
}

static const struct dict_ldap_map_settings *
ldap_dict_find_map(struct ldap_dict *dict, const char *path,
		  ARRAY_TYPE(const_string) *values)
{
	const struct dict_ldap_map_settings *maps;
	unsigned int i, count;

	t_array_init(values, 2);
	maps = array_get(&dict->set->parsed_maps, &count);
	for (i = 0; i < count; i++) {
		if (dict_ldap_map_match(&maps[i], path, values))
			return &maps[i];
	}
	return NULL;
}

static
int dict_ldap_connect(struct ldap_dict *dict, const char **error_r)
{
	return ldap_client_init_auto(dict->event, &dict->client, error_r);
}

#define IS_LDAP_ESCAPED_CHAR(c) \
	((((unsigned char)(c)) & 0x80) != 0 || strchr(LDAP_ESCAPE_CHARS, (c)) != NULL)

static const char *ldap_escape(const char *str, void *context ATTR_UNUSED)
{
	string_t *ret = NULL;

	for (const char *p = str; *p != '\0'; p++) {
		if (IS_LDAP_ESCAPED_CHAR(*p)) {
			if (ret == NULL) {
				ret = t_str_new((size_t) (p - str) + 64);
				str_append_data(ret, str, (size_t) (p - str));
			}
			str_printfa(ret, "\\%02X", (unsigned char)*p);
		} else if (ret != NULL)
			str_append_c(ret, *p);
	}

	return ret == NULL ? str : str_c(ret);
}

static
int ldap_dict_init(const struct dict *dict_driver, struct event *event,
		   struct dict **dict_r, const char **error_r)
{
	const struct dict_ldap_settings *set;
	if (dict_ldap_settings_get(event, &set, error_r) < 0)
		return -1;

	pool_t pool = pool_alloconly_create("ldap dict", 2048);
	struct ldap_dict *dict = p_new(pool, struct ldap_dict, 1);
	dict->pool = pool;
	dict->event = event_create(event);
	dict->dict = *dict_driver;
	dict->set = set;

	if (dict_ldap_connect(dict, error_r) < 0) {
		event_unref(&dict->event);
		settings_free(set);
		pool_unref(&pool);
		return -1;
	}

	*dict_r = &dict->dict;
	*error_r = NULL;
	return 0;
}

static
void ldap_dict_deinit(struct dict *_dict)
{
	struct ldap_dict *dict = (struct ldap_dict *)_dict;

	ldap_client_deinit(&dict->client);
	event_unref(&dict->event);
	settings_free(dict->set);
	pool_unref(&dict->pool);
}

static void ldap_dict_wait(struct dict *_dict)
{
	struct ldap_dict *dict = (struct ldap_dict *)_dict;

	i_assert(dict->dict.ioloop == NULL);

	dict->dict.prev_ioloop = current_ioloop;
	dict->dict.ioloop = io_loop_create();
	dict_switch_ioloop(&dict->dict);

	while (dict->pending > 0)
		io_loop_run(current_ioloop);

	io_loop_set_current(dict->dict.prev_ioloop);
	dict_switch_ioloop(&dict->dict);
	io_loop_set_current(dict->dict.ioloop);
	io_loop_destroy(&dict->dict.ioloop);
	dict->dict.prev_ioloop = NULL;
}

static bool ldap_dict_switch_ioloop(struct dict *dict)
{
	struct ldap_dict *ctx = (struct ldap_dict *)dict;

	ldap_client_switch_ioloop(ctx->client);
	return ctx->pending > 0;
}

static
void ldap_dict_lookup_done(const struct dict_lookup_result *result, void *ctx)
{
	struct dict_lookup_result *res = ctx;
	res->ret = result->ret;
	if (result->ret > 0) {
		res->values = p_strarray_dup(pool_datastack_create(),
					     result->values);
	}
	res->error = t_strdup(result->error);
}

static void
ldap_dict_lookup_cb_values(const struct ldap_entry *entry, struct dict_ldap_op *op)
{
	e_debug(op->event, "got dn %s",
		ldap_entry_dn(entry));

	const char *attribute;
	array_foreach_elem(&op->map->parsed_attributes, attribute) {
		const char *const *values = ldap_entry_get_attribute(entry, attribute);
		bool no_attribute = values == NULL;
		e_debug(op->event, "%s attribute %s",
			no_attribute ? "dit not get" : "got", attribute);
		if (no_attribute)
			continue;
		struct key_value *kv = array_append_space(&op->attribute_values);
		kv->key_lcase = p_strdup(op->pool, t_str_lcase(attribute));
		kv->value = p_strdup(op->pool, values[0]);
	}

	struct dict_ldap_map_post_settings *post;
	if (settings_get_filter(op->event, "dict_map", op->map->pattern,
				&dict_ldap_map_post_setting_parser_info,
				0, &post, &op->res.error) < 0) {
		op->res.ret = -1;
		return;
	}

	ARRAY_TYPE(const_string) resp_values;
	p_array_init(&resp_values, op->pool, array_count(&post->values) + 1);

	const char *value;
	array_foreach_elem(&post->values, value) {
		value = p_strdup(op->pool, value);
		array_push_back(&resp_values, &value);
	}

	settings_free(post);
	array_append_zero(&resp_values);
	array_pop_back(&resp_values);
	bool got_values = array_not_empty(&resp_values);
	op->res.values = got_values ? array_front(&resp_values) : NULL;
	op->res.value = got_values ? op->res.values[0] : NULL;
	op->res.ret = 1;
}

static void
ldap_dict_lookup_callback(struct ldap_result *result, struct dict_ldap_op *op)
{
	pool_t pool = op->pool;
	struct ldap_search_iterator *iter;
	const struct ldap_entry *entry;

	op->dict->pending--;

	if (ldap_result_has_failed(result)) {
		op->res.ret = -1;
		op->res.error = ldap_result_get_error(result);
	} else {
		iter = ldap_search_iterator_init(result);
		entry = ldap_search_iterator_next(iter);
		if (entry != NULL)
			ldap_dict_lookup_cb_values(entry, op);

		ldap_search_iterator_deinit(&iter);
	}
	if (op->dict->dict.prev_ioloop != NULL)
		io_loop_set_current(op->dict->dict.prev_ioloop);
	op->callback(&op->res, op->callback_ctx);
	if (op->dict->dict.prev_ioloop != NULL) {
		io_loop_set_current(op->dict->dict.ioloop);
		io_loop_stop(op->dict->dict.ioloop);
	}

	event_unref(&op->event);
	pool_unref(&pool);
}

static int
ldap_dict_lookup(struct dict *dict, const struct dict_op_settings *set,
		 pool_t pool, const char *key,
		 const char *const **values_r, const char **error_r)
{
	struct dict_lookup_result res;

	ldap_dict_lookup_async(dict, set, key, ldap_dict_lookup_done, &res);

	ldap_dict_wait(dict);
	if (res.ret < 0) {
		*error_r = res.error;
		return -1;
	}
	if (res.ret > 0)
		*values_r = p_strarray_dup(pool, res.values);
	return res.ret;
}

/*
static
struct dict_iterate_context *ldap_dict_iterate_init(struct dict *dict,
				const char *const *paths,
				enum dict_iterate_flags flags)
{
	return NULL;
}

static
bool ldap_dict_iterate(struct dict_iterate_context *ctx,
			const char **key_r, const char **value_r)
{
	return FALSE;
}

static
int ldap_dict_iterate_deinit(struct dict_iterate_context *ctx)
{
	return -1;
}

static
struct dict_transaction_context ldap_dict_transaction_init(struct dict *dict);

static
int ldap_dict_transaction_commit(struct dict_transaction_context *ctx,
				  bool async,
				  dict_transaction_commit_callback_t *callback,
				  void *context);
static
void ldap_dict_transaction_rollback(struct dict_transaction_context *ctx);

static
void ldap_dict_set(struct dict_transaction_context *ctx,
		    const char *key, const char *value);
static
void ldap_dict_unset(struct dict_transaction_context *ctx,
		      const char *key);
static
void ldap_dict_atomic_inc(struct dict_transaction_context *ctx,
			   const char *key, long long diff);
*/

static int
ldap_dict_ldap_expand(const char *key, const char **value_r, void *_ctx,
		      const char **error_r ATTR_UNUSED)
{
	struct dict_ldap_op *op = _ctx;
	*value_r = "";

	if (array_not_empty(&op->attribute_values)) {
		key = t_str_lcase(key);

		const struct key_value *attr;
		array_foreach(&op->attribute_values, attr) {
			if (strcmp(key, attr->key_lcase) == 0) {
				*value_r = attr->value;
				return 0;
			}
		}
	}

	*error_r = t_strdup_printf("ldap attribute %s not found", key);
	return -1;
}

static int
ldap_dict_pattern_expand(const char *key, const char **value_r, void *_ctx,
			 const char **error_r)
{
	struct dict_ldap_op *op = _ctx;
	*value_r = "";

	const ARRAY_TYPE(const_string) *keys = &op->map->parsed_pattern_keys;
	const char *const *value = array_lsearch(keys, &key, i_strcmp_p);
	if (value != NULL) {
		unsigned int index = array_ptr_to_idx(keys, value);
		*value_r = array_idx_elem(&op->pattern_values, index);
		return 0;
	}

	*error_r = t_strdup_printf("pattern %s not found", key);
	return -1;
}

static
void ldap_dict_lookup_async(struct dict *dict,
			    const struct dict_op_settings *set,
			    const char *key,
			    dict_lookup_callback_t *callback, void *context)
{
	struct ldap_search_input input;
	struct ldap_dict *ctx = (struct ldap_dict*)dict;
	struct dict_ldap_op *op;

	pool_t oppool = pool_alloconly_create("ldap dict lookup", 64);
	op = p_new(oppool, struct dict_ldap_op, 1);
	op->pool = oppool;
	op->dict = ctx;
	op->callback = callback;
	op->callback_ctx = context;
	op->txid = ctx->last_txid++;
	op->event = event_create(op->dict->dict.event);
	op->private = str_begins_with(key, DICT_PATH_PRIVATE);
	op->username = set->username;
	op->map = ldap_dict_find_map(ctx, key, &op->pattern_values);
	p_array_init(&op->attribute_values, op->pool, 2);

	if (op->map != NULL) {
		static const struct var_expand_provider providers[] = {
			{ "pattern", ldap_dict_pattern_expand },
			{ "ldap", ldap_dict_ldap_expand},
			{ NULL, NULL }
		};

		struct var_expand_table *table =
			p_new(op->pool, struct var_expand_table, 2);
		table[0].key = "user";
		table[0].value = p_strdup(op->pool, set->username);

		struct var_expand_params *params =
			p_new(op->pool, struct var_expand_params, 1);
		params->escape_func = ldap_escape;
		params->providers = providers;
		params->context = op;
		params->table = table;
		event_set_ptr(op->event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, params);
		struct dict_ldap_map_pre_settings *pre;
		if (settings_get_filter(op->event, "dict_map", op->map->pattern,
					&dict_ldap_map_pre_setting_parser_info,
					0, &pre, &op->res.error) < 0) {

			op->res.ret = -1;
			callback(&op->res, context);
			event_unref(&op->event);
			pool_unref(&op->pool);
			return;
		}

		/* build lookup */
		i_zero(&input);
		input.filter = pre->filter;
		input.base_dn = op->map->base;
		input.scope = op->map->parsed_scope;
		/* Guaranteed to be NULL-terminated by
		   dict_ldap_map_settings_postcheck() */
		input.attributes =
			array_is_empty(&op->map->parsed_attributes) ? NULL :
			array_front(&op->map->parsed_attributes);
		ctx->pending++;
		ldap_search_start(ctx->client, &input, ldap_dict_lookup_callback, op);
		settings_free(pre);
	} else {
		op->res.error = "no such key";
		callback(&op->res, context);
		event_unref(&op->event);
		pool_unref(&oppool);
	}
}

struct dict dict_driver_ldap = {
	.name = "ldap",
	.v = {
		.init = ldap_dict_init,
		.deinit = ldap_dict_deinit,
		.wait = ldap_dict_wait,
		.lookup = ldap_dict_lookup,
		.lookup_async = ldap_dict_lookup_async,
		.switch_ioloop = ldap_dict_switch_ioloop,
	}
};

#ifndef BUILTIN_LDAP
/* Building a plugin */
void dict_ldap_init(struct module *module ATTR_UNUSED);
void dict_ldap_deinit(void);

void dict_ldap_init(struct module *module ATTR_UNUSED)
{
	dict_driver_register(&dict_driver_ldap);
}

void dict_ldap_deinit(void)
{
	ldap_clients_cleanup();
	dict_driver_unregister(&dict_driver_ldap);
}

const char *dict_ldap_plugin_dependencies[] = { NULL };
#endif

#endif
