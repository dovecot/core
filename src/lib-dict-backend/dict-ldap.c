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
#include "dict-ldap-settings.h"

static const char *LDAP_ESCAPE_CHARS = "*,\\#+<>;\"()= ";

struct ldap_dict;

struct dict_ldap_op {
	struct ldap_dict *dict;
	struct event *event;
	const struct dict_ldap_map_settings *map;
	pool_t pool;
	unsigned long txid;
	struct dict_lookup_result res;
	dict_lookup_callback_t *callback;
	void *callback_ctx;
};

struct ldap_dict {
	struct dict dict;
	struct dict_ldap_settings *set;

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
	struct ldap_client_settings set;
	i_zero(&set);
	set.uris = dict->set->uri;
	set.auth_dn = dict->set->bind_dn;
	set.auth_dn_password = dict->set->password;
	set.timeout_secs = dict->set->timeout;
	set.max_idle_time_secs = dict->set->max_idle_time;
	set.debug_level = dict->set->debug;
	set.require_ssl = dict->set->require_ssl;
	set.starttls = dict->set->start_tls;
	set.event_parent = dict->event;
	return ldap_client_init(&set, &dict->client, error_r);
}

#define IS_LDAP_ESCAPED_CHAR(c) \
	((((unsigned char)(c)) & 0x80) != 0 || strchr(LDAP_ESCAPE_CHARS, (c)) != NULL)

static const char *ldap_escape(const char *str)
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

static bool
ldap_dict_build_query(const struct dict_op_settings *set,
		      const struct dict_ldap_map_settings *map,
                      ARRAY_TYPE(const_string) *values, bool priv,
                      string_t *query_r, const char **error_r)
{
	const char *template, *error;
	ARRAY(struct var_expand_table) exp;
	struct var_expand_table entry;

	t_array_init(&exp, 8);
	if (priv) {
		i_assert(set->username != NULL);
		i_zero(&entry);
		entry.value = ldap_escape(set->username);
		entry.key = "username";
		array_push_back(&exp, &entry);
		template = t_strdup_printf("(&(%s=%s)%s)", map->username_attribute, "%{username}", map->filter);
	} else {
		template = map->filter;
	}

	for(size_t i = 0; i < array_count(values) && i < array_count(&map->parsed_pattern_keys); i++) {
		struct var_expand_table entry;
		const char *value = array_idx_elem(values, i);
		const char *long_key = array_idx_elem(&map->parsed_pattern_keys, i);
		i_zero(&entry);
		entry.value = ldap_escape(value);
		entry.key = long_key;
		array_push_back(&exp, &entry);
	}

	array_append_zero(&exp);
	const struct var_expand_params params = {
		.table = array_front(&exp),
	};

	if (var_expand(query_r, template, &params, &error) < 0) {
		*error_r = t_strdup_printf("Failed to expand %s: %s", template, error);
		return FALSE;
	}
	return TRUE;
}

static
int ldap_dict_init_legacy(struct dict *dict_driver, const char *uri,
			  const struct dict_legacy_settings *set ATTR_UNUSED,
			  struct dict **dict_r, const char **error_r)
{
	pool_t pool = pool_alloconly_create("ldap dict", 2048);
	struct ldap_dict *dict = p_new(pool, struct ldap_dict, 1);
	dict->pool = pool;
	dict->event = event_create(dict_driver->event);
	dict->dict = *dict_driver;
	dict->uri = p_strdup(pool, uri);
	dict->set = dict_ldap_settings_read(pool, uri, error_r);

	if (dict->set == NULL) {
		event_unref(&dict->event);
		pool_unref(&pool);
		return -1;
	}

	if (dict_ldap_connect(dict, error_r) < 0) {
		event_unref(&dict->event);
		pool_unref(&pool);
		return -1;
	}

	*dict_r = (struct dict*)dict;
	*error_r = NULL;
	return 0;
}

static
void ldap_dict_deinit(struct dict *dict)
{
	struct ldap_dict *ctx = (struct ldap_dict *)dict;

	ldap_client_deinit(&ctx->client);
	event_unref(&dict->event);
	pool_unref(&ctx->pool);
}

static void ldap_dict_wait(struct dict *dict)
{
	struct ldap_dict *ctx = (struct ldap_dict *)dict;

	i_assert(ctx->dict.ioloop == NULL);

	ctx->dict.prev_ioloop = current_ioloop;
	ctx->dict.ioloop = io_loop_create();
	dict_switch_ioloop(dict);

	while (ctx->pending > 0) {
		io_loop_run(current_ioloop);
	}

	io_loop_set_current(ctx->dict.prev_ioloop);
	dict_switch_ioloop(dict);
	io_loop_set_current(ctx->dict.ioloop);
	io_loop_destroy(&ctx->dict.ioloop);
	ctx->dict.prev_ioloop = NULL;
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
		if (entry != NULL) {
			e_debug(op->event, "ldap_dict_lookup_callback got dn %s",
				ldap_entry_dn(entry));
			/* try extract value */
			const char *const *values = ldap_entry_get_attribute(
				entry, op->map->value_attribute);
			if (values != NULL) {
				const char **new_values;

				e_debug(op->event,
					"ldap_dict_lookup_callback got attribute %s",
					op->map->value_attribute);
				op->res.ret = 1;
				new_values = p_new(op->pool, const char *, 2);
				new_values[0] = p_strdup(op->pool, values[0]);
				op->res.values = new_values;
				op->res.value = op->res.values[0];
			} else {
				e_debug(op->event,
					"ldap_dict_lookup_callback dit not get attribute %s",
					op->map->value_attribute);
				op->res.value = NULL;
			}
		}
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

static
void ldap_dict_lookup_async(struct dict *dict,
			    const struct dict_op_settings *set,
			    const char *key,
			    dict_lookup_callback_t *callback, void *context)
{
	struct ldap_search_input input;
	struct ldap_dict *ctx = (struct ldap_dict*)dict;
	struct dict_ldap_op *op;
	const char *error;

	pool_t oppool = pool_alloconly_create("ldap dict lookup", 64);
	string_t *query = str_new(oppool, 64);
	op = p_new(oppool, struct dict_ldap_op, 1);
	op->pool = oppool;
	op->dict = ctx;
	op->callback = callback;
	op->callback_ctx = context;
	op->txid = ctx->last_txid++;
	op->event = event_create(op->dict->dict.event);

	/* key needs to be transformed into something else */
	ARRAY_TYPE(const_string) values;
	const char *attributes[2] = {0, 0};
	t_array_init(&values, 8);
	const struct dict_ldap_map_settings *map = ldap_dict_find_map(ctx, key, &values);

	if (map != NULL) {
		op->map = map;
		attributes[0] = map->value_attribute;
		/* build lookup */
		i_zero(&input);
		input.base_dn = map->base;
		input.scope = map->parsed_scope;
		if (!ldap_dict_build_query(set, map, &values, strncmp(key, DICT_PATH_PRIVATE, strlen(DICT_PATH_PRIVATE))==0, query, &error)) {
			op->res.error = error;
			callback(&op->res, context);
			event_unref(&op->event);
			pool_unref(&oppool);
			return;
		}
		input.filter = str_c(query);
		input.attributes = attributes;
		input.timeout_secs = ctx->set->timeout;
		ctx->pending++;
		ldap_search_start(ctx->client, &input, ldap_dict_lookup_callback, op);
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
		.init_legacy = ldap_dict_init_legacy,
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
