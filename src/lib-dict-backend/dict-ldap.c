/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING memcached */

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
	const struct dict_ldap_map *map;
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
	const char *username;
	const char *base_dn;
	enum ldap_scope scope;

	pool_t pool;

	struct ldap_client *client;
	struct ioloop *ioloop, *prev_ioloop;

	unsigned long last_txid;
	unsigned int pending;

	struct ldap_dict *prev,*next;
};

static
void ldap_dict_lookup_async(struct dict *dict, const char *key,
			     dict_lookup_callback_t *callback, void *context);


static bool
dict_ldap_map_match(const struct dict_ldap_map *map, const char *path,
		   ARRAY_TYPE(const_string) *values, size_t *pat_len_r,
		   size_t *path_len_r, bool partial_ok, bool recurse)
{
	const char *path_start = path;
	const char *pat, *attribute, *p;
	size_t len;

	array_clear(values);
	pat = map->pattern;
	while (*pat != '\0' && *path != '\0') {
		if (*pat == '$') {
			/* variable */
			pat++;
			if (*pat == '\0') {
				/* pattern ended with this variable,
				   it'll match the rest of the path */
				len = strlen(path);
				if (partial_ok) {
					/* iterating - the last field never
					   matches fully. if there's a trailing
					   '/', drop it. */
					pat--;
					if (path[len-1] == '/') {
						attribute = t_strndup(path, len-1);
						array_append(values, &attribute, 1);
					} else {
						array_append(values, &path, 1);
					}
				} else {
					array_append(values, &path, 1);
					path += len;
				}
				*path_len_r = path - path_start;
				*pat_len_r = pat - map->pattern;
				return TRUE;
			}
			/* pattern matches until the next '/' in path */
			p = strchr(path, '/');
			if (p != NULL) {
				attribute = t_strdup_until(path, p);
				array_append(values, &attribute, 1);
				path = p;
			} else {
				/* no '/' anymore, but it'll still match a
				   partial */
				array_append(values, &path, 1);
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

	*path_len_r = path - path_start;
	*pat_len_r = pat - map->pattern;

	if (*pat == '\0')
		return *path == '\0';
	else if (!partial_ok)
		return FALSE;
	else {
		/* partial matches must end with '/'. */
		if (pat != map->pattern && pat[-1] != '/')
			return FALSE;
		/* if we're not recursing, there should be only one $variable
		   left. */
		if (recurse)
			return TRUE;
		return pat[0] == '$' && strchr(pat, '/') == NULL;
	}
}

static const struct dict_ldap_map *
ldap_dict_find_map(struct ldap_dict *dict, const char *path,
		  ARRAY_TYPE(const_string) *values)
{
	const struct dict_ldap_map *maps;
	unsigned int i, count;
	size_t len;

	t_array_init(values, dict->set->max_attribute_count);
	maps = array_get(&dict->set->maps, &count);
	for (i = 0; i < count; i++) {
		if (dict_ldap_map_match(&maps[i], path, values,
				       &len, &len, FALSE, FALSE))
			return &maps[i];
	}
	return NULL;
}

static
int dict_ldap_connect(struct ldap_dict *dict, const char **error_r)
{
	struct ldap_client_settings set;
	i_zero(&set);
	set.uri = dict->set->uri;
	set.bind_dn = dict->set->bind_dn;
	set.password = dict->set->password;
	set.timeout_secs = dict->set->timeout;
	set.max_idle_time_secs = dict->set->max_idle_time;
	set.debug = dict->set->debug;
	set.require_ssl = dict->set->require_ssl;
	set.start_tls = dict->set->start_tls;
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
ldap_dict_build_query(struct ldap_dict *dict, const struct dict_ldap_map *map,
                      ARRAY_TYPE(const_string) *values, bool priv,
                      string_t *query_r, const char **error_r)
{
	const char *template, *error;
	ARRAY(struct var_expand_table) exp;
	struct var_expand_table entry;

	t_array_init(&exp, 8);
	entry.key = '\0';
	entry.value = ldap_escape(dict->username);
	entry.long_key = "username";
	array_append(&exp, &entry, 1);

	if (priv) {
		template = t_strdup_printf("(&(%s=%s)%s)", map->username_attribute, "%{username}", map->filter);
	} else {
		template = map->filter;
	}

	for(size_t i = 0; i < array_count(values) && i < array_count(&map->ldap_attributes); i++) {
		struct var_expand_table entry;
		const char *const *valuep = array_idx(values, i);
		const char *const *long_keyp = array_idx(&map->ldap_attributes, i);

		entry.value = ldap_escape(*valuep);
		entry.long_key = *long_keyp;
		array_append(&exp, &entry, 1);
	}

	array_append_zero(&exp);

	if (var_expand(query_r, template, array_first(&exp), &error) <= 0) {
		*error_r = t_strdup_printf("Failed to expand %s: %s", template, error);
		return FALSE;
	}
	return TRUE;
}

static
int ldap_dict_init(struct dict *dict_driver, const char *uri,
		   const struct dict_settings *set,
		   struct dict **dict_r, const char **error_r)
{
	pool_t pool = pool_alloconly_create("ldap dict", 2048);
	struct ldap_dict *dict = p_new(pool, struct ldap_dict, 1);
	dict->pool = pool;
	dict->dict = *dict_driver;
	dict->username = p_strdup(pool, set->username);
	dict->uri = p_strdup(pool, uri);
	dict->set = dict_ldap_settings_read(pool, uri, error_r);

	if (dict->set == NULL) {
		pool_unref(&pool);
		return -1;
	}

	if (dict_ldap_connect(dict, error_r) < 0) {
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
	pool_unref(&ctx->pool);
}

static void ldap_dict_wait(struct dict *dict)
{
	struct ldap_dict *ctx = (struct ldap_dict *)dict;

	i_assert(ctx->ioloop == NULL);

	ctx->prev_ioloop = current_ioloop;
	ctx->ioloop = io_loop_create();
	dict_switch_ioloop(dict);

	do {
		io_loop_run(current_ioloop);
	} while (ctx->pending > 0);

	io_loop_set_current(ctx->prev_ioloop);
	dict_switch_ioloop(dict);
	io_loop_set_current(ctx->ioloop);
	io_loop_destroy(&ctx->ioloop);
	ctx->prev_ioloop = NULL;
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
	res->value = t_strdup(result->value);
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
			if (op->dict->set->debug > 0)
				i_debug("ldap_dict_lookup_callback got dn %s", ldap_entry_dn(entry));
			/* try extract value */
			const char *const *values = ldap_entry_get_attribute(entry, op->map->value_attribute);
			if (values != NULL) {
				const char **new_values;

				if (op->dict->set->debug > 0)
					i_debug("ldap_dict_lookup_callback got attribute %s", op->map->value_attribute);
				op->res.ret = 1;
				new_values = p_new(op->pool, const char *, 2);
				new_values[0] = p_strdup(op->pool, values[0]);
				op->res.values = new_values;
				op->res.value = op->res.values[0];
			} else {
				if (op->dict->set->debug > 0)
					i_debug("ldap_dict_lookup_callback dit not get attribute %s", op->map->value_attribute);
				op->res.value = NULL;
			}
		}
		ldap_search_iterator_deinit(&iter);
	}
	op->callback(&op->res, op->callback_ctx);
	pool_unref(&pool);
}

static int
ldap_dict_lookup(struct dict *dict, pool_t pool, const char *key,
		 const char **value_r, const char **error_r)
{
	struct dict_lookup_result res;

	ldap_dict_lookup_async(dict, key, ldap_dict_lookup_done, &res);

	ldap_dict_wait(dict);
	if (res.ret < 0) {
		*error_r = res.error;
		return -1;
	}
	if (res.ret > 0)
		*value_r = p_strdup(pool, res.value);
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
void ldap_dict_lookup_async(struct dict *dict, const char *key,
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

	/* key needs to be transformed into something else */
	ARRAY_TYPE(const_string) values;
	const char *attributes[2] = {0, 0};
	t_array_init(&values, 8);
	const struct dict_ldap_map *map = ldap_dict_find_map(ctx, key, &values);

	if (map != NULL) {
		op->map = map;
		attributes[0] = map->value_attribute;
		/* build lookup */
		i_zero(&input);
		input.base_dn = map->base_dn;
		input.scope = map->scope_val;
		if (!ldap_dict_build_query(ctx, map, &values, strncmp(key, DICT_PATH_PRIVATE, strlen(DICT_PATH_PRIVATE))==0, query, &error)) {
			op->res.error = error;
			callback(&op->res, context);
			pool_unref(&oppool);
		}
		input.filter = str_c(query);
		input.attributes = attributes;
		input.timeout_secs = ctx->set->timeout;
		ctx->pending++;
		ldap_search_start(ctx->client, &input, ldap_dict_lookup_callback, op);
	} else {
		op->res.error = "no such key";
		callback(&op->res, context);
		pool_unref(&oppool);
	}
}

struct dict dict_driver_ldap = {
	.name = "ldap",
	{
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
