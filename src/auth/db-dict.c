/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "array.h"
#include "istream.h"
#include "str.h"
#include "json-parser.h"
#include "settings.h"
#include "dict.h"
#include "auth-request.h"
#include "auth-worker-client.h"
#include "db-dict.h"

#include <stddef.h>

enum dict_settings_section {
	DICT_SETTINGS_SECTION_ROOT = 0,
	DICT_SETTINGS_SECTION_KEY,
	DICT_SETTINGS_SECTION_PASSDB,
	DICT_SETTINGS_SECTION_USERDB
};

struct dict_settings_parser_ctx {
	struct dict_connection *conn;
	enum dict_settings_section section;
	struct db_dict_key *cur_key;
};

struct db_dict_iter_key {
	const struct db_dict_key *key;
	bool used;
	const char *value;
};

struct db_dict_value_iter {
	pool_t pool;
	struct auth_request *auth_request;
	struct dict_connection *conn;
	const struct var_expand_table *var_expand_table;
	ARRAY(struct db_dict_iter_key) keys;

	const ARRAY_TYPE(db_dict_field) *fields;
	const ARRAY_TYPE(db_dict_key_p) *objects;
	unsigned int field_idx;
	unsigned int object_idx;

	struct json_parser *json_parser;
	string_t *tmpstr;
	const char *error;
};

#define DEF_STR(name) DEF_STRUCT_STR(name, db_dict_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, db_dict_settings)
static struct setting_def setting_defs[] = {
	DEF_STR(uri),
	DEF_STR(default_pass_scheme),
 	DEF_STR(iterate_prefix),
 	DEF_BOOL(iterate_disable),

 	DEF_STR(passdb_objects),
 	DEF_STR(userdb_objects),
	{ 0, NULL, 0 }
};

static struct db_dict_settings default_dict_settings = {
	.uri = NULL,
	.default_pass_scheme = "MD5",
	.iterate_prefix = "",
	.iterate_disable = FALSE,
	.passdb_objects = "",
	.userdb_objects = ""
};

#undef DEF_STR
#define DEF_STR(name) DEF_STRUCT_STR(name, db_dict_key)
static struct setting_def key_setting_defs[] = {
	DEF_STR(name),
	DEF_STR(key),
	DEF_STR(format),
 	DEF_STR(default_value),

	{ 0, NULL, 0 }
};

static struct db_dict_key default_key_settings = {
	.name = NULL,
	.key = "",
	.format = "value",
	.default_value = NULL
};

static struct dict_connection *connections = NULL;

static struct dict_connection *dict_conn_find(const char *config_path)
{
	struct dict_connection *conn;

	for (conn = connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->config_path, config_path) == 0)
			return conn;
	}

	return NULL;
}

static bool
parse_obsolete_setting(const char *key, const char *value,
		       struct dict_settings_parser_ctx *ctx,
		       const char **error_r)
{
	const struct db_dict_key *dbkey;

	if (strcmp(key, "password_key") == 0) {
		/* key passdb { key=<value> format=json }
		   passdb_objects = passdb */
		ctx->cur_key = array_append_space(&ctx->conn->set.keys);
		*ctx->cur_key = default_key_settings;
		ctx->cur_key->name = "passdb";
		ctx->cur_key->format = "json";
		ctx->cur_key->parsed_format = DB_DICT_VALUE_FORMAT_JSON;
		ctx->cur_key->key = p_strdup(ctx->conn->pool, value);

		dbkey = ctx->cur_key;
		array_push_back(&ctx->conn->set.parsed_passdb_objects, &dbkey);
		return TRUE;
	}
	if (strcmp(key, "user_key") == 0) {
		/* key userdb { key=<value> format=json }
		   userdb_objects = userdb */
		ctx->cur_key = array_append_space(&ctx->conn->set.keys);
		*ctx->cur_key = default_key_settings;
		ctx->cur_key->name = "userdb";
		ctx->cur_key->format = "json";
		ctx->cur_key->parsed_format = DB_DICT_VALUE_FORMAT_JSON;
		ctx->cur_key->key = p_strdup(ctx->conn->pool, value);

		dbkey = ctx->cur_key;
		array_push_back(&ctx->conn->set.parsed_userdb_objects, &dbkey);
		return TRUE;
	}
	if (strcmp(key, "value_format") == 0) {
		if (strcmp(value, "json") == 0)
			return TRUE;
		*error_r = "Deprecated value_format must be 'json'";
		return FALSE;
	}
	return FALSE;
}

static const char *parse_setting(const char *key, const char *value,
				 struct dict_settings_parser_ctx *ctx)
{
	struct db_dict_field *field;
	const char *error = NULL;

	switch (ctx->section) {
	case DICT_SETTINGS_SECTION_ROOT:
		if (parse_obsolete_setting(key, value, ctx, &error))
			return NULL;
		if (error != NULL)
			return error;
		return parse_setting_from_defs(ctx->conn->pool, setting_defs,
					       &ctx->conn->set, key, value);
	case DICT_SETTINGS_SECTION_KEY:
		return parse_setting_from_defs(ctx->conn->pool, key_setting_defs,
					       ctx->cur_key, key, value);
	case DICT_SETTINGS_SECTION_PASSDB:
		field = array_append_space(&ctx->conn->set.passdb_fields);
		field->name = p_strdup(ctx->conn->pool, key);
		field->value = p_strdup(ctx->conn->pool, value);
		return NULL;
	case DICT_SETTINGS_SECTION_USERDB:
		field = array_append_space(&ctx->conn->set.userdb_fields);
		field->name = p_strdup(ctx->conn->pool, key);
		field->value = p_strdup(ctx->conn->pool, value);
		return NULL;
	}
	i_unreached();
}

static bool parse_section(const char *type, const char *name,
			  struct dict_settings_parser_ctx *ctx,
			  const char **errormsg)
{
	if (type == NULL) {
		ctx->section = DICT_SETTINGS_SECTION_ROOT;
		if (ctx->cur_key != NULL) {
			if (strcmp(ctx->cur_key->format, "value") == 0) {
				ctx->cur_key->parsed_format =
					DB_DICT_VALUE_FORMAT_VALUE;
			} else if (strcmp(ctx->cur_key->format, "json") == 0) {
				ctx->cur_key->parsed_format =
					DB_DICT_VALUE_FORMAT_JSON;
			} else {
				*errormsg = t_strconcat("Unknown key format: ",
					ctx->cur_key->format, NULL);
				return FALSE;
			}
		}
		ctx->cur_key = NULL;
		return TRUE;
	}
	if (ctx->section != DICT_SETTINGS_SECTION_ROOT) {
		*errormsg = "Nested sections not supported";
		return FALSE;
	}
	if (strcmp(type, "key") == 0) {
		if (name == NULL) {
			*errormsg = "Key section is missing name";
			return FALSE;
		}
		if (strchr(name, '.') != NULL) {
			*errormsg = "Key section names must not contain '.'";
			return FALSE;
		}
		ctx->section = DICT_SETTINGS_SECTION_KEY;
		ctx->cur_key = array_append_space(&ctx->conn->set.keys);
		*ctx->cur_key = default_key_settings;
		ctx->cur_key->name = p_strdup(ctx->conn->pool, name);
		return TRUE;
	}
	if (strcmp(type, "passdb_fields") == 0) {
		ctx->section = DICT_SETTINGS_SECTION_PASSDB;
		return TRUE;
	}
	if (strcmp(type, "userdb_fields") == 0) {
		ctx->section = DICT_SETTINGS_SECTION_USERDB;
		return TRUE;
	}
	*errormsg = "Unknown section";
	return FALSE;
}

static void
db_dict_settings_parse(struct db_dict_settings *set)
{
	const struct db_dict_key *key;
	const char *const *tmp;

	tmp = t_strsplit_spaces(set->passdb_objects, " ");
	for (; *tmp != NULL; tmp++) {
		key = db_dict_set_key_find(&set->keys, *tmp);
		if (key == NULL) {
			i_fatal("dict: passdb_objects refers to key %s, "
				"which doesn't exist", *tmp);
		}
		if (key->parsed_format == DB_DICT_VALUE_FORMAT_VALUE) {
			i_fatal("dict: passdb_objects refers to key %s, "
				"but it's in value-only format", *tmp);
		}
		array_push_back(&set->parsed_passdb_objects, &key);
	}

	tmp = t_strsplit_spaces(set->userdb_objects, " ");
	for (; *tmp != NULL; tmp++) {
		key = db_dict_set_key_find(&set->keys, *tmp);
		if (key == NULL) {
			i_fatal("dict: userdb_objects refers to key %s, "
				"which doesn't exist", *tmp);
		}
		if (key->parsed_format == DB_DICT_VALUE_FORMAT_VALUE) {
			i_fatal("dict: userdb_objects refers to key %s, "
				"but it's in value-only format", *tmp);
		}
		array_push_back(&set->parsed_userdb_objects, &key);
	}
}

struct dict_connection *db_dict_init(const char *config_path)
{
	struct dict_settings dict_set;
	struct dict_settings_parser_ctx ctx;
	struct dict_connection *conn;
	const char *error;
	pool_t pool;

	conn = dict_conn_find(config_path);
	if (conn != NULL) {
		conn->refcount++;
		return conn;
	}

	if (*config_path == '\0')
		i_fatal("dict: Configuration file path not given");

	pool = pool_alloconly_create("dict_connection", 1024);
	conn = p_new(pool, struct dict_connection, 1);
	conn->pool = pool;

	conn->refcount = 1;

	conn->config_path = p_strdup(pool, config_path);
	conn->set = default_dict_settings;
	p_array_init(&conn->set.keys, pool, 8);
	p_array_init(&conn->set.passdb_fields, pool, 8);
	p_array_init(&conn->set.userdb_fields, pool, 8);
	p_array_init(&conn->set.parsed_passdb_objects, pool, 2);
	p_array_init(&conn->set.parsed_userdb_objects, pool, 2);

	i_zero(&ctx);
	ctx.conn = conn;
	if (!settings_read(config_path, NULL, parse_setting,
			   parse_section, &ctx, &error))
		i_fatal("dict %s: %s", config_path, error);
	db_dict_settings_parse(&conn->set);

	if (conn->set.uri == NULL)
		i_fatal("dict %s: Empty uri setting", config_path);

	i_zero(&dict_set);
	dict_set.username = "";
	dict_set.base_dir = global_auth_settings->base_dir;
	if (dict_init(conn->set.uri, &dict_set, &conn->dict, &error) < 0)
		i_fatal("dict %s: Failed to init dict: %s", config_path, error);

	conn->next = connections;
	connections = conn;
	return conn;
}

void db_dict_unref(struct dict_connection **_conn)
{
	struct dict_connection *conn = *_conn;

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	dict_deinit(&conn->dict);
	pool_unref(&conn->pool);
}

static struct db_dict_iter_key *
db_dict_iter_find_key(struct db_dict_value_iter *iter, const char *name)
{
	struct db_dict_iter_key *key;

	array_foreach_modifiable(&iter->keys, key) {
		if (strcmp(key->key->name, name) == 0)
			return key;
	}
	return NULL;
}

static void db_dict_iter_find_used_keys(struct db_dict_value_iter *iter)
{
	const struct db_dict_field *field;
	struct db_dict_iter_key *key;
	const char *p, *name;
	unsigned int idx, size;

	array_foreach(iter->fields, field) {
		for (p = field->value; *p != '\0'; ) {
			if (*p != '%') {
				p++;
				continue;
			}

			var_get_key_range(++p, &idx, &size);
			if (size == 0) {
				/* broken %variable ending too early */
				break;
			}
			p += idx;
			if (size > 5 && memcmp(p, "dict:", 5) == 0) {
				name = t_strcut(t_strndup(p+5, size-5), ':');
				key = db_dict_iter_find_key(iter, name);
				if (key != NULL)
					key->used = TRUE;
			}
			p += size;
		}
	}
}

static void db_dict_iter_find_used_objects(struct db_dict_value_iter *iter)
{
	const struct db_dict_key *const *keyp;
	struct db_dict_iter_key *key;

	array_foreach(iter->objects, keyp) {
		key = db_dict_iter_find_key(iter, (*keyp)->name);
		i_assert(key != NULL); /* checked at init */
		i_assert(key->key->parsed_format != DB_DICT_VALUE_FORMAT_VALUE);
		key->used = TRUE;
	}
}

static int
db_dict_iter_key_cmp(const struct db_dict_iter_key *k1,
		     const struct db_dict_iter_key *k2)
{
	return null_strcmp(k1->key->default_value, k2->key->default_value);
}

static int db_dict_iter_lookup_key_values(struct db_dict_value_iter *iter)
{
	struct db_dict_iter_key *key;
	string_t *path;
	const char *error;
	int ret;

	/* sort the keys so that we'll first lookup the keys without
	   default value. if their lookup fails, the user doesn't exist. */
	array_sort(&iter->keys, db_dict_iter_key_cmp);

	path = t_str_new(128);
	str_append(path, DICT_PATH_SHARED);

	array_foreach_modifiable(&iter->keys, key) {
		if (!key->used)
			continue;

		str_truncate(path, strlen(DICT_PATH_SHARED));
		str_append(path, key->key->key);
		ret = dict_lookup(iter->conn->dict, iter->pool,
				  str_c(path), &key->value, &error);
		if (ret > 0) {
			auth_request_log_debug(iter->auth_request, AUTH_SUBSYS_DB,
					       "Lookup: %s = %s", str_c(path),
					       key->value);
		} else if (ret < 0) {
			auth_request_log_error(iter->auth_request, AUTH_SUBSYS_DB,
				"Failed to lookup key %s: %s", str_c(path), error);
			return -1;
		} else if (key->key->default_value != NULL) {
			auth_request_log_debug(iter->auth_request, AUTH_SUBSYS_DB,
				"Lookup: %s not found, using default value %s",
				str_c(path), key->key->default_value);
			key->value = key->key->default_value;
		} else {
			return 0;
		}
	}
	return 1;
}

int db_dict_value_iter_init(struct dict_connection *conn,
			    struct auth_request *auth_request,
			    const ARRAY_TYPE(db_dict_field) *fields,
			    const ARRAY_TYPE(db_dict_key_p) *objects,
			    struct db_dict_value_iter **iter_r)
{
	struct db_dict_value_iter *iter;
	struct db_dict_iter_key *iterkey;
	const struct db_dict_key *key;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create(MEMPOOL_GROWING"auth dict lookup", 1024);
	iter = p_new(pool, struct db_dict_value_iter, 1);
	iter->pool = pool;
	iter->conn = conn;
	iter->fields = fields;
	iter->objects = objects;
	iter->tmpstr = str_new(pool, 128);
	iter->auth_request = auth_request;
	iter->var_expand_table = auth_request_get_var_expand_table(auth_request, NULL);

	/* figure out what keys we need to lookup, and lookup them */
	p_array_init(&iter->keys, pool, array_count(&conn->set.keys));
	array_foreach(&conn->set.keys, key) {
		iterkey = array_append_space(&iter->keys);
		struct db_dict_key *new_key = p_new(iter->pool, struct db_dict_key, 1);
		memcpy(new_key, key, sizeof(struct db_dict_key));
		string_t *expanded_key = str_new(iter->pool, strlen(key->key));
		const char *error;
		if (auth_request_var_expand_with_table(expanded_key, key->key, auth_request,
						       iter->var_expand_table,
						       NULL, &error) <= 0) {
			auth_request_log_error(iter->auth_request, AUTH_SUBSYS_DB,
				"Failed to expand key %s: %s", key->key, error);
			pool_unref(&pool);
			return -1;
		}
		new_key->key = str_c(expanded_key);
		iterkey->key = new_key;
	}
	T_BEGIN {
		db_dict_iter_find_used_keys(iter);
		db_dict_iter_find_used_objects(iter);
		ret = db_dict_iter_lookup_key_values(iter);
	} T_END;
	if (ret <= 0) {
		pool_unref(&pool);
		return ret;
	}
	*iter_r = iter;
	return 1;
}

static bool
db_dict_value_iter_json_next(struct db_dict_value_iter *iter,
			     string_t *tmpstr,
			     const char **key_r, const char **value_r)
{
	enum json_type type;
	const char *value;

	if (json_parse_next(iter->json_parser, &type, &value) < 0)
		return FALSE;
	if (type != JSON_TYPE_OBJECT_KEY) {
		iter->error = "Object expected";
		return FALSE;
	}
	if (*value == '\0') {
		iter->error = "Empty object key";
		return FALSE;
	}
	str_truncate(tmpstr, 0);
	str_append(tmpstr, value);

	if (json_parse_next(iter->json_parser, &type, &value) < 0) {
		iter->error = "Missing value";
		return FALSE;
	}
	if (type == JSON_TYPE_OBJECT) {
		iter->error = "Nested objects not supported";
		return FALSE;
	}
	*key_r = str_c(tmpstr);
	*value_r = value;
	return TRUE;
}

static void
db_dict_value_iter_json_init(struct db_dict_value_iter *iter, const char *data)
{
	struct istream *input;

	i_assert(iter->json_parser == NULL);

	input = i_stream_create_from_data(data, strlen(data));
	iter->json_parser = json_parser_init(input);
	i_stream_unref(&input);
}

static bool
db_dict_value_iter_object_next(struct db_dict_value_iter *iter,
			       const char **key_r, const char **value_r)
{
	const struct db_dict_key *const *keyp;
	struct db_dict_iter_key *key;

	if (iter->json_parser != NULL)
		return db_dict_value_iter_json_next(iter, iter->tmpstr, key_r, value_r);
	if (iter->object_idx == array_count(iter->objects))
		return FALSE;

	keyp = array_idx(iter->objects, iter->object_idx);
	key = db_dict_iter_find_key(iter, (*keyp)->name);
	i_assert(key != NULL); /* checked at init */

	switch (key->key->parsed_format) {
	case DB_DICT_VALUE_FORMAT_VALUE:
		i_unreached();
	case DB_DICT_VALUE_FORMAT_JSON:
		db_dict_value_iter_json_init(iter, key->value);
		return db_dict_value_iter_json_next(iter, iter->tmpstr, key_r, value_r);
	}
	i_unreached();
}

static int
db_dict_field_find(const char *data, void *context,
		   const char **value_r,
		   const char **error_r ATTR_UNUSED)
{
	struct db_dict_value_iter *iter = context;
	struct db_dict_iter_key *key;
	const char *name, *value, *dotname = strchr(data, '.');
	string_t *tmpstr;

	*value_r = NULL;

	if (dotname != NULL)
		data = t_strdup_until(data, dotname++);
	key = db_dict_iter_find_key(iter, data);
	if (key == NULL)
		return 1;

	switch (key->key->parsed_format) {
	case DB_DICT_VALUE_FORMAT_VALUE:
		*value_r = dotname != NULL ? NULL :
			(key->value == NULL ? "" : key->value);
		return 1;
	case DB_DICT_VALUE_FORMAT_JSON:
		if (dotname == NULL)
			return 1;
		db_dict_value_iter_json_init(iter, key->value);
		*value_r = "";
		tmpstr = t_str_new(64);
		while (db_dict_value_iter_json_next(iter, tmpstr, &name, &value)) {
			if (strcmp(name, dotname) == 0) {
				*value_r = t_strdup(value);
				break;
			}
		}
		(void)json_parser_deinit(&iter->json_parser, &iter->error);
		return 1;
	}
	i_unreached();
}

bool db_dict_value_iter_next(struct db_dict_value_iter *iter,
			     const char **key_r, const char **value_r)
{
	static struct var_expand_func_table var_funcs_table[] = {
		{ "dict", db_dict_field_find },
		{ NULL, NULL }
	};
	const struct db_dict_field *field;
	const char *error;

	if (iter->field_idx == array_count(iter->fields))
		return db_dict_value_iter_object_next(iter, key_r, value_r);
	field = array_idx(iter->fields, iter->field_idx++);

	str_truncate(iter->tmpstr, 0);
	if (var_expand_with_funcs(iter->tmpstr, field->value,
				  iter->var_expand_table, var_funcs_table,
				  iter, &error) <= 0) {
		iter->error = p_strdup_printf(iter->pool,
			"Failed to expand %s=%s: %s",
			field->name, field->value, error);
		return FALSE;
	}
	*key_r = field->name;
	*value_r = str_c(iter->tmpstr);
	return TRUE;
}

int db_dict_value_iter_deinit(struct db_dict_value_iter **_iter,
			      const char **error_r)
{
	struct db_dict_value_iter *iter = *_iter;

	*_iter = NULL;

	*error_r = iter->error;
	if (iter->json_parser != NULL) {
		if (json_parser_deinit(&iter->json_parser, &iter->error) < 0 &&
		    *error_r == NULL)
			*error_r = iter->error;
	}

	pool_unref(&iter->pool);
	return *error_r != NULL ? -1 : 0;
}
