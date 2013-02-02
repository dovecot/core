/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "settings.h"
#include "dict.h"
#include "json-parser.h"
#include "istream.h"
#include "str.h"
#include "auth-request.h"
#include "auth-worker-client.h"
#include "db-dict.h"

#include <stddef.h>
#include <stdlib.h>

#define DEF_STR(name) DEF_STRUCT_STR(name, db_dict_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, db_dict_settings)

static struct setting_def setting_defs[] = {
	DEF_STR(uri),
	DEF_STR(password_key),
	DEF_STR(user_key),
 	DEF_STR(iterate_prefix),
 	DEF_STR(value_format),
 	DEF_BOOL(iterate_disable),
	DEF_STR(default_pass_scheme),

	{ 0, NULL, 0 }
};

static struct db_dict_settings default_dict_settings = {
	.uri = NULL,
	.password_key = "",
	.user_key = "",
	.iterate_prefix = "",
	.iterate_disable = FALSE,
	.value_format = "json",
	.default_pass_scheme = "MD5"
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

static const char *parse_setting(const char *key, const char *value,
				 struct dict_connection *conn)
{
	return parse_setting_from_defs(conn->pool, setting_defs,
				       &conn->set, key, value);
}

struct dict_connection *db_dict_init(const char *config_path)
{
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
	if (!settings_read_nosection(config_path, parse_setting, conn, &error))
		i_fatal("dict %s: %s", config_path, error);

	if (conn->set.uri == NULL)
		i_fatal("dict %s: Empty uri setting", config_path);
	if (strcmp(conn->set.value_format, "json") != 0) {
		i_fatal("dict %s: Unsupported value_format %s in ",
			config_path, conn->set.value_format);
	}
	if (dict_init(conn->set.uri, DICT_DATA_TYPE_STRING, "",
		      global_auth_settings->base_dir, &conn->dict, &error) < 0)
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

struct db_dict_value_iter {
	struct json_parser *parser;
	string_t *key;
	const char *error;
};

struct db_dict_value_iter *
db_dict_value_iter_init(struct dict_connection *conn, const char *value)
{
	struct db_dict_value_iter *iter;
	struct istream *input;

	i_assert(strcmp(conn->set.value_format, "json") == 0);

	/* hardcoded for now for JSON value. make it more modular when other
	   value types are supported. */
	iter = i_new(struct db_dict_value_iter, 1);
	iter->key = str_new(default_pool, 64);
	input = i_stream_create_from_data(value, strlen(value));
	iter->parser = json_parser_init(input);
	i_stream_unref(&input);
	return iter;
}

bool db_dict_value_iter_next(struct db_dict_value_iter *iter,
			     const char **key_r, const char **value_r)
{
	enum json_type type;
	const char *value;

	if (json_parse_next(iter->parser, &type, &value) < 0)
		return FALSE;
	if (type != JSON_TYPE_OBJECT_KEY) {
		iter->error = "Object expected";
		return FALSE;
	}
	if (*value == '\0') {
		iter->error = "Empty object key";
		return FALSE;
	}
	str_truncate(iter->key, 0);
	str_append(iter->key, value);

	if (json_parse_next(iter->parser, &type, &value) < 0) {
		iter->error = "Missing value";
		return FALSE;
	}
	if (type == JSON_TYPE_OBJECT) {
		iter->error = "Nested objects not supported";
		return FALSE;
	}
	*key_r = str_c(iter->key);
	*value_r = value;
	return TRUE;
}

int db_dict_value_iter_deinit(struct db_dict_value_iter **_iter,
			      const char **error_r)
{
	struct db_dict_value_iter *iter = *_iter;

	*_iter = NULL;

	*error_r = iter->error;
	if (json_parser_deinit(&iter->parser, &iter->error) < 0 &&
	    *error_r == NULL)
		*error_r = iter->error;
	str_free(&iter->key);
	i_free(iter);
	return *error_r != NULL ? -1 : 0;
}
