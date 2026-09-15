/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hex-binary.h"
#include "str.h"
#include "net.h"
#include "time-util.h"
#include "settings.h"
#include "settings-parser.h"
#include "ssl-settings.h"
#include "sql-api-private.h"

#ifdef BUILD_MYSQL
#include <unistd.h>
#include <time.h>
#ifdef HAVE_ATTR_NULL
/* ugly way to tell clang that mysql.h is a system header and we don't want
   to enable nonnull attributes for it by default.. */
# 4 "driver-mysql.c" 3
#endif
#include <mysql.h>
#ifdef HAVE_ATTR_NULL
# 4 "driver-mysql.c" 3
# line 20
#endif
#include <errmsg.h>

#define MYSQL_DEFAULT_READ_TIMEOUT_SECS 30
#define MYSQL_DEFAULT_WRITE_TIMEOUT_SECS 30

/* <settings checks> */
#define MYSQL_SQLPOOL_SET_NAME "mysql"
/* </settings checks> */

struct mysql_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) sqlpool_hosts;
	unsigned int connection_limit;

	const char *host;
	in_port_t port;
	const char *user;
	const char *password;
	const char *dbname;

	bool ssl;
	const char *option_file;
	const char *option_group;
	unsigned int client_flags;

	unsigned int connect_timeout_secs;
	unsigned int read_timeout_secs;
	unsigned int write_timeout_secs;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("mysql_"#name, name, struct mysql_settings)
#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("mysql_"#name, name##_secs, struct mysql_settings)
static const struct setting_define mysql_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = MYSQL_SQLPOOL_SET_NAME,
	  .offset = offsetof(struct mysql_settings, sqlpool_hosts),
	  .filter_array_field_name = "mysql_host", },
	DEF(UINT, connection_limit),

	DEF(STR, host),
	DEF(IN_PORT, port),
	DEF(STR, user),
	DEF(STR, password),
	DEF(STR, dbname),

	DEF(BOOL, ssl),
	DEF(STR, option_file),
	DEF(STR, option_group),
	DEF(UINT, client_flags),

	DEF_SECS(TIME, connect_timeout),
	DEF_SECS(TIME, read_timeout),
	DEF_SECS(TIME, write_timeout),

	SETTING_DEFINE_LIST_END
};

static struct mysql_settings mysql_default_settings = {
	.sqlpool_hosts = ARRAY_INIT,
	.connection_limit = SQL_DEFAULT_CONNECTION_LIMIT,

	.host = "",
	.port = 0,
	.user = "",
	.password = "",
	.dbname = "",

	.ssl = FALSE,
	.option_file = "",
	.option_group = "client",
	.client_flags = 0,

	.connect_timeout_secs = SQL_CONNECT_TIMEOUT_SECS,
	.read_timeout_secs = MYSQL_DEFAULT_READ_TIMEOUT_SECS,
	.write_timeout_secs = MYSQL_DEFAULT_WRITE_TIMEOUT_SECS,
};

const struct setting_parser_info mysql_setting_parser_info = {
	.name = "mysql",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_mysql",
#endif

	.defines = mysql_setting_defines,
	.defaults = &mysql_default_settings,

	.struct_size = sizeof(struct mysql_settings),
	.pool_offset1 = 1 + offsetof(struct mysql_settings, pool),
};

struct mysql_db {
	struct sql_db api;

	pool_t pool;
	const struct mysql_settings *set;
	const struct ssl_settings *ssl_set;

	time_t last_success;

	MYSQL *mysql;
	unsigned int next_query_connection;

	/* mysql_real_connect() has been called without mysql_close() */
	bool connection_opened:1;
};

struct mysql_result {
	struct sql_result api;
	pool_t result_pool;

	MYSQL_RES *result;
	MYSQL_STMT *stmt;
	MYSQL_BIND *result_binds;
	unsigned long *result_lengths;
	my_bool *result_is_null;

	MYSQL_ROW row;
	char *error;

	MYSQL_FIELD *fields;
	unsigned int fields_count;
	const char **values;

	my_ulonglong affected_rows;
};

struct mysql_transaction_context {
	struct sql_transaction_context ctx;

	pool_t query_pool;
	const char *error;

	bool failed:1;
	bool committed:1;
	bool commit_started:1;
};

struct mysql_statement {
	struct sql_statement api;
	MYSQL_STMT *stmt;
	ARRAY(MYSQL_BIND) binds;
};

struct mysql_db_cache {
	/* Contains the sqlpool connection */
	struct sql_db *db;

	const struct mysql_settings *set;
	const struct ssl_settings *ssl_set;
};

extern const struct sql_db driver_mysql_db;
extern const struct sql_result driver_mysql_result;
extern const struct sql_result driver_mysql_error_result;

static ARRAY(struct mysql_db_cache) mysql_db_cache;

static struct event_category event_category_mysql = {
	.parent = &event_category_sql,
	.name = "mysql"
};

static int driver_mysql_connect(struct sql_db *_db)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	const char *unix_socket, *host;
	unsigned long client_flags = db->set->client_flags;
	unsigned int secs_used;
	time_t start_time;
	bool failed;

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	if (db->set->host[0] == '\0') {
		/* assume option_file overrides the host, or if not we'll just
		   connect to localhost */
		unix_socket = NULL;
		host = NULL;
	} else if (*db->set->host == '/') {
		unix_socket = db->set->host;
		host = NULL;
	} else {
		unix_socket = NULL;
		host = db->set->host;
	}

	if (db->set->option_file[0] != '\0') {
		mysql_options(db->mysql, MYSQL_READ_DEFAULT_FILE,
			      db->set->option_file);
	}

	mysql_options(db->mysql, MYSQL_OPT_CONNECT_TIMEOUT, &db->set->connect_timeout_secs);
	mysql_options(db->mysql, MYSQL_OPT_READ_TIMEOUT, &db->set->read_timeout_secs);
	mysql_options(db->mysql, MYSQL_OPT_WRITE_TIMEOUT, &db->set->write_timeout_secs);
	mysql_options(db->mysql, MYSQL_READ_DEFAULT_GROUP, db->set->option_group);

	if (db->set->ssl) {
#ifdef HAVE_MYSQL_SSL
		struct settings_file key_file, cert_file, ca_file;
		settings_file_get(db->ssl_set->ssl_client_key_file,
				  unsafe_data_stack_pool, &key_file);
		settings_file_get(db->ssl_set->ssl_client_cert_file,
				  unsafe_data_stack_pool, &cert_file);
		settings_file_get(db->ssl_set->ssl_client_ca_file,
				  unsafe_data_stack_pool, &ca_file);
		mysql_ssl_set(db->mysql,
			      key_file.path[0] == '\0' ? NULL : key_file.path,
			      cert_file.path[0] == '\0' ? NULL : cert_file.path,
			      ca_file.path[0] == '\0' ? NULL : ca_file.path,
			      (db->ssl_set->ssl_client_ca_dir[0] != '\0' ?
			       db->ssl_set->ssl_client_ca_dir : NULL)
#ifdef HAVE_MYSQL_SSL_CIPHER
			      , db->ssl_set->ssl_cipher_list
#endif
			     );
#ifdef HAVE_MYSQL_SSL_VERIFY_SERVER_CERT
		int ssl_verify_server_cert =
			ssl_set->ssl_client_require_valid_cert ? 1 : 0;

		mysql_options(db->mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
			      (void *)&ssl_verify_server_cert);
#endif
#else
		const char *error = "mysql: SSL support not compiled in "
			"(remove ssl_client_ca_file and ssl_client_ca_dir settings)";
		i_free(_db->last_connect_error);
		_db->last_connect_error = i_strdup(error);
		e_error(_db->event, "%s", error);
		return -1;
#endif
	}

	sql_db_set_state(&db->api, SQL_DB_STATE_CONNECTING);
	e_debug(_db->event, "Connecting");

#ifdef CLIENT_MULTI_RESULTS
	client_flags |= CLIENT_MULTI_RESULTS;
#endif
	/* CLIENT_MULTI_RESULTS allows the use of stored procedures */
	start_time = time(NULL);
	db->connection_opened = TRUE;
	failed = mysql_real_connect(db->mysql, host,
		db->set->user[0] == '\0' ? NULL : db->set->user,
		db->set->password[0] == '\0' ? NULL : db->set->password,
		db->set->dbname, db->set->port,
		unix_socket, client_flags) == NULL;
	secs_used = time(NULL) - start_time;
	if (failed) {
		/* connecting could have taken a while. make sure that any
		   timeouts that get added soon will get a refreshed
		   timestamp. */
		io_loop_time_refresh();

		if (db->api.connect_delay < secs_used)
			db->api.connect_delay = secs_used;
		sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
		e_error(_db->event, "Connect failed to database (%s): %s - "
			"waiting for %u seconds before retry",
			db->set->dbname, mysql_error(db->mysql),
			db->api.connect_delay);
		i_free(_db->last_connect_error);
		_db->last_connect_error = i_strdup(mysql_error(db->mysql));
		sql_disconnect(&db->api);
		return -1;
	} else {
		db->last_success = ioloop_time;
		sql_db_set_state(&db->api, SQL_DB_STATE_IDLE);
		return 1;
	}
}

static void driver_mysql_disconnect(struct sql_db *_db)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	bool was_opened = db->connection_opened;

	/* mysql_close() must run unconditionally, not just when a
	   connection was actually opened: reinitializing the handle below
	   allocates fresh state inside it that needs its own mysql_close()
	   before the next reinit or before the handle is discarded, even
	   if that reinit'd handle never went on to attempt a real
	   connection. Only the "a connection actually finished" bookkeeping
	   below is conditional on was_opened. */
	if (db->mysql != NULL) {
		mysql_close(db->mysql);
		if (!_db->no_reconnect) {
			if (mysql_init(db->mysql) == NULL)
				i_fatal_status(FATAL_OUTOFMEM,
					       "mysql_init() failed");
		}
	}
	sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);

	if (was_opened) {
		db->connection_opened = FALSE;
		sql_connection_log_finished(_db);
	}
}

static struct mysql_db_cache *
driver_mysql_db_cache_find(const struct mysql_settings *set,
			   const struct ssl_settings *ssl_set)
{
	struct mysql_db_cache *cache;

	array_foreach_modifiable(&mysql_db_cache, cache) {
		if (settings_equal(&mysql_setting_parser_info,
				   set, cache->set, NULL) &&
		    (!set->ssl ||
		     settings_equal(&ssl_setting_parser_info,
				    ssl_set, cache->ssl_set, NULL)))
			return cache;
	}
	return NULL;
}

static struct sql_db *
driver_mysql_init_from_set(pool_t pool, struct event *event_parent,
			   const struct mysql_settings *set,
			   const struct ssl_settings *ssl_set)
{
	struct mysql_db *db;

	db = p_new(pool, struct mysql_db, 1);
	db->pool = pool;
	db->api = driver_mysql_db;
	db->api.event = event_create(event_parent);
	db->set = set;
	db->ssl_set = ssl_set;
	event_add_category(db->api.event, &event_category_mysql);
	event_add_str(db->api.event, "sql_driver", "mysql");
	if (set->host[0] != '\0') {
		event_set_append_log_prefix(db->api.event, t_strdup_printf(
			"mysql(%s): ", set->host));
	} else {
		event_set_append_log_prefix(db->api.event, "mysql: ");
	}

	db->mysql = p_new(db->pool, MYSQL, 1);
	if (mysql_init(db->mysql) == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "mysql_init() failed");
	return &db->api;
}

static int
driver_mysql_init_v(struct event *event, struct sql_db **db_r,
		    const char **error_r)
{
	const struct mysql_settings *set;
	const struct ssl_settings *ssl_set = NULL;

	*error_r = NULL;

	if (settings_get(event, &mysql_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;
	if (array_is_empty(&set->sqlpool_hosts)) {
		*error_r = "mysql { .. } named list filter is missing";
		settings_free(set);
		return -1;
	}

	if (set->ssl) {
		if (ssl_client_settings_get(event, &ssl_set, error_r) < 0) {
			settings_free(set);
			return -1;
		}
		/* Verify that inline SSL certs/keys aren't attempted
		   to be used */
		if (ssl_set->ssl_client_key_file[0] != '\0' &&
		    !settings_file_has_path(ssl_set->ssl_client_key_file))
			*error_r = "MySQL doesn't support inline content for ssl_client_key_file";
		else if (ssl_set->ssl_client_cert_file[0] != '\0' &&
			 !settings_file_has_path(ssl_set->ssl_client_cert_file))
			*error_r = "MySQL doesn't support inline content for ssl_client_cert_file";
		else if (ssl_set->ssl_client_ca_file[0] != '\0' &&
			 !settings_file_has_path(ssl_set->ssl_client_ca_file))
			*error_r = "MySQL doesn't support inline content for ssl_client_ca_file";

		if (*error_r != NULL) {
			settings_free(set);
			settings_free(ssl_set);
			return -1;
		}
	}

	if (event_get_ptr(event, SQLPOOL_EVENT_PTR) == NULL) {
		/* See if there is already such a database */
		struct mysql_db_cache *cache =
			driver_mysql_db_cache_find(set, ssl_set);
		if (cache != NULL) {
			settings_free(set);
			settings_free(ssl_set);
		} else {
			/* Use sqlpool for managing multiple connections.
			   Leave an extra reference to it, so it won't be freed
			   while it's still in the cache array. */
			struct sql_db *db =
				driver_sqlpool_init(&driver_mysql_db, event,
						    MYSQL_SQLPOOL_SET_NAME,
						    &set->sqlpool_hosts,
						    set->connection_limit);
			cache = array_append_space(&mysql_db_cache);
			cache->db = db;
			cache->set = set;
			cache->ssl_set = ssl_set;
		}
		sql_ref(cache->db);
		*db_r = cache->db;
		return 0;
	}
	/* We're being initialized by sqlpool - create a real mysql
	 connection. */

	pool_t pool = pool_alloconly_create("mysql driver", 1024);
	*db_r = driver_mysql_init_from_set(pool, event, set, ssl_set);
	event_drop_parent_log_prefixes((*db_r)->event, 1);
	sql_init_common(*db_r);
	return 0;
}

static void driver_mysql_deinit_v(struct sql_db *_db)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);

	_db->no_reconnect = TRUE;
	sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);

	driver_mysql_disconnect(_db);

	settings_free(db->set);
	settings_free(db->ssl_set);
	event_unref(&_db->event);
	array_free(&_db->module_contexts);
	pool_unref(&db->pool);
}

static int driver_mysql_do_query(struct mysql_db *db, const char *query,
				 struct event *event)
{
	int ret, diff;
	struct event_passthrough *e;

	ret = mysql_query(db->mysql, query);
	io_loop_time_refresh();
	e = sql_query_finished_event(&db->api, event, query, ret == 0, &diff);

	if (ret != 0) {
		e->add_int("error_code", mysql_errno(db->mysql));
		e->add_str("error", mysql_error(db->mysql));
		e_debug(e->event(), SQL_QUERY_FINISHED_FMT": %s", query,
			diff, mysql_error(db->mysql));
	} else
		e_debug(e->event(), SQL_QUERY_FINISHED_FMT, query, diff);

	if (ret == 0)
		return 0;

	/* failed */
	switch (mysql_errno(db->mysql)) {
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
		sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
		break;
	default:
		break;
	}
	return -1;
}

static int
driver_mysql_escape_string(struct sql_db *_db, const char *string,
			   const char **output_r, const char **error_r)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	size_t len = strlen(string);
	char *to;

	if (_db->state == SQL_DB_STATE_DISCONNECTED) {
		/* try connecting */
		(void)sql_connect(&db->api);
	}

	if (_db->state == SQL_DB_STATE_DISCONNECTED) {
		*error_r = SQL_ERRSTR_NOT_CONNECTED;
		return -1;
	}

	to = t_buffer_get(len * 2 + 1);
	len = mysql_real_escape_string(db->mysql, to, string, len);
	t_buffer_alloc(len + 1);
	*output_r = to;
	return 0;
}

static void driver_mysql_exec(struct sql_db *_db, const char *query)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	struct event *event = event_create(_db->event);

	(void)driver_mysql_do_query(db, query, event);

	event_unref(&event);
}

static struct sql_result *
driver_mysql_query_s(struct sql_db *_db, const char *query)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	struct mysql_result *result;
	struct event *event;
	int ret;

	result = i_new(struct mysql_result, 1);
	result->api = driver_mysql_result;
	event = event_create(_db->event);

	if (driver_mysql_do_query(db, query, event) < 0) {
		result->api = driver_mysql_error_result;
		result->error = i_strdup(mysql_error(db->mysql));
	} else {
		/* query ok */
		result->affected_rows = mysql_affected_rows(db->mysql);
		result->result = mysql_store_result(db->mysql);
#ifdef CLIENT_MULTI_RESULTS
		/* Because we've enabled CLIENT_MULTI_RESULTS, we need to read
		   (ignore) extra results - there should not be any.
		   ret is: -1 = done, >0 = error, 0 = more results. */
		while ((ret = mysql_next_result(db->mysql)) == 0) ;
#else
		ret = -1;
#endif

		if (ret < 0 &&
		    (result->result != NULL || mysql_errno(db->mysql) == 0)) {
			/* ok */
		} else {
			/* failed */
			if (result->result != NULL)
				mysql_free_result(result->result);
			result->result = NULL;
			result->api = driver_mysql_error_result;
			result->error = i_strdup(mysql_error(db->mysql));
		}
	}

	result->api.db = _db;
	result->api.refcount = 1;
	result->api.event = event;
	return &result->api;
}

static void driver_mysql_result_free(struct sql_result *_result)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);

	i_assert(_result != &sql_not_connected_result);
	if (_result->callback)
		return;

	if (result->result != NULL)
		mysql_free_result(result->result);
	if (result->stmt != NULL) {
		mysql_stmt_close(result->stmt);
		result->stmt = NULL;
	}
	i_free(result->result_binds);
	i_free(result->result_lengths);
	i_free(result->result_is_null);
	i_free(result->values);
	i_free(result->error);
	event_unref(&_result->event);
	pool_unref(&result->result_pool);
	i_free(result);
}

static int driver_mysql_result_stmt_next_row(struct mysql_result *result)
{
	struct mysql_db *db = container_of(result->api.db, struct mysql_db, api);

	if (result->result == NULL) {
		/* nothing to return */
		return 0;
	}

	int ret = mysql_stmt_fetch(result->stmt);

	/* MYSQL_DATA_TRUNCATED: expected with NULL-buffered result binds */
	if (ret == 0 || ret == MYSQL_DATA_TRUNCATED) {
		/* prepopulate field information */
		(void)result->api.v.get_fields_count(&result->api);
		ret = 1;
	} else if (ret == MYSQL_NO_DATA) {
		if (result->result != NULL)
			mysql_free_result(result->result);
		result->result = NULL;
		mysql_stmt_free_result(result->stmt);
		while ((ret = mysql_stmt_next_result(result->stmt)) == 0)
			mysql_stmt_free_result(result->stmt);
		if (ret == -1) {
			/* successfully looped through all results */
			ret = 0;
		}
	} else {
		ret = mysql_stmt_errno(result->stmt);
	}

	switch (ret) {
	case 0:
	case 1:
		break;
	case CR_OUT_OF_MEMORY:
		i_fatal_status(FATAL_OUTOFMEM,
			       "mysql_stmt_fetch(): Out of memory");
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
		sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
		/* fall-through */
	default:
		result->api.failed = TRUE;
		result->error = i_strdup(mysql_stmt_error(result->stmt));
		return -1;
	}

	db->last_success = ioloop_time;
	return ret;
}

static int driver_mysql_result_next_row(struct sql_result *_result)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	struct mysql_db *db = container_of(_result->db, struct mysql_db, api);
	int ret;

	/* clear previously returned results */
	if (result->result_pool != NULL)
		p_clear(result->result_pool);

	if (result->stmt != NULL)
		return driver_mysql_result_stmt_next_row(result);

	if (result->result == NULL) {
		/* no results */
		return 0;
	}

	result->row = mysql_fetch_row(result->result);
	if (result->row != NULL)
		ret = 1;
	else
		ret = mysql_errno(db->mysql);

	switch (ret) {
	case 0:
	case 1:
		break;
	case CR_OUT_OF_MEMORY:
		i_fatal_status(FATAL_OUTOFMEM, "mysql_fetch_row(): Out of memory");
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
		sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
		/* fall-through */
	default:
		result->api.failed = TRUE;
		result->error = i_strdup(mysql_error(db->mysql));
		return -1;
	}

	db->last_success = ioloop_time;
	return ret;
}

static void driver_mysql_result_fetch_fields(struct mysql_result *result)
{
	if (result->fields != NULL)
		return;

	result->fields_count = mysql_num_fields(result->result);
	result->fields = mysql_fetch_fields(result->result);
}

static unsigned int
driver_mysql_result_get_fields_count(struct sql_result *_result)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);

	driver_mysql_result_fetch_fields(result);
	return result->fields_count;
}

static const char *
driver_mysql_result_get_field_name(struct sql_result *_result, unsigned int idx)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);

	driver_mysql_result_fetch_fields(result);
	i_assert(idx < result->fields_count);
	return result->fields[idx].name;
}

static int driver_mysql_result_find_field(struct sql_result *_result,
					  const char *field_name)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	unsigned int i;

	driver_mysql_result_fetch_fields(result);
	for (i = 0; i < result->fields_count; i++) {
		if (strcmp(result->fields[i].name, field_name) == 0)
			return i;
	}
	return -1;
}

static void *
driver_mysql_stmt_fetch_field(struct mysql_result *result, unsigned int idx,
			      enum enum_field_types type,
			      size_t *len_r, bool *is_null_r)
{
	/* result_lengths[] and result_is_null[] are already populated by
	   mysql_stmt_fetch() for the current row - the column definition's
	   f->length is only the maximum possible width (e.g. 4GB for a
	   LONGBLOB) and would grossly oversize this allocation. They are
	   allocated together whenever a successful statement execution
	   returns result columns, which is the only case this is called
	   from. */
	i_assert(result->result_lengths != NULL);
	size_t len = result->result_lengths[idx];
	MYSQL_BIND b = {
		.buffer_type = type,
		.length = &len,
	};

	if (result->result_pool == NULL)
		result->result_pool = pool_alloconly_create("result pool", 256);
	b.buffer = p_malloc(result->result_pool, len + 1);
	b.buffer_length = len;

	if (mysql_stmt_fetch_column(result->stmt, &b, idx, 0) != 0)
		i_panic("mysql_stmt_fetch_column(%u) failed: %s",
			idx, mysql_stmt_error(result->stmt));
	((char *)b.buffer)[len] = '\0';

	*len_r = len;
	*is_null_r = result->result_is_null[idx] != 0;
	return b.buffer;
}

static const char *
driver_mysql_result_get_field_value(struct sql_result *_result,
				    unsigned int idx)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	i_assert(idx < result->fields_count);

	if (result->stmt != NULL) {
		size_t len;
		bool is_null;
		char *buf = driver_mysql_stmt_fetch_field(
			result, idx, MYSQL_TYPE_STRING, &len, &is_null);
		if (is_null)
			return NULL;
		return buf;
	}

	return (const char *)result->row[idx];
}

static const unsigned char *
driver_mysql_result_get_field_value_binary(struct sql_result *_result,
					   unsigned int idx, size_t *size_r)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	i_assert(idx < result->fields_count);

	if (result->stmt != NULL) {
		bool is_null;
		void *buf = driver_mysql_stmt_fetch_field(
			result, idx, MYSQL_TYPE_BLOB, size_r, &is_null);
		if (is_null) {
			*size_r = 0;
			return NULL;
		}
		return buf;
	}

	unsigned long *lengths = mysql_fetch_lengths(result->result);
	*size_r = lengths[idx];
	return (const void *)result->row[idx];
}

static const char *
driver_mysql_result_find_field_value(struct sql_result *result,
				     const char *field_name)
{
	int idx;

	idx = driver_mysql_result_find_field(result, field_name);
	if (idx < 0)
		return NULL;
	return driver_mysql_result_get_field_value(result, idx);
}

static const char *const *
driver_mysql_result_get_values(struct sql_result *_result)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);

	if (result->stmt != NULL) {
		if (result->values == NULL) {
			driver_mysql_result_fetch_fields(result);
			result->values = i_new(const char *,
					       result->fields_count);
		}
		/* @UNSAFE */
		for (unsigned int i = 0; i < result->fields_count; i++) {
			result->values[i] =
				driver_mysql_result_get_field_value(&result->api, i);
		}
		return (const char *const *)result->values;
	}

	return (const char *const *)result->row;
}

static const char *driver_mysql_result_get_error(struct sql_result *_result)
{
	struct mysql_db *db = container_of(_result->db, struct mysql_db, api);
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	const char *errstr;
	unsigned int idle_time;
	int err;

	if (result->error != NULL)
		return result->error;

	err = mysql_errno(db->mysql);
	errstr = mysql_error(db->mysql);
	if ((err == CR_SERVER_GONE_ERROR || err == CR_SERVER_LOST) &&
	    db->last_success != 0) {
		idle_time = ioloop_time - db->last_success;
		errstr = t_strdup_printf("%s (idled for %u secs)",
					 errstr, idle_time);
	}
	return errstr;
}

static struct sql_transaction_context *
driver_mysql_transaction_begin(struct sql_db *db)
{
	struct mysql_transaction_context *ctx;

	ctx = i_new(struct mysql_transaction_context, 1);
	ctx->ctx.db = db;
	ctx->query_pool = pool_alloconly_create("mysql transaction", 1024);
	ctx->ctx.event = event_create(db->event);
	return &ctx->ctx;
}

static int
execute_statement(struct mysql_statement *stmt, struct mysql_result **result_r)
{
	struct mysql_db *db = container_of(stmt->api.db, struct mysql_db, api);
	struct mysql_result *result = i_new(struct mysql_result, 1);
	const char *query_template = stmt->api.query_template;
	int ret;

	if (db->api.state == SQL_DB_STATE_DISCONNECTED &&
	    driver_mysql_connect(&db->api) < 0) {
		result->api = driver_mysql_error_result;
		result->error = i_strdup("Not connected to database");
		ret = -1;
	} else {
		stmt->stmt = mysql_stmt_init(db->mysql);
		if (stmt->stmt == NULL)
			i_fatal_status(FATAL_OUTOFMEM,
				       "mysql_stmt_init(): Out of memory");
		if (mysql_stmt_prepare(stmt->stmt, query_template,
					strlen(query_template)) != 0) {
			/* mysql_stmt_prepare() only reports success/failure -
			   the error code comes from mysql_stmt_errno().
			   libmysqlclient and MariaDB Connector/C set a
			   nonzero errno on failure; if one does not, fail
			   the statement rather than executing an unprepared
			   one. */
			ret = mysql_stmt_errno(stmt->stmt);
			if (ret == CR_OUT_OF_MEMORY) {
				i_fatal_status(FATAL_OUTOFMEM,
					       "mysql_stmt_prepare(%s): Out of memory",
					       query_template);
			}
			if (ret == 0) {
				result->api = driver_mysql_error_result;
				result->error = i_strdup(
					"mysql_stmt_prepare() failed without an error code");
				ret = -1;
			}
		} else if (array_count(&stmt->binds) !=
			   mysql_stmt_param_count(stmt->stmt)) {
			result->api = driver_mysql_error_result;
			result->error = i_strdup_printf(
				"Expected %lu parameters, got %u",
				mysql_stmt_param_count(stmt->stmt),
				array_count(&stmt->binds));
			ret = -1;
		} else
			ret = 0;
	}

	if (ret == 0) {
		if (array_count(&stmt->binds) > 0) {
			MYSQL_BIND *binds =
				array_front_modifiable(&stmt->binds);
			if (mysql_stmt_bind_param(stmt->stmt, binds) != 0)
				ret = mysql_stmt_errno(stmt->stmt);
		}
		if (ret != 0)
			; /* binding already failed */
		else if (mysql_stmt_execute(stmt->stmt) != 0 ||
			 mysql_stmt_store_result(stmt->stmt) != 0)
			ret = mysql_stmt_errno(stmt->stmt);
	}

	switch (ret) {
	case -1:
		break;
	case 0:
		result->api = driver_mysql_result;
		result->affected_rows = mysql_stmt_affected_rows(stmt->stmt);
		result->result = mysql_stmt_result_metadata(stmt->stmt);
		if (result->result != NULL) {
			unsigned int count = mysql_num_fields(result->result);
			result->result_binds = i_new(MYSQL_BIND, count);
			result->result_lengths = i_new(unsigned long, count);
			result->result_is_null = i_new(my_bool, count);
			for (unsigned int i = 0; i < count; i++) {
				result->result_binds[i].buffer_type =
					MYSQL_TYPE_STRING;
				result->result_binds[i].length =
					&result->result_lengths[i];
				result->result_binds[i].is_null =
					&result->result_is_null[i];
			}
			if (mysql_stmt_bind_result(stmt->stmt,
						   result->result_binds) != 0) {
				result->api = driver_mysql_error_result;
				result->error = i_strdup(
					mysql_stmt_error(stmt->stmt));
				ret = -1;
			}
		}
		break;
	case CR_OUT_OF_MEMORY:
		i_fatal_status(FATAL_OUTOFMEM,
			       "mysql_stmt_execute(%s): Out of memory",
			       stmt->api.query_template);
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
		sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
		/* fall-through */
	default:
		result->api = driver_mysql_error_result;
		result->error = i_strdup(mysql_stmt_error(stmt->stmt));
		break;
	}
	result->api.db = &db->api;
	result->api.refcount = 1;
	/* Transfer stmt ownership so driver_mysql_result_free() closes it. */
	result->stmt = stmt->stmt;
	stmt->stmt = NULL;
	*result_r = result;

	return ret;
}

static struct sql_result *
driver_mysql_execute_stmt(struct mysql_statement *stmt)
{
	struct mysql_db *db = container_of(stmt->api.db, struct mysql_db, api);
	struct mysql_result *result;
	struct event *event = event_create(db->api.event);
	const char *query = sql_statement_get_log_query(&stmt->api);
	int ret = execute_statement(stmt, &result);

	io_loop_time_refresh();
	int diff;
	struct event_passthrough *e =
		sql_query_finished_event(&db->api, event, query,
					 ret == 0, &diff);
	if (ret != 0) {
		e->add_int("error_code", ret);
		e->add_str("error", result->error);
		e_debug(e->event(), SQL_QUERY_FINISHED_FMT": %s",
			query, diff, result->error);
	} else {
		e_debug(e->event(), SQL_QUERY_FINISHED_FMT, query, diff);
	}

	result->api.event = event;
	pool_unref(&stmt->api.pool);
	return &result->api;
}

static int ATTR_NULL(3)
transaction_send_query(struct mysql_transaction_context *ctx,
		       struct sql_transaction_query *query,
		       unsigned int *affected_rows_r)
{
	struct sql_result *_result;
	struct mysql_statement *stmt;
	int ret = 0;

	if (ctx->failed)
		return -1;

	if (query->stmt != NULL) {
		stmt = container_of(query->stmt, struct mysql_statement, api);
		_result = driver_mysql_execute_stmt(stmt);
	} else
		_result = sql_query_s(ctx->ctx.db, query->query);

	if (sql_result_next_row(_result) < 0) {
		ctx->error = p_strdup(ctx->query_pool,
				      sql_result_get_error(_result));
		ctx->failed = TRUE;
		ret = -1;
	} else if (affected_rows_r != NULL) {
		struct mysql_result *result =
			container_of(_result, struct mysql_result, api);

		i_assert(result->affected_rows != (my_ulonglong)-1);
		*affected_rows_r = result->affected_rows;
	}
	sql_result_unref(_result);
	return ret;
}

static int driver_mysql_try_commit_s(struct mysql_transaction_context *ctx)
{
	struct sql_transaction_context *_ctx = &ctx->ctx;
	struct sql_transaction_query query = {
		.query = "BEGIN",
	};
	bool multi = _ctx->head != NULL && _ctx->head->next != NULL;

	/* wrap in BEGIN/COMMIT only if transaction has multiple statements. */
	if (multi && transaction_send_query(ctx, &query, NULL) < 0) {
		if (_ctx->db->state != SQL_DB_STATE_DISCONNECTED)
			return -1;
		/* we got disconnected, retry */
		return 0;
	} else if (multi) {
		ctx->commit_started = TRUE;
	}

	while (_ctx->head != NULL) {
		if (transaction_send_query(ctx, _ctx->head,
					   _ctx->head->affected_rows) < 0)
			return -1;
		_ctx->head = _ctx->head->next;
	}

	query.query = "COMMIT";
	if (multi && transaction_send_query(ctx, &query, NULL) < 0)
		return -1;
	return 1;
}

static int
driver_mysql_transaction_commit_s(struct sql_transaction_context *_ctx,
				  const char **error_r)
{
	struct mysql_transaction_context *ctx =
		container_of(_ctx, struct mysql_transaction_context, ctx);
	struct mysql_db *db = container_of(_ctx->db, struct mysql_db, api);
	int ret = 1;

	*error_r = NULL;

	if (_ctx->head != NULL) {
		ret = driver_mysql_try_commit_s(ctx);
		*error_r = t_strdup(ctx->error);
		if (ret == 0) {
			e_info(db->api.event, "Disconnected from database, "
			       "retrying commit");
			if (sql_connect(_ctx->db) >= 0) {
				ctx->failed = FALSE;
				ret = driver_mysql_try_commit_s(ctx);
			}
		}
	}

	if (ret > 0)
		ctx->committed = TRUE;

	sql_transaction_rollback(&_ctx);
	return ret <= 0 ? -1 : 0;
}

static void
driver_mysql_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct mysql_transaction_context *ctx =
		container_of(_ctx, struct mysql_transaction_context, ctx);
	struct sql_transaction_query query = {
		.query = "ROLLBACK",
	};

	if (ctx->failed) {
		bool rolledback = FALSE;
		const char *orig_error = t_strdup(ctx->error);
		if (ctx->commit_started) {
			/* reset failed flag so ROLLBACK is actually sent.
			   otherwise, transaction_send_query() will return
			   without trying to send the query. */
			ctx->failed = FALSE;
			if (transaction_send_query(ctx, &query, NULL) < 0)
				e_debug(event_create_passthrough(_ctx->event)->
					add_str("error", ctx->error)->event(),
					"Rollback failed: %s", ctx->error);
			else
				rolledback = TRUE;
		}
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", orig_error)->event(),
			"Transaction failed: %s%s", orig_error,
			rolledback ? " - Rolled back" : "");
	} else if (ctx->committed)
		e_debug(sql_transaction_finished_event(_ctx)->event(),
			"Transaction committed");
	else
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", "Rolled back")->event(),
			 "Transaction rolled back");

	event_unref(&ctx->ctx.event);
	pool_unref(&ctx->query_pool);
	i_free(ctx);
}

static void
driver_mysql_update(struct sql_transaction_context *_ctx, const char *query,
		    unsigned int *affected_rows)
{
	struct mysql_transaction_context *ctx =
		container_of(_ctx, struct mysql_transaction_context, ctx);

	sql_transaction_add_query(&ctx->ctx, ctx->query_pool,
				  query, affected_rows);
}

static const char *
driver_mysql_escape_blob(struct sql_db *_db ATTR_UNUSED,
			 const unsigned char *data, size_t size)
{
	string_t *str = t_str_new(128);

	str_append(str, "X'");
	binary_to_hex_append(str, data, size);
	str_append_c(str, '\'');
	return str_c(str);
}

static struct sql_statement *
driver_mysql_statement_init(struct sql_db *_db, const char *query_template)
{
	pool_t pool = pool_alloconly_create("mysql statement", 1024);
	struct mysql_statement *stmt = p_new(pool, struct mysql_statement, 1);
	stmt->api.db = _db;
	stmt->api.pool = pool;
	stmt->api.query_template = p_strdup(pool, query_template);
	p_array_init(&stmt->binds, pool, 4);
	return &stmt->api;
}

static void driver_mysql_statement_abort(struct sql_statement *_stmt)
{
	struct mysql_statement *stmt = container_of(_stmt, struct mysql_statement, api);
	if (stmt->stmt != NULL)
		mysql_stmt_close(stmt->stmt);
}

static void
driver_mysql_statement_bind_str(struct sql_statement *_stmt,
				unsigned int column_idx, const char *value)
{
	struct mysql_statement *stmt = container_of(_stmt, struct mysql_statement, api);
	MYSQL_BIND *bind = array_idx_get_space(&stmt->binds, column_idx);
	my_bool *is_null = p_new(stmt->api.pool, my_bool, 1);
	*is_null = (value == NULL ? 1 : 0);
	bind->is_null = is_null;
	bind->buffer_type = MYSQL_TYPE_STRING;
	bind->buffer = p_strdup(stmt->api.pool, value);
	unsigned long *len = p_new(stmt->api.pool, unsigned long, 1);
	*len = value != NULL ? strlen(value) : 0;
	bind->buffer_length = *len;
	bind->length = len;
}

static void
driver_mysql_statement_bind_uuid(struct sql_statement *_stmt,
				 unsigned int column_idx, const guid_128_t value)
{
	const char *guid = guid_128_to_uuid_string(value, FORMAT_RECORD);
	driver_mysql_statement_bind_str(_stmt, column_idx, guid);
}

static void
driver_mysql_statement_bind_binary(struct sql_statement *_stmt,
				   unsigned int column_idx, const void *value,
				   size_t value_len)
{
	struct mysql_statement *stmt = container_of(_stmt, struct mysql_statement, api);
	i_assert(value != NULL || value_len == 0);
	MYSQL_BIND *bind = array_idx_get_space(&stmt->binds, column_idx);
	bind->buffer_type = MYSQL_TYPE_BLOB;
	/* p_memdup() panics on a zero-size allocation, so a zero-length
	   value binds the shared empty pointer instead of allocating. */
	bind->buffer = value_len == 0 ?
		(void *)uchar_empty_ptr : p_memdup(stmt->api.pool, value, value_len);
	unsigned long *len = p_new(stmt->api.pool, unsigned long, 1);
	*len = value_len;
	bind->buffer_length = *len;
	bind->length = len;
}

static void
driver_mysql_statement_bind_int64(struct sql_statement *_stmt,
				  unsigned int column_idx, int64_t value)
{
	struct mysql_statement *stmt = container_of(_stmt, struct mysql_statement, api);
	MYSQL_BIND *bind = array_idx_get_space(&stmt->binds, column_idx);
	bind->buffer_type = MYSQL_TYPE_LONGLONG;
	bind->buffer = p_memdup(stmt->api.pool, &value, sizeof(value));
	unsigned long *len = p_new(stmt->api.pool, unsigned long, 1);
	*len = sizeof(value);
	bind->buffer_length = *len;
	bind->length = len;
}

static void
driver_mysql_statement_bind_double(struct sql_statement *_stmt,
				   unsigned int column_idx, double value)
{
	struct mysql_statement *stmt = container_of(_stmt, struct mysql_statement, api);
	MYSQL_BIND *bind = array_idx_get_space(&stmt->binds, column_idx);
	bind->buffer_type = MYSQL_TYPE_DOUBLE;
	bind->buffer = p_memdup(stmt->api.pool, &value, sizeof(value));
	unsigned long *len = p_new(stmt->api.pool, unsigned long, 1);
	*len = sizeof(value);
	bind->buffer_length = *len;
	bind->length = len;
}

static struct sql_result *
driver_mysql_statement_query_s(struct sql_statement *_stmt)
{
	struct mysql_statement *stmt =
		container_of(_stmt, struct mysql_statement, api);
	return driver_mysql_execute_stmt(stmt);
}

static void driver_mysql_update_stmt(struct sql_transaction_context *_ctx,
				     struct sql_statement *_stmt,
				     unsigned int *affected_rows)
{
	struct mysql_transaction_context *ctx =
		container_of(_ctx, struct mysql_transaction_context, ctx);

	/* ensure statement is free'd when transaction is free'd */
	pool_add_external_ref(ctx->query_pool, _stmt->pool);
	pool_unref(&_stmt->pool);

	sql_transaction_add_stmt(&ctx->ctx, ctx->query_pool,
				 _stmt, affected_rows);
}

const struct sql_db driver_mysql_db = {
	.name = "mysql",
	.flags = SQL_DB_FLAG_BLOCKING | SQL_DB_FLAG_POOLED |
		 SQL_DB_FLAG_ON_DUPLICATE_KEY,

	.v = {
		.init = driver_mysql_init_v,
		.deinit = driver_mysql_deinit_v,
		.connect = driver_mysql_connect,
		.disconnect = driver_mysql_disconnect,
		.escape_string = driver_mysql_escape_string,
		.exec = driver_mysql_exec,
		.query_s = driver_mysql_query_s,

		.transaction_begin = driver_mysql_transaction_begin,
		.transaction_commit_s = driver_mysql_transaction_commit_s,
		.transaction_rollback = driver_mysql_transaction_rollback,

		.update = driver_mysql_update,

		.escape_blob = driver_mysql_escape_blob,

		.statement_init = driver_mysql_statement_init,
		.statement_abort = driver_mysql_statement_abort,

		.statement_bind_str = driver_mysql_statement_bind_str,
		.statement_bind_binary = driver_mysql_statement_bind_binary,
		.statement_bind_int64 = driver_mysql_statement_bind_int64,
		.statement_bind_double = driver_mysql_statement_bind_double,
		.statement_bind_uuid = driver_mysql_statement_bind_uuid,
		.statement_query_s = driver_mysql_statement_query_s,

		.update_stmt = driver_mysql_update_stmt,
	}
};

const struct sql_result driver_mysql_result = {
	.v = {
		.free = driver_mysql_result_free,
		.next_row = driver_mysql_result_next_row,
		.get_fields_count = driver_mysql_result_get_fields_count,
		.get_field_name = driver_mysql_result_get_field_name,
		.find_field = driver_mysql_result_find_field,
		.get_field_value = driver_mysql_result_get_field_value,
		.get_field_value_binary = driver_mysql_result_get_field_value_binary,
		.find_field_value = driver_mysql_result_find_field_value,
		.get_values = driver_mysql_result_get_values,
		.get_error = driver_mysql_result_get_error,
	}
};

const struct sql_result driver_mysql_error_result = {
	.v = {
		.free = driver_mysql_result_free,
		.next_row = sql_result_error_next_row,
		.get_error = driver_mysql_result_get_error,
		.get_fields_count = sql_result_error_get_fields_count,
		.get_field_name = sql_result_error_get_field_name,
		.find_field = sql_result_error_find_field,
		.get_field_value = sql_result_error_get_field_value,
		.get_field_value_binary = sql_result_error_get_field_value_binary,
		.find_field_value = sql_result_error_find_field_value,
		.get_values = sql_result_error_get_values,
		.more = sql_result_error_more,
	},
	.failed_try_retry = TRUE
};

const char *driver_mysql_version = DOVECOT_ABI_VERSION;

void driver_mysql_init(void)
{
	i_array_init(&mysql_db_cache, 4);
	sql_driver_register(&driver_mysql_db);
}

void driver_mysql_deinit(void)
{
	struct mysql_db_cache *cache;

	if (!array_is_created(&mysql_db_cache))
		return;

	array_foreach_modifiable(&mysql_db_cache, cache) {
		settings_free(cache->set);
		settings_free(cache->ssl_set);
		sql_unref(&cache->db);
	}
	array_free(&mysql_db_cache);
	sql_driver_unregister(&driver_mysql_db);
	mysql_library_end();
}

#endif
