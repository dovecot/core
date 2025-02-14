/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-binary.h"
#include "str.h"
#include "net.h"
#include "time-util.h"
#include "settings.h"
#include "settings-parser.h"
#include "settings.h"
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
};

struct mysql_result {
	struct sql_result api;

	MYSQL_RES *result;
	MYSQL_ROW row;

	MYSQL_FIELD *fields;
	unsigned int fields_count;

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
	if (db->mysql != NULL)
		mysql_close(db->mysql);
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

	sql_connection_log_finished(_db);
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

static const char *
driver_mysql_escape_string(struct sql_db *_db, const char *string)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	size_t len = strlen(string);
	char *to;

	if (_db->state == SQL_DB_STATE_DISCONNECTED) {
		/* try connecting */
		(void)sql_connect(&db->api);
	}

	if (_db->state == SQL_DB_STATE_DISCONNECTED) {
		/* FIXME: we don't have a valid connection, so fallback
		   to using default escaping. the next query will most
		   likely fail anyway so it shouldn't matter that much
		   what we return here.. Anyway, this API needs
		   changing so that the escaping function could already
		   fail the query reliably. */
		to = t_buffer_get(len * 2 + 1);
		len = mysql_escape_string(to, string, len);
		t_buffer_alloc(len + 1);
		return to;
	}

	to = t_buffer_get(len * 2 + 1);
	len = mysql_real_escape_string(db->mysql, to, string, len);
	t_buffer_alloc(len + 1);
	return to;
}

static void driver_mysql_exec(struct sql_db *_db, const char *query)
{
	struct mysql_db *db = container_of(_db, struct mysql_db, api);
	struct event *event = event_create(_db->event);

	(void)driver_mysql_do_query(db, query, event);

	event_unref(&event);
}

static void driver_mysql_query(struct sql_db *db, const char *query,
			       sql_query_callback_t *callback, void *context)
{
	struct sql_result *result;

	result = sql_query_s(db, query);
	result->callback = TRUE;
	callback(result, context);
	result->callback = FALSE;
	sql_result_unref(result);
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

	if (driver_mysql_do_query(db, query, event) < 0)
		result->api = driver_mysql_error_result;
	else {
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
			result->api = driver_mysql_error_result;
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
	event_unref(&_result->event);
	i_free(result);
}

static int driver_mysql_result_next_row(struct sql_result *_result)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	struct mysql_db *db = container_of(_result->db, struct mysql_db, api);
	int ret;

	if (result->result == NULL) {
		/* no results */
		return 0;
	}

	result->row = mysql_fetch_row(result->result);
	if (result->row != NULL)
		ret = 1;
	else {
		if (mysql_errno(db->mysql) != 0)
			return -1;
		ret = 0;
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

static const char *
driver_mysql_result_get_field_value(struct sql_result *_result,
				    unsigned int idx)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);

	return (const char *)result->row[idx];
}

static const unsigned char *
driver_mysql_result_get_field_value_binary(struct sql_result *_result,
					   unsigned int idx, size_t *size_r)
{
	struct mysql_result *result =
		container_of(_result, struct mysql_result, api);
	unsigned long *lengths;

	lengths = mysql_fetch_lengths(result->result);

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

	return (const char *const *)result->row;
}

static const char *driver_mysql_result_get_error(struct sql_result *_result)
{
	struct mysql_db *db = container_of(_result->db, struct mysql_db, api);
	const char *errstr;
	unsigned int idle_time;
	int err;

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

static void
driver_mysql_transaction_commit(struct sql_transaction_context *ctx,
				sql_commit_callback_t *callback, void *context)
{
	struct sql_commit_result result;
	const char *error;

	i_zero(&result);
	if (sql_transaction_commit_s(&ctx, &error) < 0)
		result.error = error;
	callback(&result, context);
}

static int ATTR_NULL(3)
transaction_send_query(struct mysql_transaction_context *ctx, const char *query,
		       unsigned int *affected_rows_r)
{
	struct sql_result *_result;
	int ret = 0;

	if (ctx->failed)
		return -1;

	_result = sql_query_s(ctx->ctx.db, query);
	if (sql_result_next_row(_result) < 0) {
		ctx->error = sql_result_get_error(_result);
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
	bool multi = _ctx->head != NULL && _ctx->head->next != NULL;

	/* wrap in BEGIN/COMMIT only if transaction has multiple statements. */
	if (multi && transaction_send_query(ctx, "BEGIN", NULL) < 0) {
		if (_ctx->db->state != SQL_DB_STATE_DISCONNECTED)
			return -1;
		/* we got disconnected, retry */
		return 0;
	} else if (multi) {
		ctx->commit_started = TRUE;
	}

	while (_ctx->head != NULL) {
		if (transaction_send_query(ctx, _ctx->head->query,
					   _ctx->head->affected_rows) < 0)
			return -1;
		_ctx->head = _ctx->head->next;
	}
	if (multi && transaction_send_query(ctx, "COMMIT", NULL) < 0)
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

	if (ctx->failed) {
		bool rolledback = FALSE;
		const char *orig_error = t_strdup(ctx->error);
		if (ctx->commit_started) {
			/* reset failed flag so ROLLBACK is actually sent.
			   otherwise, transaction_send_query() will return
			   without trying to send the query. */
			ctx->failed = FALSE;
			if (transaction_send_query(ctx, "ROLLBACK", NULL) < 0)
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
		.query = driver_mysql_query,
		.query_s = driver_mysql_query_s,

		.transaction_begin = driver_mysql_transaction_begin,
		.transaction_commit = driver_mysql_transaction_commit,
		.transaction_commit_s = driver_mysql_transaction_commit_s,
		.transaction_rollback = driver_mysql_transaction_rollback,

		.update = driver_mysql_update,

		.escape_blob = driver_mysql_escape_blob,
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

static int
driver_mysql_result_error_next_row(struct sql_result *result ATTR_UNUSED)
{
	return -1;
}

const struct sql_result driver_mysql_error_result = {
	.v = {
		.free = driver_mysql_result_free,
		.next_row = driver_mysql_result_error_next_row,
		.get_error = driver_mysql_result_get_error,
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

	array_foreach_modifiable(&mysql_db_cache, cache) {
		settings_free(cache->set);
		settings_free(cache->ssl_set);
		sql_unref(&cache->db);
	}
	array_free(&mysql_db_cache);
	sql_driver_unregister(&driver_mysql_db);
}

#endif
