/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-binary.h"
#include "str.h"
#include "net.h"
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

struct mysql_db {
	struct sql_db api;

	pool_t pool;
	const char *user, *password, *dbname, *host, *unix_socket;
	const char *ssl_cert, *ssl_key, *ssl_ca, *ssl_ca_path, *ssl_cipher;
	int ssl_verify_server_cert;
	const char *option_file, *option_group;
	in_port_t port;
	unsigned int client_flags;
	unsigned int connect_timeout, read_timeout, write_timeout;
	time_t last_success;

	MYSQL *mysql;
	unsigned int next_query_connection;

	bool ssl_set:1;
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
};

extern const struct sql_db driver_mysql_db;
extern const struct sql_result driver_mysql_result;
extern const struct sql_result driver_mysql_error_result;

static const char *mysql_prefix(struct mysql_db *db)
{
	return db->host == NULL ? "mysql" :
		t_strdup_printf("mysql(%s)", db->host);
}

static int driver_mysql_connect(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	const char *unix_socket, *host;
	unsigned long client_flags = db->client_flags;
	unsigned int secs_used;
	time_t start_time;
	bool failed;

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	sql_db_set_state(&db->api, SQL_DB_STATE_CONNECTING);

	if (mysql_init(db->mysql) == NULL)
		i_fatal("mysql_init() failed");

	if (db->host == NULL) {
		/* assume option_file overrides the host, or if not we'll just
		   connect to localhost */
		unix_socket = NULL;
		host = NULL;
	} else if (*db->host == '/') {
		unix_socket = db->host;
		host = NULL;
	} else {
		unix_socket = NULL;
		host = db->host;
	}

	if (db->option_file != NULL) {
		mysql_options(db->mysql, MYSQL_READ_DEFAULT_FILE,
			      db->option_file);
	}

	mysql_options(db->mysql, MYSQL_OPT_CONNECT_TIMEOUT, &db->connect_timeout);
	mysql_options(db->mysql, MYSQL_OPT_READ_TIMEOUT, &db->read_timeout);
	mysql_options(db->mysql, MYSQL_OPT_WRITE_TIMEOUT, &db->write_timeout);
	mysql_options(db->mysql, MYSQL_READ_DEFAULT_GROUP,
		      db->option_group != NULL ? db->option_group : "client");

	if (!db->ssl_set && (db->ssl_ca != NULL || db->ssl_ca_path != NULL)) {
#ifdef HAVE_MYSQL_SSL
		mysql_ssl_set(db->mysql, db->ssl_key, db->ssl_cert,
			      db->ssl_ca, db->ssl_ca_path
#ifdef HAVE_MYSQL_SSL_CIPHER
			      , db->ssl_cipher
#endif
			     );
#ifdef HAVE_MYSQL_SSL_VERIFY_SERVER_CERT
		mysql_options(db->mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
			      (void *)&db->ssl_verify_server_cert);
#endif
		db->ssl_set = TRUE;
#else
		i_fatal("mysql: SSL support not compiled in "
			"(remove ssl_ca and ssl_ca_path settings)");
#endif
	}

#ifdef CLIENT_MULTI_RESULTS
	client_flags |= CLIENT_MULTI_RESULTS;
#endif
	/* CLIENT_MULTI_RESULTS allows the use of stored procedures */
	start_time = time(NULL);
	failed = mysql_real_connect(db->mysql, host, db->user, db->password,
				    db->dbname, db->port, unix_socket,
				    client_flags) == NULL;
	secs_used = time(NULL) - start_time;
	if (failed) {
		/* connecting could have taken a while. make sure that any
		   timeouts that get added soon will get a refreshed
		   timestamp. */
		io_loop_time_refresh();

		if (db->api.connect_delay < secs_used)
			db->api.connect_delay = secs_used;
		sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
		i_error("%s: Connect failed to database (%s): %s - "
			"waiting for %u seconds before retry",
			mysql_prefix(db), db->dbname,
			mysql_error(db->mysql), db->api.connect_delay);
		return -1;
	} else {
		db->last_success = ioloop_time;
		sql_db_set_state(&db->api, SQL_DB_STATE_IDLE);
		return 1;
	}
}

static void driver_mysql_disconnect(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	mysql_close(db->mysql);
}

static int driver_mysql_parse_connect_string(struct mysql_db *db,
					     const char *connect_string,
					     const char **error_r)
{
	const char *const *args, *name, *value;
	const char **field;

	db->ssl_cipher = "HIGH";
	db->ssl_verify_server_cert = 1;
	db->connect_timeout = SQL_CONNECT_TIMEOUT_SECS;
	db->read_timeout = MYSQL_DEFAULT_READ_TIMEOUT_SECS;
	db->write_timeout = MYSQL_DEFAULT_WRITE_TIMEOUT_SECS;

	args = t_strsplit_spaces(connect_string, " ");
	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL) {
			*error_r = t_strdup_printf("Missing value in connect string: %s",
						   *args);
			return -1;
		}
		name = t_strdup_until(*args, value);
		value++;

		field = NULL;
		if (strcmp(name, "host") == 0 ||
		    strcmp(name, "hostaddr") == 0)
			field = &db->host;
		else if (strcmp(name, "user") == 0)
			field = &db->user;
		else if (strcmp(name, "password") == 0)
			field = &db->password;
		else if (strcmp(name, "dbname") == 0)
			field = &db->dbname;
		else if (strcmp(name, "port") == 0) {
			if (net_str2port(value, &db->port) < 0) {
				*error_r = t_strdup_printf("Invalid port number: %s", value);
				return -1;
			}
		} else if (strcmp(name, "client_flags") == 0) {
			if (str_to_uint(value, &db->client_flags) < 0) {
				*error_r = t_strdup_printf("Invalid client flags: %s", value);
				return -1;
			}
		} else if (strcmp(name, "connect_timeout") == 0) {
			if (str_to_uint(value, &db->connect_timeout) < 0) {
				*error_r = t_strdup_printf("Invalid read_timeout: %s", value);
				return -1;
			}
		} else if (strcmp(name, "read_timeout") == 0) {
			if (str_to_uint(value, &db->read_timeout) < 0) {
				*error_r = t_strdup_printf("Invalid read_timeout: %s", value);
				return -1;
			}
		} else if (strcmp(name, "write_timeout") == 0) {
			if (str_to_uint(value, &db->write_timeout) < 0) {
				*error_r = t_strdup_printf("Invalid read_timeout: %s", value);
				return -1;
			}
		} else if (strcmp(name, "ssl_cert") == 0)
			field = &db->ssl_cert;
		else if (strcmp(name, "ssl_key") == 0)
			field = &db->ssl_key;
		else if (strcmp(name, "ssl_ca") == 0)
			field = &db->ssl_ca;
		else if (strcmp(name, "ssl_ca_path") == 0)
			field = &db->ssl_ca_path;
		else if (strcmp(name, "ssl_cipher") == 0)
			field = &db->ssl_cipher;
		else if (strcmp(name, "ssl_verify_server_cert") == 0) {
			if (strcmp(value, "yes") == 0)
				db->ssl_verify_server_cert = 1;
			else if (strcmp(value, "no") == 0)
				db->ssl_verify_server_cert = 0;
			else {
				*error_r = t_strdup_printf("Invalid boolean: %s", value);
				return -1;
			}
		} else if (strcmp(name, "option_file") == 0)
			field = &db->option_file;
		else if (strcmp(name, "option_group") == 0)
			field = &db->option_group;
		else {
			*error_r = t_strdup_printf("Unknown connect string: %s", name);
			return -1;
		}
		if (field != NULL)
			*field = p_strdup(db->pool, value);
	}

	if (db->host == NULL && db->option_file == NULL) {
		*error_r = "No hosts given in connect string";
		return -1;
	}
	db->mysql = p_new(db->pool, MYSQL, 1);
	return 0;
}

static struct sql_db *driver_mysql_init_v(const char *connect_string)
{
	struct mysql_db *db;
	const char *error = NULL;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("mysql driver", 1024);
	db = p_new(pool, struct mysql_db, 1);
	db->pool = pool;
	db->api = driver_mysql_db;
	T_BEGIN {
		ret = driver_mysql_parse_connect_string(db, connect_string, &error);
		if (ret < 0)
			i_fatal("mysql: %s", error);
	} T_END;

	return &db->api;
}

static void driver_mysql_deinit_v(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;

	_db->no_reconnect = TRUE;
	sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);

	mysql_close(db->mysql);
	array_free(&_db->module_contexts);
	pool_unref(&db->pool);
}

static int driver_mysql_do_query(struct mysql_db *db, const char *query)
{
	if (mysql_query(db->mysql, query) == 0)
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
	struct mysql_db *db = (struct mysql_db *)_db;
	size_t len = strlen(string);
	char *to;

	if (_db->state == SQL_DB_STATE_DISCONNECTED) {
		/* try connecting */
		(void)sql_connect(&db->api);
	}

	if (db->mysql == NULL) {
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
	struct mysql_db *db = (struct mysql_db *)_db;

	if (driver_mysql_do_query(db, query) < 0) {
		i_error("%s: Query '%s' failed: %s",
			mysql_prefix(db), query, mysql_error(db->mysql));
	}
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
	struct mysql_db *db = (struct mysql_db *)_db;
	struct mysql_result *result;
	int ret;

	result = i_new(struct mysql_result, 1);
	result->api = driver_mysql_result;

	if (driver_mysql_do_query(db, query) < 0)
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
	return &result->api;
}

static void driver_mysql_result_free(struct sql_result *_result)
{
	struct mysql_result *result = (struct mysql_result *)_result;

	i_assert(_result != &sql_not_connected_result);
	if (_result->callback)
		return;

	if (result->result != NULL)
		mysql_free_result(result->result);
	i_free(result);
}

static int driver_mysql_result_next_row(struct sql_result *_result)
{
	struct mysql_result *result = (struct mysql_result *)_result;
	struct mysql_db *db = (struct mysql_db *)_result->db;
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
	struct mysql_result *result = (struct mysql_result *)_result;

        driver_mysql_result_fetch_fields(result);
	return result->fields_count;
}

static const char *
driver_mysql_result_get_field_name(struct sql_result *_result, unsigned int idx)
{
	struct mysql_result *result = (struct mysql_result *)_result;

	driver_mysql_result_fetch_fields(result);
	i_assert(idx < result->fields_count);
	return result->fields[idx].name;
}

static int driver_mysql_result_find_field(struct sql_result *_result,
					  const char *field_name)
{
	struct mysql_result *result = (struct mysql_result *)_result;
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
	struct mysql_result *result = (struct mysql_result *)_result;

	return (const char *)result->row[idx];
}

static const unsigned char *
driver_mysql_result_get_field_value_binary(struct sql_result *_result,
					   unsigned int idx, size_t *size_r)
{
	struct mysql_result *result = (struct mysql_result *)_result;
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
	struct mysql_result *result = (struct mysql_result *)_result;

	return (const char *const *)result->row;
}

static const char *driver_mysql_result_get_error(struct sql_result *_result)
{
	struct mysql_db *db = (struct mysql_db *)_result->db;
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
		struct mysql_result *result = (struct mysql_result *)_result;

		i_assert(result->affected_rows != (my_ulonglong)-1);
		*affected_rows_r = result->affected_rows;
	}
	sql_result_unref(_result);
	return ret;
}

static int driver_mysql_try_commit_s(struct mysql_transaction_context *ctx)
{
	struct sql_transaction_context *_ctx = &ctx->ctx;

	/* try to use a transaction in any case,
	   even if it's not actually functional. */
	if (transaction_send_query(ctx, "BEGIN", NULL) < 0) {
		if (_ctx->db->state != SQL_DB_STATE_DISCONNECTED)
			return -1;
		/* we got disconnected, retry */
		return 0;
	}
	while (_ctx->head != NULL) {
		if (transaction_send_query(ctx, _ctx->head->query,
					   _ctx->head->affected_rows) < 0)
			return -1;
		_ctx->head = _ctx->head->next;
	}
	if (transaction_send_query(ctx, "COMMIT", NULL) < 0)
		return -1;
	return 1;
}

static int
driver_mysql_transaction_commit_s(struct sql_transaction_context *_ctx,
				  const char **error_r)
{
	struct mysql_transaction_context *ctx =
		(struct mysql_transaction_context *)_ctx;
	struct mysql_db *db = (struct mysql_db *)_ctx->db;
	int ret = 1;

	*error_r = NULL;

	if (_ctx->head != NULL) {
		ret = driver_mysql_try_commit_s(ctx);
		*error_r = t_strdup(ctx->error);
		if (ret == 0) {
			i_info("%s: Disconnected from database, "
			       "retrying commit", db->dbname);
			if (sql_connect(_ctx->db) >= 0) {
				ctx->failed = FALSE;
				ret = driver_mysql_try_commit_s(ctx);
			}
		}
	}
	sql_transaction_rollback(&_ctx);
	return ret <= 0 ? -1 : 0;
}

static void
driver_mysql_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct mysql_transaction_context *ctx =
		(struct mysql_transaction_context *)_ctx;

	pool_unref(&ctx->query_pool);
	i_free(ctx);
}

static void
driver_mysql_update(struct sql_transaction_context *_ctx, const char *query,
		    unsigned int *affected_rows)
{
	struct mysql_transaction_context *ctx =
		(struct mysql_transaction_context *)_ctx;

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
	.flags = SQL_DB_FLAG_BLOCKING | SQL_DB_FLAG_POOLED,

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

void driver_mysql_init(void);
void driver_mysql_deinit(void);

void driver_mysql_init(void)
{
	sql_driver_register(&driver_mysql_db);
}

void driver_mysql_deinit(void)
{
	sql_driver_unregister(&driver_mysql_db);
}

#endif
