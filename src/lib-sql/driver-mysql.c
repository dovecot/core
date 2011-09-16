/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "sql-api-private.h"

#ifdef BUILD_MYSQL
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <mysql.h>
#include <errmsg.h>

struct mysql_db {
	struct sql_db api;

	pool_t pool;
	const char *user, *password, *dbname, *host, *unix_socket;
	const char *ssl_cert, *ssl_key, *ssl_ca, *ssl_ca_path, *ssl_cipher;
	const char *option_file, *option_group;
	unsigned int port, client_flags;

	MYSQL *mysql;
	unsigned int next_query_connection;

	unsigned int ssl_set:1;
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

	unsigned int failed:1;
};

extern const struct sql_db driver_mysql_db;
extern const struct sql_result driver_mysql_result;
extern const struct sql_result driver_mysql_error_result;

static const char *mysql_prefix(struct mysql_db *db)
{
	return t_strdup_printf("mysql(%s)", db->host);
}

static int driver_mysql_connect(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	const char *unix_socket, *host;
	unsigned long client_flags = db->client_flags;
	unsigned int secs_used;
	bool failed;

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	sql_db_set_state(&db->api, SQL_DB_STATE_CONNECTING);

	if (*db->host == '/') {
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
		db->ssl_set = TRUE;
#else
		i_fatal("mysql: SSL support not compiled in "
			"(remove ssl_ca and ssl_ca_path settings)");
#endif
	}

	alarm(SQL_CONNECT_TIMEOUT_SECS);
#ifdef CLIENT_MULTI_RESULTS
	client_flags |= CLIENT_MULTI_RESULTS;
#endif
	/* CLIENT_MULTI_RESULTS allows the use of stored procedures */
	failed = mysql_real_connect(db->mysql, host, db->user, db->password,
				    db->dbname, db->port, unix_socket,
				    client_flags) == NULL;
	secs_used = SQL_CONNECT_TIMEOUT_SECS - alarm(0);
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
		i_info("%s: Connected to database %s%s", mysql_prefix(db),
		       db->dbname, db->ssl_set ? " using SSL" : "");

		sql_db_set_state(&db->api, SQL_DB_STATE_IDLE);
		return 1;
	}
}

static void driver_mysql_disconnect(struct sql_db *_db ATTR_UNUSED)
{
}

static void driver_mysql_parse_connect_string(struct mysql_db *db,
					      const char *connect_string)
{
	const char *const *args, *name, *value;
	const char **field;

	db->ssl_cipher = "HIGH";

	args = t_strsplit_spaces(connect_string, " ");
	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL) {
			i_fatal("mysql: Missing value in connect string: %s",
				*args);
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
		else if (strcmp(name, "port") == 0)
			db->port = atoi(value);
		else if (strcmp(name, "client_flags") == 0)
			db->client_flags = atoi(value);
		else if (strcmp(name, "ssl_cert") == 0)
			field = &db->ssl_cert;
		else if (strcmp(name, "ssl_key") == 0)
			field = &db->ssl_key;
		else if (strcmp(name, "ssl_ca") == 0)
			field = &db->ssl_ca;
		else if (strcmp(name, "ssl_ca_path") == 0)
			field = &db->ssl_ca_path;
		else if (strcmp(name, "ssl_cipher") == 0)
			field = &db->ssl_cipher;
		else if (strcmp(name, "option_file") == 0)
			field = &db->option_file;
		else if (strcmp(name, "option_group") == 0)
			field = &db->option_group;
		else
			i_fatal("mysql: Unknown connect string: %s", name);

		if (field != NULL)
			*field = p_strdup(db->pool, value);
	}

	if (db->host == NULL)
		i_fatal("mysql: No hosts given in connect string");

	db->mysql = mysql_init(NULL);
	if (db->mysql == NULL)
		i_fatal("mysql_init() failed");
}

static struct sql_db *driver_mysql_init_v(const char *connect_string)
{
	struct mysql_db *db;
	pool_t pool;

	pool = pool_alloconly_create("mysql driver", 1024);
	db = p_new(pool, struct mysql_db, 1);
	db->pool = pool;
	db->api = driver_mysql_db;

	T_BEGIN {
		driver_mysql_parse_connect_string(db, connect_string);
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

	if (result->result == NULL) {
		/* no results */
		return 0;
	}

	result->row = mysql_fetch_row(result->result);
	if (result->row != NULL)
		return 1;

	return mysql_errno(db->mysql) != 0 ? -1 : 0;
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

	return mysql_error(db->mysql);
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
	const char *error;

	if (sql_transaction_commit_s(&ctx, &error) < 0)
		callback(error, context);
	else
		callback(NULL, context);
}

static int
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

static int
driver_mysql_transaction_commit_s(struct sql_transaction_context *_ctx,
				  const char **error_r)
{
	struct mysql_transaction_context *ctx =
		(struct mysql_transaction_context *)_ctx;
	int ret = 0;

	*error_r = NULL;

	if (_ctx->head != NULL) {
		/* try to use a transaction in any case,
		   even if it doesn't work. */
		(void)transaction_send_query(ctx, "BEGIN", NULL);
		while (_ctx->head != NULL) {
			if (transaction_send_query(ctx, _ctx->head->query,
						   _ctx->head->affected_rows) < 0)
				break;
			_ctx->head = _ctx->head->next;
		}
		ret = transaction_send_query(ctx, "COMMIT", NULL);
		*error_r = ctx->error;
	}
	sql_transaction_rollback(&_ctx);
	return ret;
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

const struct sql_db driver_mysql_db = {
	.name = "mysql",
	.flags = SQL_DB_FLAG_BLOCKING | SQL_DB_FLAG_POOLED,

	.v = {
		driver_mysql_init_v,
		driver_mysql_deinit_v,
		driver_mysql_connect,
		driver_mysql_disconnect,
		driver_mysql_escape_string,
		driver_mysql_exec,
		driver_mysql_query,
		driver_mysql_query_s,

		driver_mysql_transaction_begin,
		driver_mysql_transaction_commit,
		driver_mysql_transaction_commit_s,
		driver_mysql_transaction_rollback,

		driver_mysql_update
	}
};

const struct sql_result driver_mysql_result = {
	.v = {
		driver_mysql_result_free,
		driver_mysql_result_next_row,
		driver_mysql_result_get_fields_count,
		driver_mysql_result_get_field_name,
		driver_mysql_result_find_field,
		driver_mysql_result_get_field_value,
		driver_mysql_result_get_field_value_binary,
		driver_mysql_result_find_field_value,
		driver_mysql_result_get_values,
		driver_mysql_result_get_error
	}
};

static int
driver_mysql_result_error_next_row(struct sql_result *result ATTR_UNUSED)
{
	return -1;
}

const struct sql_result driver_mysql_error_result = {
	.v = {
		driver_mysql_result_free,
		driver_mysql_result_error_next_row,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		driver_mysql_result_get_error
	},
	.failed_try_retry = TRUE
};

const char *driver_mysql_version = DOVECOT_VERSION;

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
