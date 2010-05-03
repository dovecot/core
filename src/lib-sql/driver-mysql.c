/* Copyright (c) 2003-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "sql-api-private.h"

#ifdef BUILD_MYSQL
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <mysql.h>
#include <errmsg.h>

/* Abort connect() if it can't connect within this time. */
#define MYSQL_CONNECT_FAILURE_TIMEOUT 10

/* Minimum delay between reconnecting to same server */
#define CONNECT_MIN_DELAY 1
/* Maximum time to avoiding reconnecting to same server */
#define CONNECT_MAX_DELAY (60*30)
/* If no servers are connected but a query is requested, try reconnecting to
   next server which has been disconnected longer than this (with a single
   server setup this is really the "max delay" and the CONNECT_MAX_DELAY
   is never used). */
#define CONNECT_RESET_DELAY 15

struct mysql_db {
	struct sql_db api;

	pool_t pool;
	const char *user, *password, *dbname, *unix_socket;
	const char *ssl_cert, *ssl_key, *ssl_ca, *ssl_ca_path, *ssl_cipher;
	const char *option_file, *option_group;
	unsigned int port, client_flags;

	ARRAY_DEFINE(connections, struct mysql_connection);
	unsigned int next_query_connection;
};

struct mysql_connection {
	struct mysql_db *db;

	MYSQL *mysql;
	const char *host;

	unsigned int connect_delay;
	unsigned int connect_failure_count;

	time_t last_connect;
	unsigned int connected:1;
	unsigned int ssl_set:1;
};

struct mysql_result {
	struct sql_result api;
	struct mysql_connection *conn;

	MYSQL_RES *result;
        MYSQL_ROW row;

	MYSQL_FIELD *fields;
	unsigned int fields_count;
};

struct mysql_transaction_context {
	struct sql_transaction_context ctx;

	pool_t query_pool;
	struct mysql_query_list *head, *tail;

	const char *error;

	unsigned int failed:1;
};

struct mysql_query_list {
	struct mysql_query_list *next;
	const char *query;
	unsigned int *affected_rows;
};

extern const struct sql_db driver_mysql_db;
extern const struct sql_result driver_mysql_result;
extern const struct sql_result driver_mysql_error_result;

static bool driver_mysql_connect(struct mysql_connection *conn)
{
	struct mysql_db *db = conn->db;
	const char *unix_socket, *host;
	unsigned long client_flags = db->client_flags;
	time_t now;
	bool failed;

	if (conn->connected)
		return TRUE;

	/* don't try reconnecting more than once a second */
	now = time(NULL);
	if (conn->last_connect + (time_t)conn->connect_delay > now)
		return FALSE;
	conn->last_connect = now;

	if (*conn->host == '/') {
		unix_socket = conn->host;
		host = NULL;
	} else {
		unix_socket = NULL;
		host = conn->host;
	}

	if (db->option_file != NULL) {
		mysql_options(conn->mysql, MYSQL_READ_DEFAULT_FILE,
			      db->option_file);
	}

	mysql_options(conn->mysql, MYSQL_READ_DEFAULT_GROUP,
		      db->option_group != NULL ? db->option_group : "client");

	if (!conn->ssl_set && (db->ssl_ca != NULL || db->ssl_ca_path != NULL)) {
#ifdef HAVE_MYSQL_SSL
		mysql_ssl_set(conn->mysql, db->ssl_key, db->ssl_cert,
			      db->ssl_ca, db->ssl_ca_path
#ifdef HAVE_MYSQL_SSL_CIPHER
			      , db->ssl_cipher
#endif
			     );
		conn->ssl_set = TRUE;
#else
		i_fatal("mysql: SSL support not compiled in "
			"(remove ssl_ca and ssl_ca_path settings)");
#endif
	}

	alarm(MYSQL_CONNECT_FAILURE_TIMEOUT);
#ifdef CLIENT_MULTI_RESULTS
	client_flags |= CLIENT_MULTI_RESULTS;
#endif
	/* CLIENT_MULTI_RESULTS allows the use of stored procedures */
	failed = mysql_real_connect(conn->mysql, host, db->user, db->password,
				    db->dbname, db->port, unix_socket,
				    client_flags) == NULL;
	alarm(0);
	if (failed) {
		if (conn->connect_failure_count > 0) {
			/* increase delay between reconnections to this
			   server */
			conn->connect_delay *= 5;
			if (conn->connect_delay > CONNECT_MAX_DELAY)
				conn->connect_delay = CONNECT_MAX_DELAY;
		}
		conn->connect_failure_count++;

		i_error("mysql: Connect failed to %s (%s): %s - "
			"waiting for %u seconds before retry",
			host != NULL ? host : unix_socket, db->dbname,
			mysql_error(conn->mysql), conn->connect_delay);
		return FALSE;
	} else {
		i_info("mysql: Connected to %s%s (%s)",
		       host != NULL ? host : unix_socket,
		       conn->ssl_set ? " using SSL" : "", db->dbname);

		conn->connect_failure_count = 0;
		conn->connect_delay = CONNECT_MIN_DELAY;
		conn->connected = TRUE;
		return TRUE;
	}
}

static int driver_mysql_connect_all(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	struct mysql_connection *conn;
	int ret = -1;

	array_foreach_modifiable(&db->connections, conn) {
		if (driver_mysql_connect(conn))
			ret = 1;
	}
	return ret;
}

static void driver_mysql_connection_add(struct mysql_db *db, const char *host)
{
	struct mysql_connection *conn;

	conn = array_append_space(&db->connections);
	conn->db = db;
	conn->host = p_strdup(db->pool, host);
	conn->mysql = mysql_init(NULL);
	if (conn->mysql == NULL)
		i_fatal("mysql_init() failed");

	conn->connect_delay = CONNECT_MIN_DELAY;
}

static void driver_mysql_connection_free(struct mysql_connection *conn)
{
	mysql_close(conn->mysql);
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
			driver_mysql_connection_add(db, value);
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

	if (array_count(&db->connections) == 0)
		i_fatal("mysql: No hosts given in connect string");
}

static struct sql_db *driver_mysql_init_v(const char *connect_string)
{
	struct mysql_db *db;
	pool_t pool;

	pool = pool_alloconly_create("mysql driver", 1024);
	db = p_new(pool, struct mysql_db, 1);
	db->pool = pool;
	db->api = driver_mysql_db;
	p_array_init(&db->connections, db->pool, 6);

	T_BEGIN {
		driver_mysql_parse_connect_string(db, connect_string);
	} T_END;
	return &db->api;
}

static void driver_mysql_deinit_v(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	struct mysql_connection *conn;

	array_foreach_modifiable(&db->connections, conn)
		(void)driver_mysql_connection_free(conn);

	array_free(&_db->module_contexts);
	pool_unref(&db->pool);
}

static enum sql_db_flags
driver_mysql_get_flags(struct sql_db *db ATTR_UNUSED)
{
	return SQL_DB_FLAG_BLOCKING;
}

static int driver_mysql_connection_do_query(struct mysql_connection *conn,
					    const char *query)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (!driver_mysql_connect(conn))
			return 0;

		if (mysql_query(conn->mysql, query) == 0)
			return 1;

		/* failed */
		switch (mysql_errno(conn->mysql)) {
		case CR_SERVER_GONE_ERROR:
		case CR_SERVER_LOST:
			/* connection lost - try immediate reconnect */
			conn->connected = FALSE;
			break;
		default:
			return -1;
		}
	}

	/* connected -> lost it -> connected -> lost again */
	return 0;
}

static int driver_mysql_do_query(struct mysql_db *db, const char *query,
				 struct mysql_connection **conn_r)
{
	struct mysql_connection *conn;
	unsigned int i, start, count;
	bool reset;
	int ret;

	conn = array_get_modifiable(&db->connections, &count);

	/* go through the connections in round robin. if the connection
	   isn't available, try next one that is. */
	start = db->next_query_connection % count;
	db->next_query_connection++;

	for (reset = FALSE;; reset = TRUE) {
		i = start;
		do {
			ret = driver_mysql_connection_do_query(&conn[i], query);
			if (ret != 0) {
				/* success / failure */
				*conn_r = &conn[i];
				return ret;
			}

			/* not connected, try next one */
			i = (i + 1) % count;
		} while (i != start);

		if (reset)
			break;

		/* none are connected. connect_delays may have gotten too high,
		   reset all of them to see if some are still alive. */
		for (i = 0; i < count; i++)
			conn[i].connect_delay = CONNECT_RESET_DELAY;
	}

	*conn_r = NULL;
	return 0;
}

static const char *
driver_mysql_escape_string(struct sql_db *_db, const char *string)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	struct mysql_connection *conn;
	unsigned int i, count;
	size_t len = strlen(string);
	char *to;

	/* All the connections should be identical, so just use the first
	   connected one */
	conn = array_get_modifiable(&db->connections, &count);
	for (i = 0; i < count; i++) {
		if (conn[i].connected)
			break;
	}
	if (i == count) {
		/* so, try connecting.. */
		for (i = 0; i < count; i++) {
			if (driver_mysql_connect(&conn[i]))
				break;
		}
		if (i == count) {
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
	}

	to = t_buffer_get(len * 2 + 1);
	len = mysql_real_escape_string(conn[i].mysql, to, string, len);
	t_buffer_alloc(len + 1);
	return to;
}

static void driver_mysql_exec(struct sql_db *_db, const char *query)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	struct mysql_connection *conn;

	(void)driver_mysql_do_query(db, query, &conn);
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
	struct mysql_connection *conn;
	struct mysql_result *result;
	int ret;

	result = i_new(struct mysql_result, 1);
	result->api = driver_mysql_result;
	result->api.db = _db;

	switch (driver_mysql_do_query(db, query, &conn)) {
	case 0:
		/* not connected */
		result->api = sql_not_connected_result;
		break;
	case 1:
		/* query ok */
		result->result = mysql_store_result(conn->mysql);
#ifdef CLIENT_MULTI_RESULTS
		/* Because we've enabled CLIENT_MULTI_RESULTS, we need to read
		   (ignore) extra results - there should not be any.
		   ret is: -1 = done, >0 = error, 0 = more results. */
		while ((ret = mysql_next_result(conn->mysql)) == 0) ;
#else
		ret = -1;
#endif

		if (ret < 0 &&
		    (result->result != NULL || mysql_errno(conn->mysql) == 0))
			break;

		/* failed */
		if (result->result != NULL)
			mysql_free_result(result->result);
		/* fall through */
	case -1:
		/* error */
		result->api = driver_mysql_error_result;
		break;
	}

	result->api.refcount = 1;
	result->conn = conn;
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

	if (result->result == NULL) {
		/* no results */
		return 0;
	}

	result->row = mysql_fetch_row(result->result);
	if (result->row != NULL)
		return 1;

	return mysql_errno(result->conn->mysql) != 0 ? -1 : 0;
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
driver_mysql_result_get_field_value_binary(struct sql_result *_result ATTR_UNUSED,
					   unsigned int idx ATTR_UNUSED,
					   size_t *size_r ATTR_UNUSED)
{
	/* FIXME */
	return NULL;
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
	struct mysql_result *result = (struct mysql_result *)_result;

	return mysql_error(result->conn->mysql);
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

static int transaction_send_query(struct mysql_transaction_context *ctx,
				  const char *query)
{
	struct sql_result *result;
	my_ulonglong rows;
	int ret = 0;

	if (ctx->failed)
		return -1;

	result = sql_query_s(ctx->ctx.db, query);
	if (sql_result_next_row(result) < 0) {
		ctx->error = sql_result_get_error(result);
		ctx->failed = TRUE;
		ret = -1;
	} else if (ctx->head != NULL && ctx->head->affected_rows != NULL) {
		struct mysql_result *my_result = (struct mysql_result *)result;

		rows = mysql_affected_rows(my_result->conn->mysql);
		i_assert(rows != (my_ulonglong)-1);
		*ctx->head->affected_rows = rows;
	}
	sql_result_unref(result);
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

	if (ctx->head != NULL) {
		/* try to use a transaction in any case,
		   even if it doesn't work. */
		(void)transaction_send_query(ctx, "BEGIN");
		while (ctx->head != NULL) {
			if (transaction_send_query(ctx, ctx->head->query) < 0)
				break;
			ctx->head = ctx->head->next;
		}
		ret = transaction_send_query(ctx, "COMMIT");
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
	struct mysql_query_list *list;

	list = p_new(ctx->query_pool, struct mysql_query_list, 1);
	list->query = p_strdup(ctx->query_pool, query);
	list->affected_rows = affected_rows;

	if (ctx->head == NULL)
		ctx->head = list;
	else
		ctx->tail->next = list;
	ctx->tail = list;
}

const struct sql_db driver_mysql_db = {
	"mysql",

	.v = {
		driver_mysql_init_v,
		driver_mysql_deinit_v,
		driver_mysql_get_flags,
		driver_mysql_connect_all,
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
	}
};

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
