/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "sql-api-private.h"

#include <time.h>

#define QUERY_TIMEOUT_SECS 6

/* sqlpool events are separate from category:sql, because
   they are usually not very interesting, and would only
   make logging too noisy. They can be enabled explicitly.
*/
static struct event_category event_category_sqlpool = {
	.name = "sqlpool",
};

struct sqlpool_host {
	char *connect_string;

	unsigned int connection_count;
};

struct sqlpool_connection {
	struct sql_db *db;
	unsigned int host_idx;
};

struct sqlpool_db {
	struct sql_db api;

	pool_t pool;
	const struct sql_db *driver;
	unsigned int connection_limit;

	ARRAY(struct sqlpool_host) hosts;
	/* all connections from all hosts */
	ARRAY(struct sqlpool_connection) all_connections;
	/* index of last connection in all_connections that was used to
	   send a query. */
	unsigned int last_query_conn_idx;

	/* queued requests */
	struct sqlpool_request *requests_head, *requests_tail;
	struct timeout *request_to;
};

struct sqlpool_request {
	struct sqlpool_request *prev, *next;

	struct sqlpool_db *db;
	time_t created;

	unsigned int host_idx;
	unsigned int retry_count;

	struct event *event;

	/* requests are a) queries */
	char *query;
	sql_query_callback_t *callback;
	void *context;

	/* b) transaction waiters */
	struct sqlpool_transaction_context *trans;
};

struct sqlpool_transaction_context {
	struct sql_transaction_context ctx;

	sql_commit_callback_t *callback;
	void *context;

	pool_t query_pool;
	struct sqlpool_request *commit_request;
};

extern struct sql_db driver_sqlpool_db;

static struct sqlpool_connection *
sqlpool_add_connection(struct sqlpool_db *db, struct sqlpool_host *host,
		       unsigned int host_idx);
static void
driver_sqlpool_query_callback(struct sql_result *result,
			      struct sqlpool_request *request);
static void
driver_sqlpool_commit_callback(const struct sql_commit_result *result,
			       struct sqlpool_transaction_context *ctx);
static void driver_sqlpool_deinit(struct sql_db *_db);

static struct sqlpool_request * ATTR_NULL(2)
sqlpool_request_new(struct sqlpool_db *db, const char *query)
{
	struct sqlpool_request *request;

	request = i_new(struct sqlpool_request, 1);
	request->db = db;
	request->created = time(NULL);
	request->query = i_strdup(query);
	request->event = event_create(db->api.event);
	return request;
}

static void
sqlpool_request_free(struct sqlpool_request **_request)
{
	struct sqlpool_request *request = *_request;

	*_request = NULL;

	i_assert(request->prev == NULL && request->next == NULL);
	event_unref(&request->event);
	i_free(request->query);
	i_free(request);
}

static void
sqlpool_request_abort(struct sqlpool_request **_request)
{
	struct sqlpool_request *request = *_request;

	*_request = NULL;

	if (request->callback != NULL)
		request->callback(&sql_not_connected_result, request->context);

	i_assert(request->prev != NULL ||
		 request->db->requests_head == request);
	DLLIST2_REMOVE(&request->db->requests_head,
		       &request->db->requests_tail, request);
	sqlpool_request_free(&request);
}

static struct sql_transaction_context *
driver_sqlpool_new_conn_trans(struct sqlpool_transaction_context *trans,
			      struct sql_db *conndb)
{
	struct sql_transaction_context *conn_trans;
	struct sql_transaction_query *query;

	conn_trans = sql_transaction_begin(conndb);
	/* backend will use our queries list (we might still append more
	   queries to the list) */
	conn_trans->head = trans->ctx.head;
	conn_trans->tail = trans->ctx.tail;
	for (query = conn_trans->head; query != NULL; query = query->next)
		query->trans = conn_trans;
	return conn_trans;
}

static void
sqlpool_request_handle_transaction(struct sql_db *conndb,
				   struct sqlpool_transaction_context *trans)
{
	struct sql_transaction_context *conn_trans;

	sqlpool_request_free(&trans->commit_request);
	conn_trans = driver_sqlpool_new_conn_trans(trans, conndb);
	sql_transaction_commit(&conn_trans,
			       driver_sqlpool_commit_callback, trans);
}

static void
sqlpool_request_send_next(struct sqlpool_db *db, struct sql_db *conndb)
{
	struct sqlpool_request *request;

	if (db->requests_head == NULL || !SQL_DB_IS_READY(conndb))
		return;

	request = db->requests_head;
	DLLIST2_REMOVE(&db->requests_head, &db->requests_tail, request);
	timeout_reset(db->request_to);

	if (request->query != NULL) {
		sql_query(conndb, request->query,
			  driver_sqlpool_query_callback, request);
	} else if (request->trans != NULL) {
		sqlpool_request_handle_transaction(conndb, request->trans);
	} else {
		i_unreached();
	}
}

static void sqlpool_reconnect(struct sql_db *conndb)
{
	timeout_remove(&conndb->to_reconnect);
	(void)sql_connect(conndb);
}

static struct sqlpool_host *
sqlpool_find_host_with_least_connections(struct sqlpool_db *db,
					 unsigned int *host_idx_r)
{
	struct sqlpool_host *hosts, *min = NULL;
	unsigned int i, count;

	hosts = array_get_modifiable(&db->hosts, &count);
	i_assert(count > 0);

	min = &hosts[0];
	*host_idx_r = 0;

	for (i = 1; i < count; i++) {
		if (min->connection_count > hosts[i].connection_count) {
			min = &hosts[i];
			*host_idx_r = i;
		}
	}
	return min;
}

static bool sqlpool_have_successful_connections(struct sqlpool_db *db)
{
	const struct sqlpool_connection *conn;

	array_foreach(&db->all_connections, conn) {
		if (conn->db->state >= SQL_DB_STATE_IDLE)
			return TRUE;
	}
	return FALSE;
}

static void
sqlpool_handle_connect_failed(struct sqlpool_db *db, struct sql_db *conndb)
{
	struct sqlpool_host *host;
	unsigned int host_idx;

	if (conndb->connect_failure_count > 0) {
		/* increase delay between reconnections to this
		   server */
		conndb->connect_delay *= 5;
		if (conndb->connect_delay > SQL_CONNECT_MAX_DELAY)
			conndb->connect_delay = SQL_CONNECT_MAX_DELAY;
	}
	conndb->connect_failure_count++;

	/* reconnect after the delay */
	timeout_remove(&conndb->to_reconnect);
	conndb->to_reconnect = timeout_add(conndb->connect_delay * 1000,
					   sqlpool_reconnect, conndb);

	/* if we have zero successful hosts and there still are hosts
	   without connections, connect to one of them. */
	if (!sqlpool_have_successful_connections(db)) {
		host = sqlpool_find_host_with_least_connections(db, &host_idx);
		if (host->connection_count == 0)
			(void)sqlpool_add_connection(db, host, host_idx);
	}
}

static void
sqlpool_state_changed(struct sql_db *conndb, enum sql_db_state prev_state,
		      void *context)
{
	struct sqlpool_db *db = context;

	if (conndb->state == SQL_DB_STATE_IDLE) {
		conndb->connect_failure_count = 0;
		conndb->connect_delay = SQL_CONNECT_MIN_DELAY;
		sqlpool_request_send_next(db, conndb);
	}

	if (prev_state == SQL_DB_STATE_CONNECTING &&
	    conndb->state == SQL_DB_STATE_DISCONNECTED &&
	    !conndb->no_reconnect)
		sqlpool_handle_connect_failed(db, conndb);
}

static struct sqlpool_connection *
sqlpool_add_connection(struct sqlpool_db *db, struct sqlpool_host *host,
		       unsigned int host_idx)
{
	struct sql_db *conndb;
	struct sqlpool_connection *conn;
	const char *error;
	int ret = 0;

	host->connection_count++;

	e_debug(db->api.event, "Creating new connection");

	if (db->driver->v.init_full == NULL) {
		conndb = db->driver->v.init(host->connect_string);
	} else {
		struct sql_settings set = {
			.connect_string = host->connect_string,
			.event_parent = event_get_parent(db->api.event),
		};
		ret = db->driver->v.init_full(&set, &conndb, &error);
	}
	if (ret < 0)
		i_fatal("sqlpool: %s", error);

	i_array_init(&conndb->module_contexts, 5);

	conndb->state_change_callback = sqlpool_state_changed;
	conndb->state_change_context = db;
	conndb->connect_delay = SQL_CONNECT_MIN_DELAY;

	conn = array_append_space(&db->all_connections);
	conn->host_idx = host_idx;
	conn->db = conndb;
	return conn;
}

static struct sqlpool_connection *
sqlpool_add_new_connection(struct sqlpool_db *db)
{
	struct sqlpool_host *host;
	unsigned int host_idx;

	host = sqlpool_find_host_with_least_connections(db, &host_idx);
	if (host->connection_count >= db->connection_limit)
		return NULL;
	else
		return sqlpool_add_connection(db, host, host_idx);
}

static const struct sqlpool_connection *
sqlpool_find_available_connection(struct sqlpool_db *db,
				  unsigned int unwanted_host_idx,
				  bool *all_disconnected_r)
{
	const struct sqlpool_connection *conns;
	unsigned int i, count;

	*all_disconnected_r = TRUE;

	conns = array_get(&db->all_connections, &count);
	for (i = 0; i < count; i++) {
		unsigned int idx = (i + db->last_query_conn_idx + 1) % count;
		struct sql_db *conndb = conns[idx].db;

		if (conns[idx].host_idx == unwanted_host_idx)
			continue;

		if (!SQL_DB_IS_READY(conndb) && conndb->to_reconnect == NULL) {
			/* see if we could reconnect to it immediately */
			(void)sql_connect(conndb);
		}
		if (SQL_DB_IS_READY(conndb)) {
			db->last_query_conn_idx = idx;
			*all_disconnected_r = FALSE;
			return &conns[idx];
		}
		if (conndb->state != SQL_DB_STATE_DISCONNECTED)
			*all_disconnected_r = FALSE;
	}
	return NULL;
}

static bool
driver_sqlpool_get_connection(struct sqlpool_db *db,
			      unsigned int unwanted_host_idx,
			      const struct sqlpool_connection **conn_r)
{
	const struct sqlpool_connection *conn, *conns;
	unsigned int i, count;
	bool all_disconnected;

	conn = sqlpool_find_available_connection(db, unwanted_host_idx,
						 &all_disconnected);
	if (conn == NULL && unwanted_host_idx != UINT_MAX) {
		/* maybe there are no wanted hosts. use any of them. */
		conn = sqlpool_find_available_connection(db, UINT_MAX,
							 &all_disconnected);
	}
	if (conn == NULL && all_disconnected) {
		/* no connected connections. connect_delays may have gotten too
		   high, reset all of them to see if some are still alive. */
		conns = array_get(&db->all_connections, &count);
		for (i = 0; i < count; i++) {
			struct sql_db *conndb = conns[i].db;

			if (conndb->connect_delay > SQL_CONNECT_RESET_DELAY)
				conndb->connect_delay = SQL_CONNECT_RESET_DELAY;
		}
		conn = sqlpool_find_available_connection(db, UINT_MAX,
							 &all_disconnected);
	}
	if (conn == NULL) {
		/* still nothing. try creating new connections */
		conn = sqlpool_add_new_connection(db);
		if (conn != NULL)
			(void)sql_connect(conn->db);
		if (conn == NULL || !SQL_DB_IS_READY(conn->db))
			return FALSE;
	}
	*conn_r = conn;
	return TRUE;
}

static bool
driver_sqlpool_get_sync_connection(struct sqlpool_db *db,
				   const struct sqlpool_connection **conn_r)
{
	const struct sqlpool_connection *conns;
	unsigned int i, count;

	if (driver_sqlpool_get_connection(db, UINT_MAX, conn_r))
		return TRUE;

	/* no idling connections, but maybe we can find one that's trying to
	   connect to server, and we can use it once it's finished */
	conns = array_get(&db->all_connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i].db->state == SQL_DB_STATE_CONNECTING) {
			*conn_r = &conns[i];
			return TRUE;
		}
	}
	return FALSE;
}

static int
driver_sqlpool_parse_hosts(struct sqlpool_db *db, const char *connect_string,
			   const char **error_r)
{
	const char *const *args, *key, *value, *const *hostnamep;
	struct sqlpool_host *host;
	ARRAY_TYPE(const_string) hostnames, connect_args;

	t_array_init(&hostnames, 8);
	t_array_init(&connect_args, 32);

	/* connect string is a space separated list. it may contain
	   backend-specific strings which we'll pass as-is. we'll only care
	   about our own settings, plus the host settings. */
	args = t_strsplit_spaces(connect_string, " ");
	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, value);
			value++;
		}

		if (strcmp(key, "maxconns") == 0) {
			if (str_to_uint(value, &db->connection_limit) < 0) {
				*error_r = t_strdup_printf("Invalid value for maxconns: %s",
					value);
				return -1;
			}
		} else if (strcmp(key, "host") == 0) {
			array_push_back(&hostnames, &value);
		} else {
			array_push_back(&connect_args, args);
		}
	}

	/* build a new connect string without our settings or hosts */
	array_append_zero(&connect_args);
	connect_string = t_strarray_join(array_first(&connect_args), " ");

	if (array_count(&hostnames) == 0) {
		/* no hosts specified. create a default one. */
		host = array_append_space(&db->hosts);
		host->connect_string = i_strdup(connect_string);
	} else {
		if (*connect_string == '\0')
			connect_string = NULL;

		array_foreach(&hostnames, hostnamep) {
			host = array_append_space(&db->hosts);
			host->connect_string =
				i_strconcat("host=", *hostnamep, " ",
					    connect_string, NULL);
		}
	}

	if (db->connection_limit == 0)
		db->connection_limit = SQL_DEFAULT_CONNECTION_LIMIT;
	return 0;
}

static void sqlpool_add_all_once(struct sqlpool_db *db)
{
	struct sqlpool_host *host;
	unsigned int host_idx;

	for (;;) {
		host = sqlpool_find_host_with_least_connections(db, &host_idx);
		if (host->connection_count > 0)
			break;
		(void)sqlpool_add_connection(db, host, host_idx);
	}
}

int driver_sqlpool_init_full(const struct sql_settings *set, const struct sql_db *driver,
			     struct sql_db **db_r, const char **error_r)
{
	char *error;
	struct sqlpool_db *db;
	int ret;

	db = i_new(struct sqlpool_db, 1);
	db->driver = driver;
	db->api = driver_sqlpool_db;
	db->api.flags = driver->flags;
	db->api.event = event_create(set->event_parent);
	event_add_category(db->api.event, &event_category_sqlpool);
	event_set_append_log_prefix(db->api.event,
				    t_strdup_printf("sqlpool(%s): ", driver->name));
	i_array_init(&db->hosts, 8);

	T_BEGIN {
		const char *tmp = NULL;
		if ((ret = driver_sqlpool_parse_hosts(db, set->connect_string,
						      &tmp)) < 0)
			error = i_strdup(tmp);
	} T_END;

	if (ret < 0) {
		*error_r = t_strdup(error);
		i_free(error);
		driver_sqlpool_deinit(&db->api);
		return ret;
	}
	i_array_init(&db->all_connections, 16);
	/* connect to all databases so we can do load balancing immediately */
	sqlpool_add_all_once(db);

	*db_r = &db->api;
	return 0;
}

static void driver_sqlpool_abort_requests(struct sqlpool_db *db)
{
	while (db->requests_head != NULL) {
		struct sqlpool_request *request = db->requests_head;

		sqlpool_request_abort(&request);
	}
	timeout_remove(&db->request_to);
}

static void driver_sqlpool_deinit(struct sql_db *_db)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	struct sqlpool_host *host;
	struct sqlpool_connection *conn;

	array_foreach_modifiable(&db->all_connections, conn)
		sql_deinit(&conn->db);
	array_clear(&db->all_connections);

	driver_sqlpool_abort_requests(db);

	array_foreach_modifiable(&db->hosts, host)
		i_free(host->connect_string);

	i_assert(array_count(&db->all_connections) == 0);
	array_free(&db->hosts);
	array_free(&db->all_connections);
	array_free(&_db->module_contexts);
	event_unref(&_db->event);
	i_free(db);
}

static int driver_sqlpool_connect(struct sql_db *_db)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conn;
	int ret = -1, ret2;

	array_foreach(&db->all_connections, conn) {
		ret2 = conn->db->to_reconnect != NULL ? -1 :
			sql_connect(conn->db);
		if (ret2 > 0)
			ret = 1;
		else if (ret2 == 0 && ret < 0)
			ret = 0;
	}
	return ret;
}

static void driver_sqlpool_disconnect(struct sql_db *_db)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conn;

	array_foreach(&db->all_connections, conn)
		sql_disconnect(conn->db);
	driver_sqlpool_abort_requests(db);
}

static const char *
driver_sqlpool_escape_string(struct sql_db *_db, const char *string)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conns;
	unsigned int i, count;

	/* use the first ready connection */
	conns = array_get(&db->all_connections, &count);
	for (i = 0; i < count; i++) {
		if (SQL_DB_IS_READY(conns[i].db))
			return sql_escape_string(conns[i].db, string);
	}
	/* no ready connections. just use the first one (we're guaranteed
	   to always have one) */
	return sql_escape_string(conns[0].db, string);
}

static void driver_sqlpool_timeout(struct sqlpool_db *db)
{
	int duration;

	while (db->requests_head != NULL) {
		struct sqlpool_request *request = db->requests_head;

		if (request->created + SQL_QUERY_TIMEOUT_SECS > ioloop_time)
			break;


		if (request->query != NULL) {
			e_error(sql_query_finished_event(&db->api, request->event,
							 request->query, FALSE,
							 &duration)->
					add_str("error", "Query timed out")->
					event(),
				SQL_QUERY_FINISHED_FMT": Query timed out "
	                        "(no free connections for %u secs)",
				request->query, duration,
				(unsigned int)(ioloop_time - request->created));
		} else {
			e_error(event_create_passthrough(request->event)->
					add_str("error", "Timed out")->
					set_name(SQL_TRANSACTION_FINISHED)->event(),
				"Transaction timed out "
				"(no free connections for %u secs)",
				(unsigned int)(ioloop_time - request->created));
		}
		sqlpool_request_abort(&request);
	}

	if (db->requests_head == NULL)
		timeout_remove(&db->request_to);
}

static void
driver_sqlpool_prepend_request(struct sqlpool_db *db,
			       struct sqlpool_request *request)
{
	DLLIST2_PREPEND(&db->requests_head, &db->requests_tail, request);
	if (db->request_to == NULL) {
		db->request_to = timeout_add(SQL_QUERY_TIMEOUT_SECS * 1000,
					     driver_sqlpool_timeout, db);
	}
}

static void
driver_sqlpool_append_request(struct sqlpool_db *db,
			      struct sqlpool_request *request)
{
	DLLIST2_APPEND(&db->requests_head, &db->requests_tail, request);
	if (db->request_to == NULL) {
		db->request_to = timeout_add(SQL_QUERY_TIMEOUT_SECS * 1000,
					     driver_sqlpool_timeout, db);
	}
}

static void
driver_sqlpool_query_callback(struct sql_result *result,
			      struct sqlpool_request *request)
{
	struct sqlpool_db *db = request->db;
	const struct sqlpool_connection *conn = NULL;
	struct sql_db *conndb;

	if (result->failed_try_retry &&
	    request->retry_count < array_count(&db->hosts)) {
		e_warning(db->api.event, "Query failed, retrying: %s",
			  sql_result_get_error(result));
		request->retry_count++;
		driver_sqlpool_prepend_request(db, request);

		if (driver_sqlpool_get_connection(request->db,
						  request->host_idx, &conn)) {
			request->host_idx = conn->host_idx;
			sqlpool_request_send_next(db, conn->db);
		}
	} else {
		if (result->failed) {
			e_error(db->api.event, "Query failed, aborting: %s",
				request->query);
		}
		conndb = result->db;

		if (request->callback != NULL)
			request->callback(result, request->context);
		sqlpool_request_free(&request);

		sqlpool_request_send_next(db, conndb);
	}
}

static void ATTR_NULL(3, 4)
driver_sqlpool_query(struct sql_db *_db, const char *query,
		     sql_query_callback_t *callback, void *context)
{
        struct sqlpool_db *db = (struct sqlpool_db *)_db;
	struct sqlpool_request *request;
	const struct sqlpool_connection *conn;

	request = sqlpool_request_new(db, query);
	request->callback = callback;
	request->context = context;

	if (!driver_sqlpool_get_connection(db, UINT_MAX, &conn))
		driver_sqlpool_append_request(db, request);
	else {
		request->host_idx = conn->host_idx;
		sql_query(conn->db, query, driver_sqlpool_query_callback,
			  request);
	}
}

static void driver_sqlpool_exec(struct sql_db *_db, const char *query)
{
	driver_sqlpool_query(_db, query, NULL, NULL);
}

static struct sql_result *
driver_sqlpool_query_s(struct sql_db *_db, const char *query)
{
        struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conn;
	struct sql_result *result;

	if (!driver_sqlpool_get_sync_connection(db, &conn)) {
		sql_not_connected_result.refcount++;
		return &sql_not_connected_result;
	}

	result = sql_query_s(conn->db, query);
	if (result->failed_try_retry) {
		if (!driver_sqlpool_get_sync_connection(db, &conn))
			return result;

		sql_result_unref(result);
		result = sql_query_s(conn->db, query);
	}
	return result;
}

static struct sql_transaction_context *
driver_sqlpool_transaction_begin(struct sql_db *_db)
{
	struct sqlpool_transaction_context *ctx;

	ctx = i_new(struct sqlpool_transaction_context, 1);
	ctx->ctx.db = _db;

	/* queue changes until commit. even if we did have a free connection
	   now, don't use it or multiple open transactions could tie up all
	   connections. */
	ctx->query_pool = pool_alloconly_create("sqlpool transaction", 1024);
	return &ctx->ctx;
}

static void
driver_sqlpool_transaction_free(struct sqlpool_transaction_context *ctx)
{
	if (ctx->commit_request != NULL)
		sqlpool_request_abort(&ctx->commit_request);
	pool_unref(&ctx->query_pool);
	i_free(ctx);
}

static void
driver_sqlpool_commit_callback(const struct sql_commit_result *result,
			       struct sqlpool_transaction_context *ctx)
{
	ctx->callback(result, ctx->context);
	driver_sqlpool_transaction_free(ctx);
}

static void
driver_sqlpool_transaction_commit(struct sql_transaction_context *_ctx,
				  sql_commit_callback_t *callback,
				  void *context)
{
	struct sqlpool_transaction_context *ctx =
		(struct sqlpool_transaction_context *)_ctx;
	struct sqlpool_db *db = (struct sqlpool_db *)_ctx->db;
	const struct sqlpool_connection *conn;

	ctx->callback = callback;
	ctx->context = context;

	ctx->commit_request = sqlpool_request_new(db, NULL);
	ctx->commit_request->trans = ctx;

	if (driver_sqlpool_get_connection(db, UINT_MAX, &conn))
		sqlpool_request_handle_transaction(conn->db, ctx);
	else
		driver_sqlpool_append_request(db, ctx->commit_request);
}

static int
driver_sqlpool_transaction_commit_s(struct sql_transaction_context *_ctx,
				    const char **error_r)
{
	struct sqlpool_transaction_context *ctx =
		(struct sqlpool_transaction_context *)_ctx;
        struct sqlpool_db *db = (struct sqlpool_db *)_ctx->db;
	const struct sqlpool_connection *conn;
	struct sql_transaction_context *conn_trans;
	int ret;

	*error_r = NULL;

	if (!driver_sqlpool_get_sync_connection(db, &conn)) {
		*error_r = SQL_ERRSTR_NOT_CONNECTED;
		driver_sqlpool_transaction_free(ctx);
		return -1;
	}

	conn_trans = driver_sqlpool_new_conn_trans(ctx, conn->db);
	ret = sql_transaction_commit_s(&conn_trans, error_r);
	driver_sqlpool_transaction_free(ctx);
	return ret;
}

static void
driver_sqlpool_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct sqlpool_transaction_context *ctx =
		(struct sqlpool_transaction_context *)_ctx;

	driver_sqlpool_transaction_free(ctx);
}

static void
driver_sqlpool_update(struct sql_transaction_context *_ctx, const char *query,
		      unsigned int *affected_rows)
{
	struct sqlpool_transaction_context *ctx =
		(struct sqlpool_transaction_context *)_ctx;

	/* we didn't get a connection for transaction immediately.
	   queue updates until commit transfers all of these */
	sql_transaction_add_query(&ctx->ctx, ctx->query_pool,
				  query, affected_rows);
}

static const char *
driver_sqlpool_escape_blob(struct sql_db *_db,
			   const unsigned char *data, size_t size)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conns;
	unsigned int i, count;

	/* use the first ready connection */
	conns = array_get(&db->all_connections, &count);
	for (i = 0; i < count; i++) {
		if (SQL_DB_IS_READY(conns[i].db))
			return sql_escape_blob(conns[i].db, data, size);
	}
	/* no ready connections. just use the first one (we're guaranteed
	   to always have one) */
	return sql_escape_blob(conns[0].db, data, size);
}

struct sql_db driver_sqlpool_db = {
	"",

	.v = {
		.deinit = driver_sqlpool_deinit,
		.connect = driver_sqlpool_connect,
		.disconnect = driver_sqlpool_disconnect,
		.escape_string = driver_sqlpool_escape_string,
		.exec = driver_sqlpool_exec,
		.query = driver_sqlpool_query,
		.query_s = driver_sqlpool_query_s,

		.transaction_begin = driver_sqlpool_transaction_begin,
		.transaction_commit = driver_sqlpool_transaction_commit,
		.transaction_commit_s = driver_sqlpool_transaction_commit_s,
		.transaction_rollback = driver_sqlpool_transaction_rollback,

		.update = driver_sqlpool_update,

		.escape_blob = driver_sqlpool_escape_blob,
	}
};
