/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "settings.h"
#include "sql-api-private.h"

#include <time.h>

/* sqlpool events are separate from category:sql, because
   they are usually not very interesting, and would only
   make logging too noisy. They can be enabled explicitly.
*/
static struct event_category event_category_sqlpool = {
	.name = "sqlpool",
};

struct sqlpool_host {
	char *hostname;

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
	char *filter_name;
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

struct sqlpool_statement;

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

	/* c) statement queries waiting for a connection: replayed onto a
	   fresh statement once one is available, so the query is never
	   rendered to plain text. Owns the reference on pool_stmt->api.pool
	   until it is handed off to a struct sqlpool_statement_query or
	   released on abort. */
	struct sqlpool_statement *pool_stmt;
};

struct sqlpool_transaction_context {
	struct sql_transaction_context ctx;

	sql_commit_callback_t *callback;
	void *context;

	/* connection the commit was sent to, captured so the commit
	   callback can resume the next queued request on it. */
	struct sql_db *conndb;

	pool_t query_pool;
	struct sqlpool_request *commit_request;
};

enum sqlpool_bind_type {
	SQLPOOL_BIND_STR,
	SQLPOOL_BIND_BINARY,
	SQLPOOL_BIND_INT64,
	SQLPOOL_BIND_DOUBLE,
	SQLPOOL_BIND_UUID,
};

/* One bind call recorded exactly as it was forwarded to the backend
   statement, so it can be replayed onto a fresh statement on a retry
   without ever rendering the query to plain text. */
struct sqlpool_bind {
	enum sqlpool_bind_type type;
	unsigned int column_idx;

	/* STR only. */
	const char *value_str;
	const void *value_binary;
	size_t value_len;
	int64_t value_int64;
	double value_double;
	guid_128_t value_uuid;
};

struct sqlpool_statement {
	struct sql_statement api;
	struct sql_statement *stmt;
	/* index of the host stmt was created on, recorded instead of a
	   pointer because array_append_space() can move db->all_connections
	   on a later sqlpool_add_connection() - only the index is safe to
	   read after statement_init() has returned. */
	unsigned int host_idx;

	/* binds recorded as they are forwarded to stmt, and the
	   no_log_expanded_values flag, which stmt itself may never have
	   received if it was still NULL when set - replayed onto a fresh
	   statement by sqlpool_statement_replay_binds(). */
	ARRAY(struct sqlpool_bind) binds;
	bool no_log_expanded_values;
	/* bind column indexes marked no-log via the per-field setter,
	   replayed the same way as no_log_expanded_values. */
	ARRAY(unsigned int) no_log_field_idxs;
};

/* Tracks an in-flight asynchronous statement query so its callback can
   retry on another host: once the backend statement has been executed,
   its pool is gone, so a retry builds a fresh statement on the new
   connection and replays pool_stmt's recorded binds onto it, keeping the
   query template and its typed bind values out of plain text throughout.
   pool_stmt is released (pool_unref()'d) exactly once, when the query
   finally completes or is aborted with no more retries left. */
struct sqlpool_statement_query {
	struct sqlpool_db *db;
	struct sqlpool_statement *pool_stmt;
	sql_query_callback_t *callback;
	void *context;

	unsigned int host_idx;
	unsigned int retry_count;
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
static const struct sqlpool_connection *
sqlpool_find_connection(struct sqlpool_db *db, struct sql_db *conndb);
static void
sqlpool_statement_query_on(struct sqlpool_db *db,
			   const struct sqlpool_connection *conn,
			   struct sqlpool_statement *pool_stmt,
			   sql_query_callback_t *callback, void *context,
			   unsigned int retry_count);
static void
driver_sqlpool_statement_query_callback(struct sql_result *result,
					struct sqlpool_statement_query *query);
static void
driver_sqlpool_transaction_free(struct sqlpool_transaction_context *ctx);
static void
sqlpool_statement_replay_binds(const struct sqlpool_statement *pool_stmt,
			       struct sql_statement *stmt);

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

static struct sqlpool_request *
sqlpool_request_new_stmt(struct sqlpool_db *db,
			 struct sqlpool_statement *pool_stmt)
{
	struct sqlpool_request *request = sqlpool_request_new(db, NULL);

	request->pool_stmt = pool_stmt;
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
	if (request->pool_stmt != NULL)
		pool_unref(&request->pool_stmt->api.pool);

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
	for (query = conn_trans->head; query != NULL; query = query->next) {
		query->trans = conn_trans;
		if (query->stmt == NULL)
			continue;
		if (query->stmt->db != trans->ctx.db) {
			/* Already a real backend statement - point it at
			   whichever connection this transaction ended up
			   using. */
			query->stmt->db = conndb;
			continue;
		}
		/* driver_sqlpool_update_stmt() deferred this one: no
		   connection was available when its binds were recorded, so
		   query->stmt is still the sqlpool wrapper (its .db is still
		   our own db, never a real connection's). Build the real
		   statement now that conndb is known, and replay the
		   recorded binds onto it, the same as the async query path's
		   sqlpool_statement_query_on() does. */
		struct sqlpool_statement *pool_stmt =
			container_of(query->stmt, struct sqlpool_statement, api);
		i_assert(pool_stmt->stmt == NULL);
		struct sql_statement *stmt =
			sql_statement_init(conndb, pool_stmt->api.query_template);
		sqlpool_statement_replay_binds(pool_stmt, stmt);
		pool_add_external_ref(trans->query_pool, stmt->pool);
		pool_unref(&stmt->pool);
		query->stmt = stmt;
	}
	return conn_trans;
}

static void
sqlpool_request_handle_transaction(struct sql_db *conndb,
				   struct sqlpool_transaction_context *trans)
{
	struct sql_transaction_context *conn_trans;

	sqlpool_request_free(&trans->commit_request);
	trans->conndb = conndb;
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
	} else if (request->pool_stmt != NULL) {
		const struct sqlpool_connection *conn =
			sqlpool_find_connection(db, conndb);
		sqlpool_statement_query_on(db, conn, request->pool_stmt,
					   request->callback, request->context,
					   request->retry_count);
		request->pool_stmt = NULL;
		sqlpool_request_free(&request);
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

	struct event *event = event_create(db->api.event);
	event_set_ptr(event, SQLPOOL_EVENT_PTR, "yes");
	settings_event_add_list_filter_name(event, db->filter_name, host->hostname);
	ret = db->driver->v.init(event, &conndb, &error);
	event_unref(&event);
	if (ret < 0)
		i_fatal("sqlpool: %s", error);

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
sqlpool_find_connection(struct sqlpool_db *db, struct sql_db *conndb)
{
	const struct sqlpool_connection *conn;

	array_foreach(&db->all_connections, conn) {
		if (conn->db == conndb)
			return conn;
	}
	i_unreached();
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

static bool
driver_sqlpool_get_connected_flags(struct sqlpool_db *db,
				   enum sql_db_flags *flags_r)
{
	const struct sqlpool_connection *conn;

	array_foreach(&db->all_connections, conn) {
		if (conn->db->state > SQL_DB_STATE_CONNECTING) {
			*flags_r = sql_get_flags(conn->db);
			return TRUE;
		}
	}
	return FALSE;
}

static enum sql_db_flags driver_sqlpool_get_flags(struct sql_db *_db)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conn;
	enum sql_db_flags flags;

	/* try to use a connected db */
	if (driver_sqlpool_get_connected_flags(db, &flags))
		return flags;

	if (!driver_sqlpool_get_sync_connection(db, &conn)) {
		/* Failed to connect to database. Just use the first
		   connection. */
		conn = array_idx(&db->all_connections, 0);
	}
	return sql_get_flags(conn->db);
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

static struct sqlpool_db *
driver_sqlpool_init_common(const struct sql_db *driver,
			   struct event *event_parent,
			   const ARRAY_TYPE(const_string) *hostnames,
			   unsigned int connection_limit)
{
	struct sqlpool_db *db;
	struct sqlpool_host *host;
	const char *hostname;

	db = i_new(struct sqlpool_db, 1);
	db->driver = driver;
	db->connection_limit = connection_limit;
	db->api = driver_sqlpool_db;
	db->api.flags = driver->flags;
	db->api.event = event_create(event_parent);
	event_add_category(db->api.event, &event_category_sqlpool);
	event_set_append_log_prefix(db->api.event,
				    t_strdup_printf("sqlpool(%s): ", driver->name));
	i_array_init(&db->hosts, array_count(hostnames));

	if (array_count(hostnames) == 0) {
		/* no hosts specified. create a default one. */
		array_append_zero(&db->hosts);
	} else {
		array_foreach_elem(hostnames, hostname) {
			host = array_append_space(&db->hosts);
			host->hostname = i_strdup(hostname);
		}
	}

	i_array_init(&db->all_connections, 16);
	return db;
}

struct sql_db *driver_sqlpool_init(const struct sql_db *driver,
				   struct event *event_parent,
				   const char *filter_name,
				   const ARRAY_TYPE(const_string) *hostnames,
				   unsigned int connection_limit)
{
	i_assert(filter_name != NULL);
	i_assert(array_count(hostnames) > 0);

	struct sqlpool_db *db =
		driver_sqlpool_init_common(driver, event_parent, hostnames,
					   connection_limit);
	db->filter_name = i_strdup(filter_name);
	sql_init_common(&db->api);

	/* connect to all databases so we can do load balancing immediately */
	sqlpool_add_all_once(db);
	return &db->api;
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
		sql_unref(&conn->db);
	array_clear(&db->all_connections);

	driver_sqlpool_abort_requests(db);

	array_foreach_modifiable(&db->hosts, host)
		i_free(host->hostname);

	i_assert(array_count(&db->all_connections) == 0);
	array_free(&db->hosts);
	array_free(&db->all_connections);
	array_free(&_db->module_contexts);
	event_unref(&_db->event);
	i_free(db->filter_name);
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

static int
driver_sqlpool_escape_string(struct sql_db *_db, const char *string,
			     const char **output_r, const char **error_r)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conns;
	unsigned int i, count;

	/* use the first ready connection */
	conns = array_get(&db->all_connections, &count);
	for (i = 0; i < count; i++) {
		if (SQL_DB_IS_READY(conns[i].db))
			return sql_escape_string(conns[i].db, string,
						 output_r, error_r);
	}
	/* no ready connections. just use the first one (we're guaranteed
	   to always have one) */
	return sql_escape_string(conns[0].db, string, output_r, error_r);
}

static void driver_sqlpool_timeout(struct sqlpool_db *db)
{
	int duration;

	while (db->requests_head != NULL) {
		struct sqlpool_request *request = db->requests_head;

		if (request->created + SQL_QUERY_TIMEOUT_SECS > ioloop_time)
			break;


		if (request->query != NULL) {
			struct event_passthrough *e =
				sql_query_finished_event(&db->api, request->event,
							 request->query, FALSE,
							 &duration)->
				add_str("error", "Query timed out");
			e_error(e->event(),
				SQL_QUERY_FINISHED_FMT": Query timed out "
	                        "(no free connections for %u secs)",
				request->query, duration,
				(unsigned int)(ioloop_time - request->created));
		} else if (request->pool_stmt != NULL) {
			struct event_passthrough *e =
				sql_query_finished_event(&db->api, request->event,
							 request->pool_stmt->api.query_template,
							 FALSE, &duration)->
				add_str("error", "Query timed out");
			e_error(e->event(),
				SQL_QUERY_FINISHED_FMT": Query timed out "
	                        "(no free connections for %"PRIdTIME_T" secs)",
				request->pool_stmt->api.query_template, duration,
				ioloop_time - request->created);
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
driver_sqlpool_request_retry(struct sqlpool_db *db,
			     struct sqlpool_request *request)
{
	const struct sqlpool_connection *conn;

	driver_sqlpool_prepend_request(db, request);
	if (driver_sqlpool_get_connection(db, request->host_idx, &conn)) {
		request->host_idx = conn->host_idx;
		sqlpool_request_send_next(db, conn->db);
	}
}

static void
driver_sqlpool_query_callback(struct sql_result *result,
			      struct sqlpool_request *request)
{
	struct sqlpool_db *db = request->db;
	struct sql_db *conndb;

	if (result->failed_try_retry &&
	    request->retry_count < array_count(&db->hosts)) {
		e_warning(db->api.event, "Query failed, retrying: %s",
			  sql_result_get_error(result));
		request->retry_count++;
		driver_sqlpool_request_retry(db, request);
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
	struct sqlpool_db *db = (struct sqlpool_db *)ctx->ctx.db;
	struct sql_db *conndb = ctx->conndb;

	ctx->callback(result, ctx->context);
	driver_sqlpool_transaction_free(ctx);

	sqlpool_request_send_next(db, conndb);
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
	struct sql_db *conndb;
	int ret;

	*error_r = NULL;

	if (!driver_sqlpool_get_sync_connection(db, &conn)) {
		*error_r = SQL_ERRSTR_NOT_CONNECTED;
		driver_sqlpool_transaction_free(ctx);
		return -1;
	}
	conndb = conn->db;

	conn_trans = driver_sqlpool_new_conn_trans(ctx, conndb);
	ret = sql_transaction_commit_s(&conn_trans, error_r);
	driver_sqlpool_transaction_free(ctx);

	/* this connection is free again - resume whatever is queued behind
	   it, the same as the async commit and statement-query completions
	   already do. */
	sqlpool_request_send_next(db, conndb);
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

static void driver_sqlpool_wait(struct sql_db *_db)
{
	struct sqlpool_db *db = (struct sqlpool_db *)_db;
	const struct sqlpool_connection *conn;

	array_foreach(&db->all_connections, conn)
		sql_wait(conn->db);
}

static struct sql_statement *
driver_sqlpool_statement_init(struct sql_db *_db, const char *query_template)
{
	struct sqlpool_db *db = container_of(_db, struct sqlpool_db, api);
	pool_t pool = pool_alloconly_create("sqlpool statement", 256);
	struct sqlpool_statement *pool_stmt =
		p_new(pool, struct sqlpool_statement, 1);
	pool_stmt->api.pool = pool;
	pool_stmt->api.query_template = p_strdup(pool, query_template);
	p_array_init(&pool_stmt->binds, pool, 8);

	const struct sqlpool_connection *conn;
	if (driver_sqlpool_get_connection(db, UINT_MAX, &conn)) {
		pool_stmt->host_idx = conn->host_idx;
		pool_stmt->stmt = sql_statement_init(conn->db, query_template);
	}
	return &pool_stmt->api;
}

static void driver_sqlpool_statement_abort(struct sql_statement *_stmt)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);

	/* sql_statement_abort() already unrefs _stmt->pool (i.e.
	   pool_stmt->api.pool) after this hook returns, so this must not
	   unref it again here. */
	if (pool_stmt->stmt != NULL)
		sql_statement_abort(&pool_stmt->stmt);
}

static void
driver_sqlpool_statement_bind_str(struct sql_statement *_stmt,
				  unsigned int column_idx, const char *value)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_bind *bind = array_append_space(&pool_stmt->binds);
	bind->type = SQLPOOL_BIND_STR;
	bind->column_idx = column_idx;
	bind->value_str = p_strdup(pool_stmt->api.pool, value);

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_bind_str(pool_stmt->stmt, column_idx, value);
}

static void
driver_sqlpool_statement_bind_uuid(struct sql_statement *_stmt,
				   unsigned int column_idx,
				   const guid_128_t value)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_bind *bind = array_append_space(&pool_stmt->binds);
	bind->type = SQLPOOL_BIND_UUID;
	bind->column_idx = column_idx;
	guid_128_copy(bind->value_uuid, value);

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_bind_uuid(pool_stmt->stmt, column_idx, value);
}

static void
driver_sqlpool_statement_bind_binary(struct sql_statement *_stmt,
				     unsigned int column_idx,
				     const void *value, size_t value_len)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_bind *bind = array_append_space(&pool_stmt->binds);
	bind->type = SQLPOOL_BIND_BINARY;
	bind->column_idx = column_idx;
	bind->value_binary = value_len == 0 ? "" :
		p_memdup(pool_stmt->api.pool, value, value_len);
	bind->value_len = value_len;

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_bind_binary(pool_stmt->stmt, column_idx, value, value_len);
}

static void
driver_sqlpool_statement_bind_int64(struct sql_statement *_stmt,
				    unsigned int column_idx, int64_t value)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_bind *bind = array_append_space(&pool_stmt->binds);
	bind->type = SQLPOOL_BIND_INT64;
	bind->column_idx = column_idx;
	bind->value_int64 = value;

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_bind_int64(pool_stmt->stmt, column_idx, value);
}

static void
driver_sqlpool_statement_bind_double(struct sql_statement *_stmt,
				     unsigned int column_idx, double value)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_bind *bind = array_append_space(&pool_stmt->binds);
	bind->type = SQLPOOL_BIND_DOUBLE;
	bind->column_idx = column_idx;
	bind->value_double = value;

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_bind_double(pool_stmt->stmt, column_idx, value);
}

/* Replays every bind recorded on pool_stmt onto stmt (a freshly created
   statement on a, possibly different, connection), so a retry never has
   to render the query to plain text to carry its bind values across. */
static void
sqlpool_statement_replay_binds(const struct sqlpool_statement *pool_stmt,
			       struct sql_statement *stmt)
{
	const struct sqlpool_bind *bind;

	array_foreach(&pool_stmt->binds, bind) {
		switch (bind->type) {
		case SQLPOOL_BIND_STR:
			sql_statement_bind_str(stmt, bind->column_idx,
					       bind->value_str);
			break;
		case SQLPOOL_BIND_BINARY:
			sql_statement_bind_binary(stmt, bind->column_idx,
						  bind->value_binary,
						  bind->value_len);
			break;
		case SQLPOOL_BIND_INT64:
			sql_statement_bind_int64(stmt, bind->column_idx,
						 bind->value_int64);
			break;
		case SQLPOOL_BIND_DOUBLE:
			sql_statement_bind_double(stmt, bind->column_idx,
						  bind->value_double);
			break;
		case SQLPOOL_BIND_UUID:
			sql_statement_bind_uuid(stmt, bind->column_idx,
						bind->value_uuid);
			break;
		}
	}
	sql_statement_set_no_log_expanded_values(
		stmt, pool_stmt->no_log_expanded_values);
	if (array_is_created(&pool_stmt->no_log_field_idxs)) {
		const unsigned int *column_idx;
		array_foreach(&pool_stmt->no_log_field_idxs, column_idx)
			sql_statement_set_no_log_expanded_value_field(
				stmt, *column_idx);
	}
}

static void
driver_sqlpool_statement_set_no_log_expanded_values(struct sql_statement *_stmt,
						     bool no_expand)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	pool_stmt->no_log_expanded_values = no_expand;

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_set_no_log_expanded_values(pool_stmt->stmt, no_expand);
}

static void
driver_sqlpool_statement_set_no_log_expanded_value_field(
	struct sql_statement *_stmt, unsigned int column_idx)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	if (!array_is_created(&pool_stmt->no_log_field_idxs)) {
		p_array_init(&pool_stmt->no_log_field_idxs,
			    pool_stmt->api.pool, 1);
	}
	array_push_back(&pool_stmt->no_log_field_idxs, &column_idx);
	pool_stmt->no_log_expanded_values = FALSE;

	if (pool_stmt->stmt == NULL)
		return;
	sql_statement_set_no_log_expanded_value_field(pool_stmt->stmt,
						       column_idx);
}

static struct sql_result *
driver_sqlpool_statement_query_s(struct sql_statement *_stmt)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_db *db = container_of(_stmt->db, struct sqlpool_db, api);
	struct sql_result *res;

	if (pool_stmt->stmt != NULL)
		res = sql_statement_query_s(&pool_stmt->stmt);
	else {
		/* No connection was available when the statement was
		   created. Try one now and build a real statement on it
		   instead of falling back to default_sql_statement_query_s(),
		   which would render the query to plain text. */
		const struct sqlpool_connection *conn;
		if (!driver_sqlpool_get_sync_connection(db, &conn)) {
			pool_unref(&_stmt->pool);
			sql_not_connected_result.refcount++;
			return &sql_not_connected_result;
		}
		struct sql_statement *stmt =
			sql_statement_init(conn->db, pool_stmt->api.query_template);
		sqlpool_statement_replay_binds(pool_stmt, stmt);
		res = sql_statement_query_s(&stmt);
	}

	if (res->failed_try_retry) {
		/* The backend statement's pool is gone now -
		   sql_statement_query_s() already freed it whether the
		   query succeeded or not. Build a fresh statement on the
		   new connection and replay pool_stmt's recorded binds onto
		   it, the same as the async path does, instead of ever
		   rendering the query to plain text. Retries a single time
		   without avoiding the host that just failed, matching
		   driver_sqlpool_query_s(). */
		const struct sqlpool_connection *conn;
		if (driver_sqlpool_get_sync_connection(db, &conn)) {
			sql_result_unref(res);
			struct sql_statement *stmt =
				sql_statement_init(conn->db,
						   pool_stmt->api.query_template);
			sqlpool_statement_replay_binds(pool_stmt, stmt);
			res = sql_statement_query_s(&stmt);
		}
	}
	pool_unref(&_stmt->pool);
	return res;
}

/* Builds a fresh statement on conn, replays pool_stmt's recorded binds
   onto it, and issues it - used both for the very first attempt when no
   connection was available at statement_init() time, and for a retry
   after a connection failure. Takes over pool_stmt's single pool
   reference; the caller must not touch pool_stmt again. */
static void
sqlpool_statement_query_on(struct sqlpool_db *db,
			   const struct sqlpool_connection *conn,
			   struct sqlpool_statement *pool_stmt,
			   sql_query_callback_t *callback, void *context,
			   unsigned int retry_count)
{
	struct sql_statement *stmt =
		sql_statement_init(conn->db, pool_stmt->api.query_template);
	sqlpool_statement_replay_binds(pool_stmt, stmt);

	struct sqlpool_statement_query *query =
		i_new(struct sqlpool_statement_query, 1);
	query->db = db;
	query->pool_stmt = pool_stmt;
	query->callback = callback;
	query->context = context;
	query->host_idx = conn->host_idx;
	query->retry_count = retry_count;

	sql_statement_query(&stmt, driver_sqlpool_statement_query_callback, query);
}

/* Queues a statement for a connection instead of sending it immediately -
   used for the very first attempt when no connection is available at
   statement_init() time, always at retry_count 0. A later retry after a
   connection failure goes through driver_sqlpool_request_retry() instead,
   which preserves the accumulated retry_count. */
static void
sqlpool_statement_send(struct sqlpool_db *db, struct sqlpool_statement *pool_stmt,
		       sql_query_callback_t *callback, void *context)
{
	const struct sqlpool_connection *conn;

	if (!driver_sqlpool_get_connection(db, UINT_MAX, &conn)) {
		struct sqlpool_request *request =
			sqlpool_request_new_stmt(db, pool_stmt);
		request->callback = callback;
		request->context = context;
		driver_sqlpool_append_request(db, request);
		return;
	}
	sqlpool_statement_query_on(db, conn, pool_stmt, callback, context, 0);
}

static void
driver_sqlpool_statement_query_callback(struct sql_result *result,
					struct sqlpool_statement_query *query)
{
	struct sqlpool_db *db = query->db;

	if (result->failed_try_retry &&
	    query->retry_count < array_count(&db->hosts)) {
		e_warning(db->api.event, "Query failed, retrying: %s",
			  sql_result_get_error(result));

		struct sqlpool_request *request =
			sqlpool_request_new_stmt(db, query->pool_stmt);
		request->callback = query->callback;
		request->context = query->context;
		request->retry_count = query->retry_count + 1;
		request->host_idx = query->host_idx;

		i_free(query);

		driver_sqlpool_request_retry(db, request);
		return;
	}

	sql_query_callback_t *callback = query->callback;
	void *cb_context = query->context;
	struct sqlpool_statement *pool_stmt = query->pool_stmt;
	struct sql_db *conndb = result->db;

	i_free(query);

	if (callback != NULL)
		callback(result, cb_context);
	pool_unref(&pool_stmt->api.pool);

	sqlpool_request_send_next(db, conndb);
}

static void
driver_sqlpool_statement_query(struct sql_statement *_stmt,
			       sql_query_callback_t *callback, void *context)
{
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);
	struct sqlpool_db *db = container_of(_stmt->db, struct sqlpool_db, api);

	if (pool_stmt->stmt == NULL) {
		/* No connection was available when the statement was
		   created. Queue it exactly like a retry after a connection
		   failure - once a connection is ready, a real backend
		   statement is built from the recorded binds, so the query
		   is never rendered to plain text here either. */
		sqlpool_statement_send(db, pool_stmt, callback, context);
		return;
	}

	struct sqlpool_statement_query *query =
		i_new(struct sqlpool_statement_query, 1);
	query->db = db;
	query->pool_stmt = pool_stmt;
	query->callback = callback;
	query->context = context;
	query->host_idx = pool_stmt->host_idx;

	sql_statement_query(&pool_stmt->stmt,
			    driver_sqlpool_statement_query_callback, query);
}

static void
driver_sqlpool_update_stmt(struct sql_transaction_context *_ctx,
			   struct sql_statement *_stmt,
			   unsigned int *affected_rows)
{
	struct sqlpool_transaction_context *ctx =
		container_of(_ctx, struct sqlpool_transaction_context, ctx);
	struct sqlpool_statement *pool_stmt =
		container_of(_stmt, struct sqlpool_statement, api);

	if (pool_stmt->stmt == NULL) {
		/* No connection was available when the statement was
		   created. Defer building the real backend statement until
		   driver_sqlpool_new_conn_trans() knows which connection the
		   transaction will use, instead of rendering the query (and
		   its bind values) to plain text via default_sql_update_stmt()
		   now. _stmt (the sqlpool wrapper, with its recorded binds)
		   is what gets resolved there. */
		pool_add_external_ref(ctx->query_pool, _stmt->pool);
		sql_transaction_add_stmt(&ctx->ctx, ctx->query_pool,
					 _stmt, affected_rows);
		pool_unref(&_stmt->pool);
		return;
	}
	pool_add_external_ref(ctx->query_pool, pool_stmt->stmt->pool);
	pool_unref(&pool_stmt->stmt->pool);
	sql_transaction_add_stmt(&ctx->ctx, ctx->query_pool,
				 pool_stmt->stmt, affected_rows);
	pool_unref(&_stmt->pool);
}

struct sql_db driver_sqlpool_db = {
	"",

	.v = {
		.get_flags = driver_sqlpool_get_flags,
		.deinit = driver_sqlpool_deinit,
		.connect = driver_sqlpool_connect,
		.disconnect = driver_sqlpool_disconnect,
		.escape_string = driver_sqlpool_escape_string,
		.exec = driver_sqlpool_exec,
		.query = driver_sqlpool_query,
		.query_s = driver_sqlpool_query_s,
		.wait = driver_sqlpool_wait,

		.transaction_begin = driver_sqlpool_transaction_begin,
		.transaction_commit = driver_sqlpool_transaction_commit,
		.transaction_commit_s = driver_sqlpool_transaction_commit_s,
		.transaction_rollback = driver_sqlpool_transaction_rollback,

		.update = driver_sqlpool_update,

		.escape_blob = driver_sqlpool_escape_blob,

		.statement_init = driver_sqlpool_statement_init,
		.statement_abort = driver_sqlpool_statement_abort,
		.statement_bind_str = driver_sqlpool_statement_bind_str,
		.statement_bind_uuid = driver_sqlpool_statement_bind_uuid,
		.statement_bind_int64 = driver_sqlpool_statement_bind_int64,
		.statement_bind_binary = driver_sqlpool_statement_bind_binary,
		.statement_bind_double = driver_sqlpool_statement_bind_double,
		.statement_set_no_log_expanded_values =
			driver_sqlpool_statement_set_no_log_expanded_values,
		.statement_set_no_log_expanded_value_field =
			driver_sqlpool_statement_set_no_log_expanded_value_field,
		.statement_query_s = driver_sqlpool_statement_query_s,
		.statement_query = driver_sqlpool_statement_query,

		.update_stmt = driver_sqlpool_update_stmt,
	}
};
