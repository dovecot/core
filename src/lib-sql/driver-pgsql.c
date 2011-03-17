/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "sql-api-private.h"

#ifdef BUILD_PGSQL
#include <stdlib.h>
#include <libpq-fe.h>

struct pgsql_db {
	struct sql_db api;

	pool_t pool;
	char *connect_string;
	char *host;
	PGconn *pg;

	struct io *io;
	struct timeout *to_connect;
	enum io_condition io_dir;

	struct pgsql_result *cur_result;
	struct ioloop *ioloop, *orig_ioloop;
	struct sql_result *sync_result;

	char *error;

	unsigned int fatal_error:1;
};

struct pgsql_binary_value {
	unsigned char *value;
	size_t size;
};

struct pgsql_result {
	struct sql_result api;
	PGresult *pgres;
	struct timeout *to;

	unsigned int rownum, rows;
	unsigned int fields_count;
	const char **fields;
	const char **values;

	ARRAY_DEFINE(binary_values, struct pgsql_binary_value);

	sql_query_callback_t *callback;
	void *context;

	unsigned int timeout:1;
};

struct pgsql_transaction_context {
	struct sql_transaction_context ctx;
	int refcount;

	sql_commit_callback_t *callback;
	void *context;

	pool_t query_pool;
	const char *error;

	unsigned int begin_succeeded:1;
	unsigned int begin_failed:1;
	unsigned int failed:1;
};

extern const struct sql_db driver_pgsql_db;
extern const struct sql_result driver_pgsql_result;

static void result_finish(struct pgsql_result *result);

static const char *pgsql_prefix(struct pgsql_db *db)
{
	return db->host == NULL ? "pgsql" :
		t_strdup_printf("pgsql(%s)", db->host);
}

static void driver_pgsql_set_state(struct pgsql_db *db, enum sql_db_state state)
{
	i_assert(state == SQL_DB_STATE_BUSY || db->cur_result == NULL);

	/* switch back to original ioloop in case the caller wants to
	   add/remove timeouts */
	if (db->ioloop != NULL)
		current_ioloop = db->orig_ioloop;
	sql_db_set_state(&db->api, state);
	if (db->ioloop != NULL)
		current_ioloop = db->ioloop;
}

static void driver_pgsql_stop_io(struct pgsql_db *db)
{
	if (db->io != NULL) {
		io_remove(&db->io);
		db->io_dir = 0;
	}
}

static void driver_pgsql_close(struct pgsql_db *db)
{
	db->io_dir = 0;
	db->fatal_error = FALSE;

	driver_pgsql_stop_io(db);

	PQfinish(db->pg);
	db->pg = NULL;

	if (db->to_connect != NULL)
		timeout_remove(&db->to_connect);

	driver_pgsql_set_state(db, SQL_DB_STATE_DISCONNECTED);

	if (db->ioloop != NULL) {
		/* running a sync query, stop it */
		io_loop_stop(db->ioloop);
	}
}

static const char *last_error(struct pgsql_db *db)
{
	const char *msg;
	size_t len;

	msg = PQerrorMessage(db->pg);
	if (msg == NULL)
		return "(no error set)";

	/* Error message should contain trailing \n, we don't want it */
	len = strlen(msg);
	return len == 0 || msg[len-1] != '\n' ? msg :
		t_strndup(msg, len-1);
}

static void connect_callback(struct pgsql_db *db)
{
	enum io_condition io_dir = 0;
	int ret;

	driver_pgsql_stop_io(db);

	while ((ret = PQconnectPoll(db->pg)) == PGRES_POLLING_ACTIVE)
		;

	switch (ret) {
	case PGRES_POLLING_READING:
		io_dir = IO_READ;
		break;
	case PGRES_POLLING_WRITING:
		io_dir = IO_WRITE;
		break;
	case PGRES_POLLING_OK:
		break;
	case PGRES_POLLING_FAILED:
		i_error("%s: Connect failed to database %s: %s",
			pgsql_prefix(db), PQdb(db->pg), last_error(db));
		driver_pgsql_close(db);
		return;
	}

	if (io_dir != 0) {
		db->io = io_add(PQsocket(db->pg), io_dir, connect_callback, db);
		db->io_dir = io_dir;
	}

	if (io_dir == 0) {
		i_info("%s: Connected to database %s",
		       pgsql_prefix(db), PQdb(db->pg));
		if (db->to_connect != NULL)
			timeout_remove(&db->to_connect);
		driver_pgsql_set_state(db, SQL_DB_STATE_IDLE);
		if (db->ioloop != NULL) {
			/* driver_pgsql_sync_init() waiting for connection to
			   finish */
			io_loop_stop(db->ioloop);
		}
	}
}

static void driver_pgsql_connect_timeout(struct pgsql_db *db)
{
	unsigned int secs = ioloop_time - db->api.last_connect_try;

	i_error("%s: Connect failed: Timeout after %u seconds",
		pgsql_prefix(db), secs);
	driver_pgsql_close(db);
}

static int driver_pgsql_connect(struct sql_db *_db)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	db->pg = PQconnectStart(db->connect_string);
	if (db->pg == NULL) {
		i_fatal("%s: PQconnectStart() failed (out of memory)",
			pgsql_prefix(db));
	}

	if (PQstatus(db->pg) == CONNECTION_BAD) {
		i_error("%s: Connect failed to database %s: %s",
			pgsql_prefix(db), PQdb(db->pg), last_error(db));
		driver_pgsql_close(db);
		return -1;
	}

	/* nonblocking connecting begins. */
	if (PQsetnonblocking(db->pg, 1) < 0)
		i_error("%s: PQsetnonblocking() failed", pgsql_prefix(db));
	i_assert(db->to_connect == NULL);
	db->to_connect = timeout_add(SQL_CONNECT_TIMEOUT_SECS * 1000,
				     driver_pgsql_connect_timeout, db);
	db->io = io_add(PQsocket(db->pg), IO_WRITE, connect_callback, db);
	db->io_dir = IO_WRITE;
	driver_pgsql_set_state(db, SQL_DB_STATE_CONNECTING);
	return 0;
}

static void driver_pgsql_disconnect(struct sql_db *_db)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;

	if (db->cur_result != NULL && db->cur_result->to != NULL)
                result_finish(db->cur_result);

	_db->no_reconnect = TRUE;
	driver_pgsql_close(db);
	_db->no_reconnect = FALSE;
}

static struct sql_db *driver_pgsql_init_v(const char *connect_string)
{
	struct pgsql_db *db;

	db = i_new(struct pgsql_db, 1);
	db->connect_string = i_strdup(connect_string);
	db->api = driver_pgsql_db;

	T_BEGIN {
		const char *const *arg = t_strsplit(connect_string, " ");

		for (; *arg != NULL; arg++) {
			if (strncmp(*arg, "host=", 5) == 0)
				db->host = i_strdup(*arg + 5);
		}
	} T_END;
	return &db->api;
}

static void driver_pgsql_deinit_v(struct sql_db *_db)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;

	if (db->cur_result != NULL && db->cur_result->to != NULL)
                result_finish(db->cur_result);

	_db->no_reconnect = TRUE;
        driver_pgsql_close(db);
	i_free(db->host);
	i_free(db->error);
	i_free(db->connect_string);
	array_free(&_db->module_contexts);
	i_free(db);
}

static void driver_pgsql_set_idle(struct pgsql_db *db)
{
	i_assert(db->api.state == SQL_DB_STATE_BUSY);

	if (db->fatal_error)
		driver_pgsql_close(db);
	else
		driver_pgsql_set_state(db, SQL_DB_STATE_IDLE);
}

static void consume_results(struct pgsql_db *db)
{
	PGresult *pgres;

	driver_pgsql_stop_io(db);

	while (PQconsumeInput(db->pg)) {
		if (PQisBusy(db->pg)) {
			db->io = io_add(PQsocket(db->pg), IO_READ,
					consume_results, db);
			db->io_dir = IO_READ;
			return;
		}

		pgres = PQgetResult(db->pg);
		if (pgres == NULL)
			break;
		PQclear(pgres);
	}

	if (PQstatus(db->pg) == CONNECTION_BAD)
		driver_pgsql_close(db);
	else
		driver_pgsql_set_idle(db);
}

static void driver_pgsql_result_free(struct sql_result *_result)
{
	struct pgsql_db *db = (struct pgsql_db *)_result->db;
        struct pgsql_result *result = (struct pgsql_result *)_result;
	bool success;

	if (result->api.callback) {
		/* we're coming here from a user's sql_result_free() that's
		   being called from a callback. we'll do this later,
		   so ignore. */
		return;
	}

	i_assert(db->cur_result == result);
	i_assert(result->callback == NULL);

	if (_result == db->sync_result)
		db->sync_result = NULL;
	db->cur_result = NULL;

	success = result->pgres != NULL && !db->fatal_error;
	if (result->pgres != NULL) {
		PQclear(result->pgres);
		result->pgres = NULL;
	}

	if (success) {
		/* we'll have to read the rest of the results as well */
		i_assert(db->io == NULL);
		consume_results(db);
	} else {
		driver_pgsql_set_idle(db);
	}

	if (array_is_created(&result->binary_values)) {
		struct pgsql_binary_value *value;

		array_foreach_modifiable(&result->binary_values, value)
			PQfreemem(value->value);
		array_free(&result->binary_values);
	}

	i_free(result->fields);
	i_free(result->values);
	i_free(result);
}

static void result_finish(struct pgsql_result *result)
{
	struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	bool free_result = TRUE;

	i_assert(db->io == NULL);
	timeout_remove(&result->to);

	/* if connection to server was lost, we don't yet see that the
	   connection is bad. we only see the fatal error, so assume it also
	   means disconnection. */
	if (PQstatus(db->pg) == CONNECTION_BAD || result->pgres == NULL ||
	    PQresultStatus(result->pgres) == PGRES_FATAL_ERROR)
		db->fatal_error = TRUE;

	if (db->fatal_error) {
		result->api.failed = TRUE;
		result->api.failed_try_retry = TRUE;
	}
	result->api.callback = TRUE;
	T_BEGIN {
		result->callback(&result->api, result->context);
	} T_END;
	result->api.callback = FALSE;
	result->callback = NULL;

	free_result = db->sync_result != &result->api;
	if (db->ioloop != NULL)
		io_loop_stop(db->ioloop);

	if (free_result)
		sql_result_unref(&result->api);
}

static void get_result(struct pgsql_result *result)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;

	driver_pgsql_stop_io(db);

	if (!PQconsumeInput(db->pg)) {
		result_finish(result);
		return;
	}

	if (PQisBusy(db->pg)) {
		db->io = io_add(PQsocket(db->pg), IO_READ,
				get_result, result);
		db->io_dir = IO_READ;
		return;
	}

	result->pgres = PQgetResult(db->pg);
	result_finish(result);
}

static void flush_callback(struct pgsql_result *result)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	int ret;

	driver_pgsql_stop_io(db);

	ret = PQflush(db->pg);
	if (ret > 0) {
		db->io = io_add(PQsocket(db->pg), IO_WRITE,
				flush_callback, result);
		db->io_dir = IO_WRITE;
		return;
	}

	if (ret < 0) {
		result_finish(result);
	} else {
		/* all flushed */
		get_result(result);
	}
}

static void query_timeout(struct pgsql_result *result)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;

	driver_pgsql_stop_io(db);

	i_error("%s: Query timed out, aborting", pgsql_prefix(db));
	result->timeout = TRUE;
	result_finish(result);
}

static void do_query(struct pgsql_result *result, const char *query)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	int ret;

	i_assert(SQL_DB_IS_READY(&db->api));
	i_assert(db->cur_result == NULL);
	i_assert(db->io == NULL);

	driver_pgsql_set_state(db, SQL_DB_STATE_BUSY);
	db->cur_result = result;
	result->to = timeout_add(SQL_QUERY_TIMEOUT_SECS * 1000,
				 query_timeout, result);

	if (!PQsendQuery(db->pg, query) ||
	    (ret = PQflush(db->pg)) < 0) {
		/* failed to send query */
		result_finish(result);
		return;
	}

	if (ret > 0) {
		/* write blocks */
		db->io = io_add(PQsocket(db->pg), IO_WRITE,
				flush_callback, result);
		db->io_dir = IO_WRITE;
	} else {
		get_result(result);
	}
}

static const char *
driver_pgsql_escape_string(struct sql_db *_db, const char *string)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;
	size_t len = strlen(string);
	char *to;

#ifdef HAVE_PQESCAPE_STRING_CONN
	if (db->api.state == SQL_DB_STATE_DISCONNECTED) {
		/* try connecting again */
		(void)sql_connect(&db->api);
	}
	if (db->api.state != SQL_DB_STATE_DISCONNECTED) {
		to = t_buffer_get(len * 2 + 1);
		len = PQescapeStringConn(db->pg, to, string, len, NULL);
	} else
#endif
	{
		to = t_buffer_get(len * 2 + 1);
		len = PQescapeString(to, string, len);
	}
	t_buffer_alloc(len + 1);
	return to;
}

static void exec_callback(struct sql_result *_result,
			  void *context ATTR_UNUSED)
{
	struct pgsql_db *db = (struct pgsql_db *)_result->db;

	i_error("%s: sql_exec() failed: %s", pgsql_prefix(db), last_error(db));
}

static void driver_pgsql_exec(struct sql_db *db, const char *query)
{
	struct pgsql_result *result;

	result = i_new(struct pgsql_result, 1);
	result->api = driver_pgsql_result;
	result->api.db = db;
	result->api.refcount = 1;
	result->callback = exec_callback;
	do_query(result, query);
}

static void driver_pgsql_query(struct sql_db *db, const char *query,
			       sql_query_callback_t *callback, void *context)
{
	struct pgsql_result *result;

	result = i_new(struct pgsql_result, 1);
	result->api = driver_pgsql_result;
	result->api.db = db;
	result->api.refcount = 1;
	result->callback = callback;
	result->context = context;
	do_query(result, query);
}

static void pgsql_query_s_callback(struct sql_result *result, void *context)
{
        struct pgsql_db *db = context;

	db->sync_result = result;
}

static void driver_pgsql_sync_init(struct pgsql_db *db)
{
	bool add_to_connect;

	db->orig_ioloop = current_ioloop;
	if (db->io == NULL) {
		db->ioloop = io_loop_create();
		return;
	}

	i_assert(db->api.state == SQL_DB_STATE_CONNECTING);

	/* have to move our existing I/O and timeout handlers to new I/O loop */
	io_remove(&db->io);
	if (db->to_connect != NULL) {
		timeout_remove(&db->to_connect);
		add_to_connect = TRUE;
	} else {
		add_to_connect = FALSE;
	}

	db->ioloop = io_loop_create();
	if (add_to_connect) {
		db->to_connect = timeout_add(SQL_CONNECT_TIMEOUT_SECS * 1000,
					     driver_pgsql_connect_timeout, db);
	}
	db->io = io_add(PQsocket(db->pg), db->io_dir, connect_callback, db);
	/* wait for connecting to finish */
	io_loop_run(db->ioloop);
}

static void driver_pgsql_sync_deinit(struct pgsql_db *db)
{
	io_loop_destroy(&db->ioloop);
}

static struct sql_result *
driver_pgsql_sync_query(struct pgsql_db *db, const char *query)
{
	struct sql_result *result;

	i_assert(db->sync_result == NULL);

	switch (db->api.state) {
	case SQL_DB_STATE_CONNECTING:
	case SQL_DB_STATE_BUSY:
		i_unreached();
	case SQL_DB_STATE_DISCONNECTED:
		sql_not_connected_result.refcount++;
		return &sql_not_connected_result;
	case SQL_DB_STATE_IDLE:
		break;
	}

	driver_pgsql_query(&db->api, query, pgsql_query_s_callback, db);
	if (db->sync_result == NULL)
		io_loop_run(db->ioloop);

	i_assert(db->io == NULL);

	result = db->sync_result;
	if (result == &sql_not_connected_result) {
		/* we don't end up in pgsql's free function, so sync_result
		   won't be set to NULL if we don't do it here. */
		db->sync_result = NULL;
	}

	i_assert(db->io == NULL);
	return result;
}

static struct sql_result *
driver_pgsql_query_s(struct sql_db *_db, const char *query)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;
	struct sql_result *result;

	driver_pgsql_sync_init(db);
	result = driver_pgsql_sync_query(db, query);
	driver_pgsql_sync_deinit(db);
	return result;
}

static int driver_pgsql_result_next_row(struct sql_result *_result)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;
	struct pgsql_db *db = (struct pgsql_db *)_result->db;

	if (result->rows != 0) {
		/* second time we're here */
		if (++result->rownum < result->rows)
			return 1;

		/* end of this packet. see if there's more. FIXME: this may
		   block, but the current API doesn't provide a non-blocking
		   way to do this.. */
		PQclear(result->pgres);
		result->pgres = PQgetResult(db->pg);
		if (result->pgres == NULL)
			return 0;
	}

	if (result->pgres == NULL) {
		_result->failed = TRUE;
		return -1;
	}

	switch (PQresultStatus(result->pgres)) {
	case PGRES_COMMAND_OK:
		/* no rows returned */
		return 0;
	case PGRES_TUPLES_OK:
		result->rows = PQntuples(result->pgres);
		return result->rows > 0;
	case PGRES_EMPTY_QUERY:
	case PGRES_NONFATAL_ERROR:
		/* nonfatal error */
		_result->failed = TRUE;
		return -1;
	default:
		/* treat as fatal error */
		_result->failed = TRUE;
		db->fatal_error = TRUE;
		return -1;
	}
}

static void driver_pgsql_result_fetch_fields(struct pgsql_result *result)
{
	unsigned int i;

	if (result->fields != NULL)
		return;

	/* @UNSAFE */
	result->fields_count = PQnfields(result->pgres);
	result->fields = i_new(const char *, result->fields_count);
	for (i = 0; i < result->fields_count; i++)
		result->fields[i] = PQfname(result->pgres, i);
}

static unsigned int
driver_pgsql_result_get_fields_count(struct sql_result *_result)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;

        driver_pgsql_result_fetch_fields(result);
	return result->fields_count;
}

static const char *
driver_pgsql_result_get_field_name(struct sql_result *_result, unsigned int idx)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;

	driver_pgsql_result_fetch_fields(result);
	i_assert(idx < result->fields_count);
	return result->fields[idx];
}

static int driver_pgsql_result_find_field(struct sql_result *_result,
					  const char *field_name)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;
	unsigned int i;

	driver_pgsql_result_fetch_fields(result);
	for (i = 0; i < result->fields_count; i++) {
		if (strcmp(result->fields[i], field_name) == 0)
			return i;
	}
	return -1;
}

static const char *
driver_pgsql_result_get_field_value(struct sql_result *_result,
				    unsigned int idx)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;

	if (PQgetisnull(result->pgres, result->rownum, idx))
		return NULL;

	return PQgetvalue(result->pgres, result->rownum, idx);
}

static const unsigned char *
driver_pgsql_result_get_field_value_binary(struct sql_result *_result,
					   unsigned int idx, size_t *size_r)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;
	const char *value;
	struct pgsql_binary_value *binary_value;

	if (PQgetisnull(result->pgres, result->rownum, idx)) {
		*size_r = 0;
		return NULL;
	}

	value = PQgetvalue(result->pgres, result->rownum, idx);

	if (!array_is_created(&result->binary_values))
		i_array_init(&result->binary_values, idx + 1);

	binary_value = array_idx_modifiable(&result->binary_values, idx);
	if (binary_value->value == NULL) {
		binary_value->value =
			PQunescapeBytea((const unsigned char *)value,
					&binary_value->size);
	}

	*size_r = binary_value->size;
	return binary_value->value;
}

static const char *
driver_pgsql_result_find_field_value(struct sql_result *result,
				     const char *field_name)
{
	int idx;

	idx = driver_pgsql_result_find_field(result, field_name);
	if (idx < 0)
		return NULL;
	return driver_pgsql_result_get_field_value(result, idx);
}

static const char *const *
driver_pgsql_result_get_values(struct sql_result *_result)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;
	unsigned int i;

	if (result->values == NULL) {
		driver_pgsql_result_fetch_fields(result);
		result->values = i_new(const char *, result->fields_count);
	}

	/* @UNSAFE */
	for (i = 0; i < result->fields_count; i++) {
		result->values[i] =
                        driver_pgsql_result_get_field_value(_result, i);
	}

	return result->values;
}

static const char *driver_pgsql_result_get_error(struct sql_result *_result)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;
	struct pgsql_db *db = (struct pgsql_db *)_result->db;
	const char *msg;
	size_t len;

	i_free_and_null(db->error);

	if (result->timeout) {
		db->error = i_strdup("Query timed out");
	} else if (result->pgres == NULL) {
		/* connection error */
		db->error = i_strdup(last_error(db));
	} else {
		msg = PQresultErrorMessage(result->pgres);
		if (msg == NULL)
			return "(no error set)";

		/* Error message should contain trailing \n, we don't want it */
		len = strlen(msg);
		db->error = len == 0 || msg[len-1] != '\n' ?
			i_strdup(msg) : i_strndup(msg, len-1);
	}
	return db->error;
}

static struct sql_transaction_context *
driver_pgsql_transaction_begin(struct sql_db *db)
{
	struct pgsql_transaction_context *ctx;

	ctx = i_new(struct pgsql_transaction_context, 1);
	ctx->ctx.db = db;
	ctx->refcount = 1;
	/* we need to be able to handle multiple open transactions, so at least
	   for now just keep them in memory until commit time. */
	ctx->query_pool = pool_alloconly_create("pgsql transaction", 1024);
	return &ctx->ctx;
}

static void
driver_pgsql_transaction_unref(struct pgsql_transaction_context *ctx)
{
	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;

	pool_unref(&ctx->query_pool);
	i_free(ctx);
}

static void
transaction_begin_callback(struct sql_result *result,
			   struct pgsql_transaction_context *ctx)
{
	if (sql_result_next_row(result) < 0) {
		ctx->begin_failed = TRUE;
		ctx->failed = TRUE;
		ctx->error = sql_result_get_error(result);
	} else {
		ctx->begin_succeeded = TRUE;
	}
	driver_pgsql_transaction_unref(ctx);
}

static void
transaction_commit_callback(struct sql_result *result,
			    struct pgsql_transaction_context *ctx)
{
	if (sql_result_next_row(result) < 0)
		ctx->callback(sql_result_get_error(result), ctx->context);
	else
		ctx->callback(NULL, ctx->context);
	driver_pgsql_transaction_unref(ctx);
}

static void
transaction_update_callback(struct sql_result *result,
			    struct sql_transaction_query *query)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)query->trans;

	if (sql_result_next_row(result) < 0) {
		ctx->failed = TRUE;
		ctx->error = sql_result_get_error(result);
	} else if (query->affected_rows != NULL) {
		struct pgsql_result *pg_result = (struct pgsql_result *)result;

		*query->affected_rows = atoi(PQcmdTuples(pg_result->pgres));
	}
	driver_pgsql_transaction_unref(ctx);
}

static void
driver_pgsql_transaction_commit(struct sql_transaction_context *_ctx,
				sql_commit_callback_t *callback, void *context)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;

	ctx->callback = callback;
	ctx->context = context;

	if (ctx->failed || _ctx->head == NULL) {
		callback(ctx->failed ? ctx->error : NULL, context);
		driver_pgsql_transaction_unref(ctx);
	} else if (_ctx->head->next == NULL) {
		/* just a single query, send it */
		sql_query(_ctx->db, _ctx->head->query,
			  transaction_commit_callback, ctx);
	} else {
		/* multiple queries, use a transaction */
		ctx->refcount++;
		sql_query(_ctx->db, "BEGIN", transaction_begin_callback, ctx);
		while (_ctx->head != NULL) {
			ctx->refcount++;
			sql_query(_ctx->db, _ctx->head->query,
				  transaction_update_callback, _ctx->head);
			_ctx->head = _ctx->head->next;
		}
		sql_query(_ctx->db, "COMMIT", transaction_commit_callback, ctx);
	}
}

static void
commit_multi_fail(struct pgsql_transaction_context *ctx,
		  struct sql_result *result, const char *query)
{
	ctx->failed = TRUE;
	ctx->error = t_strdup_printf("%s (query: %s)",
				     sql_result_get_error(result), query);
	sql_result_unref(result);
}

static struct sql_result *
driver_pgsql_transaction_commit_multi(struct pgsql_transaction_context *ctx)
{
	struct pgsql_db *db = (struct pgsql_db *)ctx->ctx.db;
	struct sql_result *result;
	struct sql_transaction_query *query;

	result = driver_pgsql_sync_query(db, "BEGIN");
	if (sql_result_next_row(result) < 0) {
		commit_multi_fail(ctx, result, "BEGIN");
		return NULL;
	}
	sql_result_unref(result);

	/* send queries */
	for (query = ctx->ctx.head; query != NULL; query = query->next) {
		result = driver_pgsql_sync_query(db, query->query);
		if (sql_result_next_row(result) < 0) {
			commit_multi_fail(ctx, result, query->query);
			break;
		}
		if (query->affected_rows != NULL) {
			struct pgsql_result *pg_result =
				(struct pgsql_result *)result;

			*query->affected_rows =
				atoi(PQcmdTuples(pg_result->pgres));
		}
		sql_result_unref(result);
	}

	return driver_pgsql_sync_query(db, ctx->failed ?
				       "ROLLBACK" : "COMMIT");
}

static int
driver_pgsql_transaction_commit_s(struct sql_transaction_context *_ctx,
				  const char **error_r)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;
	struct pgsql_db *db = (struct pgsql_db *)_ctx->db;
	struct sql_transaction_query *single_query = NULL;
	struct sql_result *result;

	*error_r = NULL;

	if (ctx->failed || _ctx->head == NULL) {
		/* nothing to be done */
		result = NULL;
	} else if (_ctx->head->next == NULL) {
		/* just a single query, send it */
		single_query = _ctx->head;
		result = sql_query_s(_ctx->db, single_query->query);
	} else {
		/* multiple queries, use a transaction */
		driver_pgsql_sync_init(db);
		result = driver_pgsql_transaction_commit_multi(ctx);
		driver_pgsql_sync_deinit(db);
	}

	if (ctx->failed) {
		i_assert(ctx->error != NULL);
		*error_r = ctx->error;
	} else if (result != NULL) {
		if (sql_result_next_row(result) < 0)
			*error_r = sql_result_get_error(result);
		else if (single_query != NULL &&
			 single_query->affected_rows != NULL) {
			struct pgsql_result *pg_result =
				(struct pgsql_result *)result;

			*single_query->affected_rows =
				atoi(PQcmdTuples(pg_result->pgres));
		}
	}
	if (result != NULL)
		sql_result_unref(result);

	i_assert(ctx->refcount == 1);
	driver_pgsql_transaction_unref(ctx);
	return *error_r == NULL ? 0 : -1;
}

static void
driver_pgsql_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;

	i_assert(ctx->refcount == 1);
	driver_pgsql_transaction_unref(ctx);
}

static void
driver_pgsql_update(struct sql_transaction_context *_ctx, const char *query,
		    unsigned int *affected_rows)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;

	sql_transaction_add_query(_ctx, ctx->query_pool, query, affected_rows);
}

const struct sql_db driver_pgsql_db = {
	.name = "pgsql",
	.flags = SQL_DB_FLAG_POOLED,

	.v = {
		driver_pgsql_init_v,
		driver_pgsql_deinit_v,
		driver_pgsql_connect,
		driver_pgsql_disconnect,
		driver_pgsql_escape_string,
		driver_pgsql_exec,
		driver_pgsql_query,
		driver_pgsql_query_s,

		driver_pgsql_transaction_begin,
		driver_pgsql_transaction_commit,
		driver_pgsql_transaction_commit_s,
		driver_pgsql_transaction_rollback,

		driver_pgsql_update
	}
};

const struct sql_result driver_pgsql_result = {
	.v = {
		driver_pgsql_result_free,
		driver_pgsql_result_next_row,
		driver_pgsql_result_get_fields_count,
		driver_pgsql_result_get_field_name,
		driver_pgsql_result_find_field,
		driver_pgsql_result_get_field_value,
		driver_pgsql_result_get_field_value_binary,
		driver_pgsql_result_find_field_value,
		driver_pgsql_result_get_values,
		driver_pgsql_result_get_error
	}
};

const char *driver_pgsql_version = DOVECOT_VERSION;

void driver_pgsql_init(void);
void driver_pgsql_deinit(void);

void driver_pgsql_init(void)
{
	sql_driver_register(&driver_pgsql_db);
}

void driver_pgsql_deinit(void)
{
	sql_driver_unregister(&driver_pgsql_db);
}

#endif
