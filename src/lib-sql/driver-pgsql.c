/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "ioloop-internal.h" /* kind of dirty, but it should be fine.. */
#include "sql-api-private.h"

#ifdef BUILD_PGSQL
#include <stdlib.h>
#include <time.h>
#include <libpq-fe.h>

struct pgsql_db {
	struct sql_db api;

	pool_t pool;
	const char *connect_string;
	PGconn *pg;

	struct io *io;
	enum io_condition io_dir;

	struct pgsql_queue *queue, **queue_tail;
	struct timeout *queue_to;

	struct ioloop *ioloop;
	struct sql_result *sync_result;

	char *error;
	time_t last_connect;
	unsigned int connecting:1;
	unsigned int connected:1;
	unsigned int querying:1;
};

struct pgsql_result {
	struct sql_result api;
	PGresult *pgres;

	unsigned int rownum, rows;
	unsigned int fields_count;
	const char **fields;
	const char **values;

	sql_query_callback_t *callback;
	void *context;
};

struct pgsql_queue {
	struct pgsql_queue *next;

	time_t created;
	char *query;
	struct pgsql_result *result;
};

struct pgsql_transaction_context {
	struct sql_transaction_context ctx;

	sql_commit_callback_t *callback;
	void *context;

	const char *error;

	unsigned int opened:1;
	unsigned int failed:1;
};

extern struct sql_db driver_pgsql_db;
extern struct sql_result driver_pgsql_result;

static void queue_send_next(struct pgsql_db *db);
static void result_finish(struct pgsql_result *result);

static void driver_pgsql_close(struct pgsql_db *db)
{
	if (db->io != NULL)
		io_remove(&db->io);
	db->io_dir = 0;

	PQfinish(db->pg);
	db->pg = NULL;

	db->connecting = FALSE;
	db->connected = FALSE;
        db->querying = FALSE;
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
		i_info("pgsql: Connected to %s", PQdb(db->pg));
		db->connecting = FALSE;
		db->connected = TRUE;
		break;
	case PGRES_POLLING_FAILED:
		i_error("pgsql: Connect failed to %s: %s",
			PQdb(db->pg), last_error(db));
		driver_pgsql_close(db);
		return;
	}

	if (db->io_dir != io_dir) {
		if (db->io != NULL)
			io_remove(&db->io);
		db->io = io_dir == 0 ? NULL :
			io_add(PQsocket(db->pg), io_dir, connect_callback, db);
		db->io_dir = io_dir;
	}

	if (db->connected && db->queue != NULL)
		queue_send_next(db);
}

static int driver_pgsql_connect(struct sql_db *_db)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;
	time_t now;

	/* don't try reconnecting more than once a second */
	now = time(NULL);
	if (db->connecting || db->last_connect == now)
		return db->connected ? 1 : (db->connecting ? 0 : -1);
	db->last_connect = now;

	db->pg = PQconnectStart(db->connect_string);
	if (db->pg == NULL)
		i_fatal("pgsql: PQconnectStart() failed (out of memory)");

	if (PQstatus(db->pg) == CONNECTION_BAD) {
		i_error("pgsql: Connect failed to %s: %s",
			PQdb(db->pg), last_error(db));
		driver_pgsql_close(db);
		return -1;
	} else {
		/* nonblocking connecting begins. */
		db->io = io_add(PQsocket(db->pg), IO_WRITE,
				connect_callback, db);
		db->io_dir = IO_WRITE;
		db->connecting = TRUE;
		return 0;
	}
}

static struct sql_db *_driver_pgsql_init(const char *connect_string)
{
	struct pgsql_db *db;

	i_assert(connect_string != NULL);

	db = i_new(struct pgsql_db, 1);
	db->connect_string = i_strdup(connect_string);
	db->api = driver_pgsql_db;
	db->queue_tail = &db->queue;
	return &db->api;
}

static void _driver_pgsql_deinit(struct sql_db *_db)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;

	while (db->queue != NULL) {
		struct pgsql_queue *next = db->queue->next;

                result_finish(db->queue->result);
		i_free(db->queue->query);
		i_free(db->queue);

		db->queue = next;
	}

	if (db->queue_to != 0)
		timeout_remove(&db->queue_to);
        driver_pgsql_close(db);
	i_free(db->error);
	i_free(db);
}

static enum sql_db_flags
driver_pgsql_get_flags(struct sql_db *db __attr_unused__)
{
	return 0;
}

static void consume_results(struct pgsql_db *db)
{
	do {
		if (!PQconsumeInput(db->pg))
			break;

		if (PQisBusy(db->pg))
			return;
	} while (PQgetResult(db->pg) != NULL);

	io_remove(&db->io);

	db->querying = FALSE;
	if (db->queue != NULL && db->connected)
		queue_send_next(db);
}

static void driver_pgsql_result_free(struct sql_result *_result)
{
	struct pgsql_db *db = (struct pgsql_db *)_result->db;
        struct pgsql_result *result = (struct pgsql_result *)_result;

	if (result->api.callback)
		return;

	if (result->pgres != NULL) {
		PQclear(result->pgres);

		/* we'll have to read the rest of the results as well */
		i_assert(db->io == NULL);
		db->io = io_add(PQsocket(db->pg), IO_READ,
				consume_results, db);
		db->io_dir = IO_READ;
		consume_results(db);
	} else {
		db->querying = FALSE;
	}

	i_free(result->fields);
	i_free(result->values);
	i_free(result);

	if (db->queue != NULL && !db->querying && db->connected)
		queue_send_next(db);
}

static void result_finish(struct pgsql_result *result)
{
	struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	bool free_result = TRUE;

	if (result->callback != NULL) {
		result->api.callback = TRUE;
		t_push();
		result->callback(&result->api, result->context);
		t_pop();
		result->api.callback = FALSE;
		free_result = db->sync_result != &result->api;
	}
	if (free_result)
		driver_pgsql_result_free(&result->api);

	if (PQstatus(db->pg) == CONNECTION_BAD) {
		/* disconnected */
		driver_pgsql_close(db);
	}
}

static void get_result(struct pgsql_result *result)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;

	if (!PQconsumeInput(db->pg)) {
		db->connected = FALSE;
		result_finish(result);
		return;
	}

	if (PQisBusy(db->pg)) {
		if (db->io == NULL) {
 			db->io = io_add(PQsocket(db->pg), IO_READ,
					get_result, result);
			db->io_dir = IO_READ;
		}
		return;
	}

	if (db->io != NULL)
		io_remove(&db->io);

	result->pgres = PQgetResult(db->pg);
	result_finish(result);
}

static void flush_callback(struct pgsql_result *result)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	int ret;

	ret = PQflush(db->pg);
	if (ret > 0)
		return;

	io_remove(&db->io);

	if (ret < 0) {
		db->connected = FALSE;
		result_finish(result);
	} else {
		/* all flushed */
		get_result(result);
	}
}

static void send_query(struct pgsql_result *result, const char *query)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	int ret;

	i_assert(db->io == NULL);
	i_assert(!db->querying);
	i_assert(db->connected);

	if (!PQsendQuery(db->pg, query)) {
		db->connected = FALSE;
		result_finish(result);
		return;
	}

	ret = PQflush(db->pg);
	if (ret < 0) {
		db->connected = FALSE;
		result_finish(result);
		return;
	}

	db->querying = TRUE;
	if (ret > 0) {
		/* write blocks */
		db->io = io_add(PQsocket(db->pg), IO_WRITE,
				flush_callback, result);
		db->io_dir = IO_WRITE;
	} else {
		get_result(result);
	}
}

static void queue_send_next(struct pgsql_db *db)
{
	struct pgsql_queue *queue;

	queue = db->queue;
	db->queue = queue->next;

	if (db->queue == NULL)
		db->queue_tail = &db->queue;

	send_query(queue->result, queue->query);

	i_free(queue->query);
	i_free(queue);
}

static void queue_timeout(struct pgsql_db *db)
{
	if (db->querying)
		return;

	if (!db->connected) {
		driver_pgsql_connect(&db->api);
		return;
	}

	if (db->queue != NULL)
		queue_send_next(db);

	if (db->queue == NULL)
		timeout_remove(&db->queue_to);
}

static void
driver_pgsql_queue_query(struct pgsql_result *result, const char *query)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;
	struct pgsql_queue *queue;

	queue = i_new(struct pgsql_queue, 1);
	queue->created = time(NULL);
	queue->query = i_strdup(query);
	queue->result = result;

	*db->queue_tail = queue;
	db->queue_tail = &queue->next;

	if (db->queue_to == NULL)
		db->queue_to = timeout_add(5000, queue_timeout, db);
}

static void do_query(struct pgsql_result *result, const char *query)
{
        struct pgsql_db *db = (struct pgsql_db *)result->api.db;

	if (db->querying) {
		/* only one query at a time */
		driver_pgsql_queue_query(result, query);
		return;
	}

	if (!db->connected) {
		/* try connecting again */
		driver_pgsql_connect(&db->api);
		driver_pgsql_queue_query(result, query);
		return;
	}

	if (db->queue == NULL)
		send_query(result, query);
	else {
		/* there's already queries queued, send them first */
		driver_pgsql_queue_query(result, query);
		queue_send_next(db);
	}
}

static void exec_callback(struct sql_result *result,
			  void *context __attr_unused__)
{
        struct pgsql_db *db = (struct pgsql_db *)result->db;

	i_error("pgsql: sql_exec() failed: %s", last_error(db));
}

static const char *
driver_pgsql_escape_string(struct sql_db *_db, const char *string)
{
	struct pgsql_db *db = (struct pgsql_db *)_db;
	size_t len = strlen(string);
	char *to;

	to = t_buffer_get(len * 2 + 1);
#ifdef HAVE_PQESCAPE_STRING_CONN
	len = PQescapeStringConn(db->pg, to, string, len, NULL);
#else
	len = PQescapeString(to, string, len);
#endif
	t_buffer_alloc(len + 1);
	return to;
}

static void driver_pgsql_exec(struct sql_db *db, const char *query)
{
	struct pgsql_result *result;

	result = i_new(struct pgsql_result, 1);
	result->api = driver_pgsql_result;
	result->api.db = db;
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
	result->callback = callback;
	result->context = context;

	do_query(result, query);
}

static void pgsql_query_s_callback(struct sql_result *result, void *context)
{
        struct pgsql_db *db = context;

	db->sync_result = result;
	io_loop_stop(db->ioloop);
}

static struct sql_result *
driver_pgsql_query_s(struct sql_db *_db, const char *query)
{
        struct pgsql_db *db = (struct pgsql_db *)_db;
	struct io old_io;

	if (db->io == NULL)
		db->ioloop = io_loop_create(default_pool);
	else {
		/* have to move our existing I/O handler to new I/O loop */
		old_io = *db->io;
		io_remove(&db->io);

		db->ioloop = io_loop_create(default_pool);

		db->io = io_add(old_io.fd, old_io.condition,
				old_io.callback, old_io.context);
	}

	driver_pgsql_query(_db, query, pgsql_query_s_callback, db);

	io_loop_run(db->ioloop);
	io_loop_destroy(&db->ioloop);

	i_assert(db->io == NULL);

	return db->sync_result;
}

static int driver_pgsql_result_next_row(struct sql_result *_result)
{
	struct pgsql_result *result = (struct pgsql_result *)_result;
	struct pgsql_db *db = (struct pgsql_db *)_result->db;

	if (result->rows != 0) {
		/* second time we're here */
		return ++result->rownum < result->rows;
	}

	if (result->pgres == NULL)
		return -1;

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
		return -1;
	default:
		/* treat as fatal error */
		db->connected = FALSE;
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

	msg = PQresultErrorMessage(result->pgres);
	if (msg == NULL)
		return "(no error set)";

	/* Error message should contain trailing \n, we don't want it */
	len = strlen(msg);
	i_free(db->error);
	db->error = len == 0 || msg[len-1] != '\n' ?
		i_strdup(msg) : i_strndup(msg, len-1);

	return db->error;
}

static struct sql_transaction_context *
driver_pgsql_transaction_begin(struct sql_db *db)
{
	struct pgsql_transaction_context *ctx;

	ctx = i_new(struct pgsql_transaction_context, 1);
	ctx->ctx.db = db;
	return &ctx->ctx;
}

static void
transaction_commit_callback(struct sql_result *result, void *context)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)context;

	if (sql_result_next_row(result) < 0)
		ctx->callback(sql_result_get_error(result), ctx->context);
	else
		ctx->callback(NULL, ctx->context);
}

static void
driver_pgsql_transaction_commit(struct sql_transaction_context *_ctx,
				sql_commit_callback_t *callback, void *context)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;

	if (ctx->failed) {
		callback(ctx->error, context);
		sql_exec(_ctx->db, "ROLLBACK");
		i_free(ctx);
		return;
	}

	ctx->callback = callback;
	ctx->context = context;

	sql_query(_ctx->db, "COMMIT", transaction_commit_callback, ctx);
}

static int
driver_pgsql_transaction_commit_s(struct sql_transaction_context *_ctx,
				  const char **error_r)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;
	struct sql_result *result;

	if (ctx->failed) {
		*error_r = ctx->error;
		sql_exec(_ctx->db, "ROLLBACK");
	} else {
		result = sql_query_s(_ctx->db, "COMMIT");
		if (sql_result_next_row(result) < 0)
			*error_r = sql_result_get_error(result);
		else
			*error_r = NULL;
		sql_result_free(result);
	}

	i_free(ctx);
	return *error_r == NULL ? 0 : -1;
}

static void
driver_pgsql_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;

	sql_exec(_ctx->db, "ROLLBACK");
	i_free(ctx);
}

static void
transaction_update_callback(struct sql_result *result,
			    struct pgsql_transaction_context *ctx)
{
	if (sql_result_next_row(result) < 0) {
		ctx->failed = TRUE;
		ctx->error = sql_result_get_error(result);
	}
}

static void
driver_pgsql_update(struct sql_transaction_context *_ctx, const char *query)
{
	struct pgsql_transaction_context *ctx =
		(struct pgsql_transaction_context *)_ctx;

	if (ctx->failed)
		return;

	if (!ctx->opened) {
		ctx->opened = TRUE;
		sql_query(_ctx->db, "BEGIN", transaction_update_callback, ctx);
	}

	sql_query(_ctx->db, query, transaction_update_callback, ctx);
}

struct sql_db driver_pgsql_db = {
	"pgsql",

	_driver_pgsql_init,
	_driver_pgsql_deinit,
        driver_pgsql_get_flags,
	driver_pgsql_connect,
	driver_pgsql_escape_string,
	driver_pgsql_exec,
	driver_pgsql_query,
	driver_pgsql_query_s,

	driver_pgsql_transaction_begin,
	driver_pgsql_transaction_commit,
	driver_pgsql_transaction_commit_s,
	driver_pgsql_transaction_rollback,

	driver_pgsql_update
};

struct sql_result driver_pgsql_result = {
	NULL,

	driver_pgsql_result_free,
	driver_pgsql_result_next_row,
	driver_pgsql_result_get_fields_count,
	driver_pgsql_result_get_field_name,
	driver_pgsql_result_find_field,
	driver_pgsql_result_get_field_value,
	driver_pgsql_result_find_field_value,
	driver_pgsql_result_get_values,
	driver_pgsql_result_get_error,

	FALSE
};

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
