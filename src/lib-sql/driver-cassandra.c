/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "write-full.h"
#include "sql-api-private.h"

#ifdef BUILD_CASSANDRA
#include <unistd.h>
#include <cassandra.h>

#define IS_CONNECTED(db) \
	((db)->api.state != SQL_DB_STATE_DISCONNECTED && \
	 (db)->api.state != SQL_DB_STATE_CONNECTING)

typedef void driver_cassandra_callback_t(CassFuture *future, void *context);

struct cassandra_callback {
	unsigned int id;
	CassFuture *future;
	struct cassandra_db *db;
	driver_cassandra_callback_t *callback;
	void *context;
};

struct cassandra_db {
	struct sql_db api;

	char *hosts, *keyspace;
	CassConsistency consistency;

	CassCluster *cluster;
	CassSession *session;

	int fd_pipe[2];
	struct io *io_pipe;
	ARRAY(struct cassandra_callback *) callbacks;
	unsigned int callback_ids;

	struct cassandra_result *cur_result;
	struct ioloop *ioloop, *orig_ioloop;
	struct sql_result *sync_result;

	char *error;

	unsigned int set_consistency:1;
};

struct cassandra_result {
	struct sql_result api;
	CassStatement *statement;
	const CassResult *result;
	CassIterator *iterator;
	char *query;
	char *error;

	pool_t row_pool;
	ARRAY_TYPE(const_string) fields;

	sql_query_callback_t *callback;
	void *context;

	unsigned int finished:1;
};

struct cassandra_transaction_context {
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

extern const struct sql_db driver_cassandra_db;
extern const struct sql_result driver_cassandra_result;

static struct {
	CassConsistency consistency;
	const char *name;
} cass_consistency_names[] = {
	{ CASS_CONSISTENCY_ANY, "any" },
	{ CASS_CONSISTENCY_ONE, "one" },
	{ CASS_CONSISTENCY_TWO, "two" },
	{ CASS_CONSISTENCY_THREE, "three" },
	{ CASS_CONSISTENCY_QUORUM, "" },
	{ CASS_CONSISTENCY_ALL, "all" },
	{ CASS_CONSISTENCY_QUORUM, "" },
	{ CASS_CONSISTENCY_ALL, "all" },
	{ CASS_CONSISTENCY_LOCAL_QUORUM, "local-quorum" },
	{ CASS_CONSISTENCY_EACH_QUORUM, "each-quorum" },
	{ CASS_CONSISTENCY_SERIAL, "serial" },
	{ CASS_CONSISTENCY_LOCAL_SERIAL, "local-serial" },
	{ CASS_CONSISTENCY_LOCAL_ONE, "local-one" }
};

static void result_finish(struct cassandra_result *result);

static int consistency_parse(const char *str, CassConsistency *consistency_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cass_consistency_names); i++) {
		if (strcmp(cass_consistency_names[i].name, str) == 0) {
			*consistency_r = cass_consistency_names[i].consistency;
			return 0;
		}
	}
	return -1;
}

static void driver_cassandra_set_state(struct cassandra_db *db, enum sql_db_state state)
{
	i_assert(state == SQL_DB_STATE_BUSY || db->cur_result == NULL);

	/* switch back to original ioloop in case the caller wants to
	   add/remove timeouts */
	if (db->ioloop != NULL)
		io_loop_set_current(db->orig_ioloop);
	sql_db_set_state(&db->api, state);
	if (db->ioloop != NULL)
		io_loop_set_current(db->ioloop);
}

static void driver_cassandra_close(struct cassandra_db *db)
{
	if (db->io_pipe != NULL)
		io_remove(&db->io_pipe);
	if (db->fd_pipe[0] != -1) {
		i_close_fd(&db->fd_pipe[0]);
		i_close_fd(&db->fd_pipe[1]);
	}
	driver_cassandra_set_state(db, SQL_DB_STATE_DISCONNECTED);

	if (db->ioloop != NULL) {
		/* running a sync query, stop it */
		io_loop_stop(db->ioloop);
	}
}

static void driver_cassandra_log_error(CassFuture *future, const char *str)
{
	const char *message;
	size_t size;

	cass_future_error_message(future, &message, &size);
	i_error("cassandra: %s: %.*s", str, (int)size, message);
}

static void driver_cassandra_future_callback(CassFuture *future ATTR_UNUSED,
					     void *context)
{
	struct cassandra_callback *cb = context;

	/* this isn't the main thread - communicate with main thread by
	   writing the callback id to the pipe */
	if (write_full(cb->db->fd_pipe[1], &cb->id, sizeof(cb->id)) < 0)
		i_error("cassandra: write(pipe) failed: %m");
}

static void cassandra_callback_run(struct cassandra_callback *cb)
{
	cb->callback(cb->future, cb->context);
	cass_future_free(cb->future);
	i_free(cb);
}

static void driver_cassandra_input_id(struct cassandra_db *db, unsigned int id)
{
	struct cassandra_callback *cb, *const *cbp;

	/* usually there are only a few callbacks, so don't bother with using
	   a hash table */
	array_foreach(&db->callbacks, cbp) {
		cb = *cbp;
		if (cb->id == id) {
			array_delete(&db->callbacks,
				     array_foreach_idx(&db->callbacks, cbp), 1);
			cassandra_callback_run(cb);
			return;
		}
	}
	i_panic("cassandra: Received unknown ID %u", id);
}

static void driver_cassandra_input(struct cassandra_db *db)
{
	unsigned int ids[1024];
	ssize_t ret;

	ret = read(db->fd_pipe[0], ids, sizeof(ids));
	if (ret < 0)
		i_error("cassandra: read(pipe) failed: %m");
	else if (ret == 0)
		i_error("cassandra: read(pipe) failed: EOF");
	else if (ret % sizeof(ids[0]) != 0)
		i_error("cassandra: read(pipe) returned wrong amount of data");
	else {
		/* success */
		unsigned int i, count = ret / sizeof(ids[0]);

		for (i = 0; i < count && db->api.state != SQL_DB_STATE_DISCONNECTED; i++)
			driver_cassandra_input_id(db, ids[i]);
		return;
	}
	driver_cassandra_close(db);
}

static void
driver_cassandra_set_callback(CassFuture *future, struct cassandra_db *db,
			      driver_cassandra_callback_t *callback,
			      void *context)
{
	struct cassandra_callback *cb;

	cb = i_new(struct cassandra_callback, 1);
	cb->id = ++db->callback_ids;
	cb->future = future;
	cb->callback = callback;
	cb->context = context;
	cb->db = db;
	array_append(&db->callbacks, &cb, 1);

	cass_future_set_callback(future, driver_cassandra_future_callback, cb);
}

static void connect_callback(CassFuture *future, void *context)
{
	struct cassandra_db *db = context;
	CassError rc;

	if ((rc = cass_future_error_code(future)) != CASS_OK) {
		driver_cassandra_log_error(future,
					   "Couldn't connect to Cassandra");
		driver_cassandra_close(db);
		return;
	}
	driver_cassandra_set_state(db, SQL_DB_STATE_IDLE);
	if (db->ioloop != NULL) {
		/* driver_cassandra_sync_init() waiting for connection to
		   finish */
		io_loop_stop(db->ioloop);
	}
}

static int driver_cassandra_connect(struct sql_db *_db)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;
	CassFuture *future;

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	if (pipe(db->fd_pipe) < 0) {
		i_error("pipe() failed: %m");
		return -1;
	}
	db->io_pipe = io_add(db->fd_pipe[0], IO_READ,
			     driver_cassandra_input, db);
	driver_cassandra_set_state(db, SQL_DB_STATE_CONNECTING);

	future = cass_session_connect_keyspace(db->session, db->cluster, db->keyspace);
	driver_cassandra_set_callback(future, db, connect_callback, db);
	return 0;
}

static void driver_cassandra_disconnect(struct sql_db *_db)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;

	if (db->cur_result != NULL && !db->cur_result->finished)
                result_finish(db->cur_result);
	driver_cassandra_close(db);
}

static const char *
driver_cassandra_escape_string(struct sql_db *db ATTR_UNUSED,
			       const char *string)
{
	string_t *escaped;
	unsigned int i;

	if (strchr(string, '\'') == NULL)
		return string;
	escaped = t_str_new(strlen(string)+10);
	for (i = 0; string[i] != '\0'; i++) {
		if (string[i] == '\'')
			str_append_c(escaped, '\'');
		str_append_c(escaped, string[i]);
	}
	return str_c(escaped);
}

static void driver_cassandra_parse_connect_string(struct cassandra_db *db,
						  const char *connect_string)
{
	const char *const *args, *key, *value;
	string_t *hosts = t_str_new(64);

	args = t_strsplit_spaces(connect_string, " ");
	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL) {
			i_fatal("cassandra: Missing value in connect string: %s",
				*args);
		}
		key = t_strdup_until(*args, value++);

		if (strcmp(key, "host") == 0) {
			if (str_len(hosts) > 0)
				str_append_c(hosts, ',');
			str_append(hosts, value);
		} else if (strcmp(key, "dbname") == 0 ||
			   strcmp(key, "keyspace") == 0) {
			i_free(db->keyspace);
			db->keyspace = i_strdup(value);
		} else if (strcmp(key, "consistency") == 0) {
			if (consistency_parse(value, &db->consistency) < 0)
				i_fatal("cassandra: Unknown consistency: %s", value);
			db->set_consistency = TRUE;
		} else {
			i_fatal("cassandra: Unknown connect string: %s", key);
		}
	}

	if (str_len(hosts) == 0)
		i_fatal("cassandra: No hosts given in connect string");
	if (db->keyspace == NULL)
		i_fatal("cassandra: No dbname given in connect string");
	db->hosts = i_strdup(str_c(hosts));
}

static struct sql_db *driver_cassandra_init_v(const char *connect_string)
{
	struct cassandra_db *db;

	db = i_new(struct cassandra_db, 1);
	db->api = driver_cassandra_db;
	db->fd_pipe[0] = db->fd_pipe[1] = -1;

	T_BEGIN {
		driver_cassandra_parse_connect_string(db, connect_string);
	} T_END;

	db->cluster = cass_cluster_new();
	cass_cluster_set_connect_timeout(db->cluster, SQL_CONNECT_TIMEOUT_SECS * 1000);
	cass_cluster_set_request_timeout(db->cluster, SQL_QUERY_TIMEOUT_SECS * 1000);
	cass_cluster_set_contact_points(db->cluster, db->hosts);
	db->session = cass_session_new();
	i_array_init(&db->callbacks, 16);
	return &db->api;
}

static void driver_cassandra_deinit_v(struct sql_db *_db)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;

	if (db->cur_result != NULL && !db->cur_result->finished)
                result_finish(db->cur_result);
        driver_cassandra_close(db);

	i_assert(array_count(&db->callbacks) == 0);
	array_free(&db->callbacks);

	cass_session_free(db->session);
	cass_cluster_free(db->cluster);
	i_free(db->hosts);
	i_free(db->error);
	i_free(db->keyspace);
	array_free(&_db->module_contexts);
	i_free(db);
}

static void driver_cassandra_set_idle(struct cassandra_db *db)
{
	i_assert(db->api.state == SQL_DB_STATE_BUSY);

	driver_cassandra_set_state(db, SQL_DB_STATE_IDLE);
}

static void driver_cassandra_result_free(struct sql_result *_result)
{
	struct cassandra_db *db = (struct cassandra_db *)_result->db;
        struct cassandra_result *result = (struct cassandra_result *)_result;

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

	driver_cassandra_set_idle(db);
	cass_result_free(result->result);
	cass_iterator_free(result->iterator);
	cass_statement_free(result->statement);
	pool_unref(&result->row_pool);
	i_free(result->query);
	i_free(result->error);
	i_free(result);
}

static void result_finish(struct cassandra_result *result)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	bool free_result = TRUE;

	result->finished = TRUE;

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

static void query_callback(CassFuture *future, void *context)
{
	struct cassandra_result *result = context;

	if (cass_future_error_code(future) != CASS_OK) {
		const char *errmsg;
		size_t errsize;

		cass_future_error_message(future, &errmsg, &errsize);
		i_free(result->error);
		result->error = i_strdup_printf("Query '%s' failed: %.*s",
						result->query,
						(int)errsize, errmsg);
		result_finish(result);
		return;
	}
	result->result = cass_future_get_result(future);
	result->iterator = cass_iterator_from_result(result->result);
	result_finish(result);
}

static void do_query(struct cassandra_result *result, const char *query)
{
        struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	CassFuture *future;

	i_assert(SQL_DB_IS_READY(&db->api));
	i_assert(db->cur_result == NULL);

	driver_cassandra_set_state(db, SQL_DB_STATE_BUSY);
	db->cur_result = result;

	result->query = i_strdup(query);
	result->row_pool = pool_alloconly_create("cassandra result", 512);
	result->statement = cass_statement_new(query, 0);
	if (db->set_consistency)
		cass_statement_set_consistency(result->statement, db->consistency);
	future = cass_session_execute(db->session, result->statement);
	driver_cassandra_set_callback(future, db, query_callback, result);
}

static void exec_callback(struct sql_result *_result ATTR_UNUSED,
			  void *context ATTR_UNUSED)
{
}

static void driver_cassandra_exec(struct sql_db *db, const char *query)
{
	struct cassandra_result *result;

	result = i_new(struct cassandra_result, 1);
	result->api = driver_cassandra_result;
	result->api.db = db;
	result->api.refcount = 1;
	result->callback = exec_callback;
	do_query(result, query);
}

static void driver_cassandra_query(struct sql_db *db, const char *query,
				   sql_query_callback_t *callback, void *context)
{
	struct cassandra_result *result;

	result = i_new(struct cassandra_result, 1);
	result->api = driver_cassandra_result;
	result->api.db = db;
	result->api.refcount = 1;
	result->callback = callback;
	result->context = context;
	do_query(result, query);
}

static void cassandra_query_s_callback(struct sql_result *result, void *context)
{
        struct cassandra_db *db = context;

	db->sync_result = result;
}

static void driver_cassandra_sync_init(struct cassandra_db *db)
{
	if (sql_connect(&db->api) < 0)
		return;
	db->orig_ioloop = current_ioloop;
	db->ioloop = io_loop_create();
	if (IS_CONNECTED(db))
		return;
	i_assert(db->api.state == SQL_DB_STATE_CONNECTING);

	db->io_pipe = io_loop_move_io(&db->io_pipe);
	/* wait for connecting to finish */
	io_loop_run(db->ioloop);
}

static void driver_cassandra_sync_deinit(struct cassandra_db *db)
{
	if (db->orig_ioloop == NULL)
		return;
	if (db->io_pipe != NULL) {
		io_loop_set_current(db->orig_ioloop);
		db->io_pipe = io_loop_move_io(&db->io_pipe);
		io_loop_set_current(db->ioloop);
	}
	io_loop_destroy(&db->ioloop);
}

static struct sql_result *
driver_cassandra_sync_query(struct cassandra_db *db, const char *query)
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

	driver_cassandra_query(&db->api, query, cassandra_query_s_callback, db);
	if (db->sync_result == NULL) {
		db->io_pipe = io_loop_move_io(&db->io_pipe);
		io_loop_run(db->ioloop);
	}

	result = db->sync_result;
	if (result == &sql_not_connected_result) {
		/* we don't end up in cassandra's free function, so sync_result
		   won't be set to NULL if we don't do it here. */
		db->sync_result = NULL;
	} else if (result == NULL) {
		result = &sql_not_connected_result;
		result->refcount++;
	}
	return result;
}

static struct sql_result *
driver_cassandra_query_s(struct sql_db *_db, const char *query)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;
	struct sql_result *result;

	driver_cassandra_sync_init(db);
	result = driver_cassandra_sync_query(db, query);
	driver_cassandra_sync_deinit(db);
	return result;
}

static int
driver_cassandra_get_value(struct cassandra_result *result,
			   const CassValue *value, const char **str_r)
{
	const char *output;
	size_t output_size;
	CassError rc;

	if (cass_value_is_null(value)) {
		*str_r = NULL;
		return 0;
	}

	rc = cass_value_get_string(value, &output, &output_size);
	if (rc != CASS_OK) {
		i_free(result->error);
		result->error = i_strdup_printf("Couldn't get value as string (code=%d)", rc);
		return -1;
	}
	*str_r = p_strndup(result->row_pool, output, output_size);
	return 0;
}

static int driver_cassandra_result_next_row(struct sql_result *_result)
{
	struct cassandra_result *result = (struct cassandra_result *)_result;
	const CassRow *row;
	const CassValue *value;
	const char *str;
	unsigned int i;
	int ret = 1;

	if (result->iterator == NULL)
		return -1;

	if (!cass_iterator_next(result->iterator))
		return 0;

	p_clear(result->row_pool);
	p_array_init(&result->fields, result->row_pool, 8);

	row = cass_iterator_get_row(result->iterator);
	for (i = 0; (value = cass_row_get_column(row, i)) != NULL; i++) {
		if (driver_cassandra_get_value(result, value, &str) < 0) {
			ret = -1;
			break;
		}
		array_append(&result->fields, &str, 1);
	}
	return ret;
}

static unsigned int
driver_cassandra_result_get_fields_count(struct sql_result *_result)
{
	struct cassandra_result *result = (struct cassandra_result *)_result;

	return array_count(&result->fields);
}

static const char *
driver_cassandra_result_get_field_name(struct sql_result *_result ATTR_UNUSED,
				       unsigned int idx ATTR_UNUSED)
{
	i_unreached();
}

static int
driver_cassandra_result_find_field(struct sql_result *_result ATTR_UNUSED,
				   const char *field_name ATTR_UNUSED)
{
	i_unreached();
}

static const char *
driver_cassandra_result_get_field_value(struct sql_result *_result,
					unsigned int idx)
{
	struct cassandra_result *result = (struct cassandra_result *)_result;
	const char *const *strp;

	strp = array_idx(&result->fields, idx);
	return *strp;
}

static const unsigned char *
driver_cassandra_result_get_field_value_binary(struct sql_result *_result ATTR_UNUSED,
					       unsigned int idx ATTR_UNUSED,
					       size_t *size_r ATTR_UNUSED)
{
	i_unreached();
}

static const char *
driver_cassandra_result_find_field_value(struct sql_result *result ATTR_UNUSED,
					 const char *field_name ATTR_UNUSED)
{
	i_unreached();
}

static const char *const *
driver_cassandra_result_get_values(struct sql_result *_result)
{
	struct cassandra_result *result = (struct cassandra_result *)_result;

	return array_idx(&result->fields, 0);
}

static const char *driver_cassandra_result_get_error(struct sql_result *_result)
{
	struct cassandra_result *result = (struct cassandra_result *)_result;

	if (result->error != NULL)
		return result->error;
	return "FIXME";
}

static struct sql_transaction_context *
driver_cassandra_transaction_begin(struct sql_db *db)
{
	struct cassandra_transaction_context *ctx;

	ctx = i_new(struct cassandra_transaction_context, 1);
	ctx->ctx.db = db;
	ctx->refcount = 1;
	/* we need to be able to handle multiple open transactions, so at least
	   for now just keep them in memory until commit time. */
	ctx->query_pool = pool_alloconly_create("cassandra transaction", 1024);
	return &ctx->ctx;
}

static void
driver_cassandra_transaction_unref(struct cassandra_transaction_context *ctx)
{
	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;

	pool_unref(&ctx->query_pool);
	i_free(ctx);
}

static void
transaction_begin_callback(struct sql_result *result,
			   struct cassandra_transaction_context *ctx)
{
	if (sql_result_next_row(result) < 0) {
		ctx->begin_failed = TRUE;
		ctx->failed = TRUE;
		ctx->error = sql_result_get_error(result);
	} else {
		ctx->begin_succeeded = TRUE;
	}
	driver_cassandra_transaction_unref(ctx);
}

static void
transaction_commit_callback(struct sql_result *result,
			    struct cassandra_transaction_context *ctx)
{
	if (sql_result_next_row(result) < 0)
		ctx->callback(sql_result_get_error(result), ctx->context);
	else
		ctx->callback(NULL, ctx->context);
	driver_cassandra_transaction_unref(ctx);
}

static void
transaction_update_callback(struct sql_result *result,
			    struct sql_transaction_query *query)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)query->trans;

	if (sql_result_next_row(result) < 0) {
		ctx->failed = TRUE;
		ctx->error = sql_result_get_error(result);
	}
	driver_cassandra_transaction_unref(ctx);
}

static void
driver_cassandra_transaction_commit(struct sql_transaction_context *_ctx,
				sql_commit_callback_t *callback, void *context)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	ctx->callback = callback;
	ctx->context = context;

	if (ctx->failed || _ctx->head == NULL) {
		callback(ctx->failed ? ctx->error : NULL, context);
		driver_cassandra_transaction_unref(ctx);
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
commit_multi_fail(struct cassandra_transaction_context *ctx,
		  struct sql_result *result, const char *query)
{
	ctx->failed = TRUE;
	ctx->error = t_strdup_printf("%s (query: %s)",
				     sql_result_get_error(result), query);
	sql_result_unref(result);
}

static struct sql_result *
driver_cassandra_transaction_commit_multi(struct cassandra_transaction_context *ctx)
{
	struct cassandra_db *db = (struct cassandra_db *)ctx->ctx.db;
	struct sql_result *result;
	struct sql_transaction_query *query;

	result = driver_cassandra_sync_query(db, "BEGIN");
	if (sql_result_next_row(result) < 0) {
		commit_multi_fail(ctx, result, "BEGIN");
		return NULL;
	}
	sql_result_unref(result);

	/* send queries */
	for (query = ctx->ctx.head; query != NULL; query = query->next) {
		result = driver_cassandra_sync_query(db, query->query);
		if (sql_result_next_row(result) < 0) {
			commit_multi_fail(ctx, result, query->query);
			break;
		}
		sql_result_unref(result);
	}

	return driver_cassandra_sync_query(db, ctx->failed ?
				       "ROLLBACK" : "COMMIT");
}

static void
driver_cassandra_try_commit_s(struct cassandra_transaction_context *ctx,
			      const char **error_r)
{
	struct sql_transaction_context *_ctx = &ctx->ctx;
	struct cassandra_db *db = (struct cassandra_db *)_ctx->db;
	struct sql_transaction_query *single_query = NULL;
	struct sql_result *result;

	if (_ctx->head->next == NULL) {
		/* just a single query, send it */
		single_query = _ctx->head;
		result = sql_query_s(_ctx->db, single_query->query);
	} else {
		/* multiple queries, use a transaction */
		driver_cassandra_sync_init(db);
		result = driver_cassandra_transaction_commit_multi(ctx);
		driver_cassandra_sync_deinit(db);
	}

	if (ctx->failed) {
		i_assert(ctx->error != NULL);
		*error_r = ctx->error;
	} else if (result != NULL) {
		if (sql_result_next_row(result) < 0)
			*error_r = sql_result_get_error(result);
	}
	*error_r = t_strdup(*error_r);
	if (result != NULL)
		sql_result_unref(result);
}

static int
driver_cassandra_transaction_commit_s(struct sql_transaction_context *_ctx,
				      const char **error_r)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	*error_r = NULL;

	if (_ctx->head != NULL)
		driver_cassandra_try_commit_s(ctx, error_r);

	i_assert(ctx->refcount == 1);
	driver_cassandra_transaction_unref(ctx);
	return *error_r == NULL ? 0 : -1;
}

static void
driver_cassandra_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	i_assert(ctx->refcount == 1);
	driver_cassandra_transaction_unref(ctx);
}

static void
driver_cassandra_update(struct sql_transaction_context *_ctx, const char *query,
			unsigned int *affected_rows)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	i_assert(affected_rows == NULL);

	sql_transaction_add_query(_ctx, ctx->query_pool, query, affected_rows);
}

const struct sql_db driver_cassandra_db = {
	.name = "cassandra",
	.flags = 0,

	.v = {
		driver_cassandra_init_v,
		driver_cassandra_deinit_v,
		driver_cassandra_connect,
		driver_cassandra_disconnect,
		driver_cassandra_escape_string,
		driver_cassandra_exec,
		driver_cassandra_query,
		driver_cassandra_query_s,

		driver_cassandra_transaction_begin,
		driver_cassandra_transaction_commit,
		driver_cassandra_transaction_commit_s,
		driver_cassandra_transaction_rollback,

		driver_cassandra_update
	}
};

const struct sql_result driver_cassandra_result = {
	.v = {
		driver_cassandra_result_free,
		driver_cassandra_result_next_row,
		driver_cassandra_result_get_fields_count,
		driver_cassandra_result_get_field_name,
		driver_cassandra_result_find_field,
		driver_cassandra_result_get_field_value,
		driver_cassandra_result_get_field_value_binary,
		driver_cassandra_result_find_field_value,
		driver_cassandra_result_get_values,
		driver_cassandra_result_get_error
	}
};

const char *driver_cassandra_version = DOVECOT_ABI_VERSION;

void driver_cassandra_init(void);
void driver_cassandra_deinit(void);

void driver_cassandra_init(void)
{
	sql_driver_register(&driver_cassandra_db);
}

void driver_cassandra_deinit(void)
{
	sql_driver_unregister(&driver_cassandra_db);
}

#endif
