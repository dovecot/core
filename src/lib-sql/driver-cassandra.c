/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "str.h"
#include "ioloop.h"
#include "net.h"
#include "write-full.h"
#include "time-util.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "sql-api-private.h"

#ifdef BUILD_CASSANDRA
#include <fcntl.h>
#include <unistd.h>
#include <cassandra.h>

#define IS_CONNECTED(db) \
	((db)->api.state != SQL_DB_STATE_DISCONNECTED && \
	 (db)->api.state != SQL_DB_STATE_CONNECTING)

#define CASSANDRA_FALLBACK_WARN_INTERVAL_SECS 60
#define CASSANDRA_FALLBACK_FIRST_RETRY_MSECS 50
#define CASSANDRA_FALLBACK_MAX_RETRY_MSECS (1000*60)

typedef void driver_cassandra_callback_t(CassFuture *future, void *context);

enum cassandra_query_type {
	CASSANDRA_QUERY_TYPE_READ,
	CASSANDRA_QUERY_TYPE_WRITE,
	CASSANDRA_QUERY_TYPE_DELETE
};
#define CASSANDRA_QUERY_TYPE_COUNT 3

static const char *cassandra_query_type_names[CASSANDRA_QUERY_TYPE_COUNT] = {
	"read", "write", "delete"
};

struct cassandra_callback {
	unsigned int id;
	CassFuture *future;
	struct cassandra_db *db;
	driver_cassandra_callback_t *callback;
	void *context;
};

struct cassandra_db {
	struct sql_db api;

	char *hosts, *keyspace, *user, *password;
	CassConsistency read_consistency, write_consistency, delete_consistency;
	CassConsistency read_fallback_consistency, write_fallback_consistency, delete_fallback_consistency;
	CassLogLevel log_level;
	unsigned int protocol_version;
	unsigned int num_threads;
	unsigned int connect_timeout_secs, request_timeout_secs;
	in_port_t port;

	CassCluster *cluster;
	CassSession *session;
	CassTimestampGen *timestamp_gen;

	int fd_pipe[2];
	struct io *io_pipe;
	ARRAY(struct cassandra_callback *) callbacks;
	ARRAY(struct cassandra_result *) results;
	unsigned int callback_ids;

	char *metrics_path;
	struct timeout *to_metrics;

	struct timeval first_fallback_sent[CASSANDRA_QUERY_TYPE_COUNT];
	time_t last_fallback_warning[CASSANDRA_QUERY_TYPE_COUNT];
	unsigned int fallback_failures[CASSANDRA_QUERY_TYPE_COUNT];

	/* for synchronous queries: */
	struct ioloop *ioloop, *orig_ioloop;
	struct sql_result *sync_result;

	char *error;
};

struct cassandra_result {
	struct sql_result api;
	CassStatement *statement;
	const CassResult *result;
	CassIterator *iterator;
	char *query;
	char *error;
	CassConsistency consistency, fallback_consistency;
	enum cassandra_query_type query_type;
	struct timeval start_time, finish_time;
	unsigned int row_count;

	pool_t row_pool;
	ARRAY_TYPE(const_string) fields;
	ARRAY(size_t) field_sizes;

	sql_query_callback_t *callback;
	void *context;

	unsigned int query_sent:1;
	unsigned int finished:1;
};

struct cassandra_transaction_context {
	struct sql_transaction_context ctx;
	int refcount;

	sql_commit_callback_t *callback;
	void *context;

	pool_t query_pool;
	char *error;

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

static struct {
	CassLogLevel log_level;
	const char *name;
} cass_log_level_names[] = {
	{ CASS_LOG_CRITICAL, "critical" },
	{ CASS_LOG_ERROR, "error" },
	{ CASS_LOG_WARN, "warn" },
	{ CASS_LOG_INFO, "info" },
	{ CASS_LOG_DEBUG, "debug" },
	{ CASS_LOG_TRACE, "trace" }
};

static void driver_cassandra_result_send_query(struct cassandra_result *result);
static void driver_cassandra_send_queries(struct cassandra_db *db);
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

static int log_level_parse(const char *str, CassLogLevel *log_level_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cass_log_level_names); i++) {
		if (strcmp(cass_log_level_names[i].name, str) == 0) {
			*log_level_r = cass_log_level_names[i].log_level;
			return 0;
		}
	}
	return -1;
}

static void driver_cassandra_set_state(struct cassandra_db *db, enum sql_db_state state)
{
	/* switch back to original ioloop in case the caller wants to
	   add/remove timeouts */
	if (db->ioloop != NULL)
		io_loop_set_current(db->orig_ioloop);
	sql_db_set_state(&db->api, state);
	if (db->ioloop != NULL)
		io_loop_set_current(db->ioloop);
}

static void driver_cassandra_close(struct cassandra_db *db, const char *error)
{
	struct cassandra_result *const *resultp;

	if (db->io_pipe != NULL)
		io_remove(&db->io_pipe);
	if (db->fd_pipe[0] != -1) {
		i_close_fd(&db->fd_pipe[0]);
		i_close_fd(&db->fd_pipe[1]);
	}
	driver_cassandra_set_state(db, SQL_DB_STATE_DISCONNECTED);

	while (array_count(&db->results) > 0) {
		resultp = array_idx(&db->results, 0);
		if ((*resultp)->error == NULL)
			(*resultp)->error = i_strdup(error);
		result_finish(*resultp);
	}

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
	driver_cassandra_close(db, "IPC pipe closed");
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
		driver_cassandra_close(db, "Couldn't connect to Cassandra");
		return;
	}
	driver_cassandra_set_state(db, SQL_DB_STATE_IDLE);
	if (db->ioloop != NULL) {
		/* driver_cassandra_sync_init() waiting for connection to
		   finish */
		io_loop_stop(db->ioloop);
	}
	driver_cassandra_send_queries(db);
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

	driver_cassandra_close(db, "Disconnected");
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
	const char *const *args, *key, *value, *error;
	string_t *hosts = t_str_new(64);
	bool read_fallback_set = FALSE, write_fallback_set = FALSE, delete_fallback_set = FALSE;

	db->log_level = CASS_LOG_WARN;
	db->read_consistency = CASS_CONSISTENCY_LOCAL_QUORUM;
	db->write_consistency = CASS_CONSISTENCY_LOCAL_QUORUM;
	db->delete_consistency = CASS_CONSISTENCY_LOCAL_QUORUM;
	db->connect_timeout_secs = SQL_CONNECT_TIMEOUT_SECS;
	db->request_timeout_secs = SQL_QUERY_TIMEOUT_SECS;

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
		} else if (strcmp(key, "port") == 0) {
			if (net_str2port(value, &db->port) < 0)
				i_fatal("cassandra: Invalid port: %s", value);
		} else if (strcmp(key, "dbname") == 0 ||
			   strcmp(key, "keyspace") == 0) {
			i_free(db->keyspace);
			db->keyspace = i_strdup(value);
		} else if (strcmp(key, "user") == 0) {
			i_free(db->user);
			db->user = i_strdup(value);
		} else if (strcmp(key, "password") == 0) {
			i_free(db->password);
			db->password = i_strdup(value);
		} else if (strcmp(key, "read_consistency") == 0) {
			if (consistency_parse(value, &db->read_consistency) < 0)
				i_fatal("cassandra: Unknown read_consistency: %s", value);
		} else if (strcmp(key, "read_fallback_consistency") == 0) {
			if (consistency_parse(value, &db->read_fallback_consistency) < 0)
				i_fatal("cassandra: Unknown read_fallback_consistency: %s", value);
			read_fallback_set = TRUE;
		} else if (strcmp(key, "write_consistency") == 0) {
			if (consistency_parse(value, &db->write_consistency) < 0)
				i_fatal("cassandra: Unknown write_consistency: %s", value);
		} else if (strcmp(key, "write_fallback_consistency") == 0) {
			if (consistency_parse(value, &db->write_fallback_consistency) < 0)
				i_fatal("cassandra: Unknown write_fallback_consistency: %s", value);
			write_fallback_set = TRUE;
		} else if (strcmp(key, "delete_consistency") == 0) {
			if (consistency_parse(value, &db->delete_consistency) < 0)
				i_fatal("cassandra: Unknown delete_consistency: %s", value);
		} else if (strcmp(key, "delete_fallback_consistency") == 0) {
			if (consistency_parse(value, &db->delete_fallback_consistency) < 0)
				i_fatal("cassandra: Unknown delete_fallback_consistency: %s", value);
			delete_fallback_set = TRUE;
		} else if (strcmp(key, "log_level") == 0) {
			if (log_level_parse(value, &db->log_level) < 0)
				i_fatal("cassandra: Unknown log_level: %s", value);
		} else if (strcmp(key, "version") == 0) {
			if (str_to_uint(value, &db->protocol_version) < 0)
				i_fatal("cassandra: Invalid version: %s", value);
		} else if (strcmp(key, "num_threads") == 0) {
			if (str_to_uint(value, &db->num_threads) < 0)
				i_fatal("cassandra: Invalid num_threads: %s", value);
		} else if (strcmp(key, "connect_timeout") == 0) {
			if (settings_get_time(value, &db->connect_timeout_secs, &error) < 0)
				i_fatal("cassandra: Invalid connect_timeout '%s': %s", value, error);
		} else if (strcmp(key, "request_timeout") == 0) {
			if (settings_get_time(value, &db->request_timeout_secs, &error) < 0)
				i_fatal("cassandra: Invalid request_timeout '%s': %s", value, error);
		} else if (strcmp(key, "metrics") == 0) {
			i_free(db->metrics_path);
			db->metrics_path = i_strdup(value);
		} else {
			i_fatal("cassandra: Unknown connect string: %s", key);
		}
	}

	if (!read_fallback_set)
		db->read_fallback_consistency = db->read_consistency;
	if (!write_fallback_set)
		db->write_fallback_consistency = db->write_consistency;
	if (!delete_fallback_set)
		db->delete_fallback_consistency = db->delete_consistency;

	if (str_len(hosts) == 0)
		i_fatal("cassandra: No hosts given in connect string");
	if (db->keyspace == NULL)
		i_fatal("cassandra: No dbname given in connect string");
	db->hosts = i_strdup(str_c(hosts));
}

static void
driver_cassandra_get_metrics_json(struct cassandra_db *db, string_t *dest)
{
#define ADD_UINT64(_struct, _field) \
	str_printfa(dest, "\""#_field"\": %llu,", (unsigned long long)metrics._struct._field);
#define ADD_DOUBLE(_struct, _field) \
	str_printfa(dest, "\""#_field"\": %02lf,", metrics._struct._field);
	CassMetrics metrics;

	cass_session_get_metrics(db->session, &metrics);
	str_append(dest, "{ \"requests\": {");
	ADD_UINT64(requests, min);
	ADD_UINT64(requests, max);
	ADD_UINT64(requests, mean);
	ADD_UINT64(requests, stddev);
	ADD_UINT64(requests, median);
	ADD_UINT64(requests, percentile_75th);
	ADD_UINT64(requests, percentile_95th);
	ADD_UINT64(requests, percentile_98th);
	ADD_UINT64(requests, percentile_99th);
	ADD_UINT64(requests, percentile_999th);
	ADD_DOUBLE(requests, mean_rate);
	ADD_DOUBLE(requests, one_minute_rate);
	ADD_DOUBLE(requests, five_minute_rate);
	ADD_DOUBLE(requests, fifteen_minute_rate);
	str_truncate(dest, str_len(dest)-1);
	str_append(dest, "}, \"stats\": {");
	ADD_UINT64(stats, total_connections);
	ADD_UINT64(stats, available_connections);
	ADD_UINT64(stats, exceeded_pending_requests_water_mark);
	ADD_UINT64(stats, exceeded_write_bytes_water_mark);
	str_truncate(dest, str_len(dest)-1);
	str_append(dest, "}, \"errors\": {");
	ADD_UINT64(errors, connection_timeouts);
	ADD_UINT64(errors, pending_request_timeouts);
	ADD_UINT64(errors, request_timeouts);
	str_truncate(dest, str_len(dest)-1);
	str_append(dest, "}}");
}

static void driver_cassandra_metrics_write(struct cassandra_db *db)
{
	struct var_expand_table tab[] = {
		{ '\0', NULL, NULL }
	};
	string_t *path = t_str_new(64);
	string_t *data;
	int fd;

	var_expand(path, db->metrics_path, tab);

	fd = open(str_c(path), O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, 0600);
	if (fd == -1) {
		i_error("creat(%s) failed: %m", str_c(path));
		return;
	}
	data = t_str_new(1024);
	driver_cassandra_get_metrics_json(db, data);
	if (write_full(fd, str_data(data), str_len(data)) < 0)
		i_error("write(%s) failed: %m", str_c(path));
	i_close_fd(&fd);
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
	cass_log_set_level(db->log_level);

	db->timestamp_gen = cass_timestamp_gen_monotonic_new();
	db->cluster = cass_cluster_new();
	cass_cluster_set_timestamp_gen(db->cluster, db->timestamp_gen);
	cass_cluster_set_connect_timeout(db->cluster, db->connect_timeout_secs * 1000);
	cass_cluster_set_request_timeout(db->cluster, db->request_timeout_secs * 1000);
	cass_cluster_set_contact_points(db->cluster, db->hosts);
	if (db->user != NULL && db->password != NULL)
		cass_cluster_set_credentials(db->cluster, db->user, db->password);
	if (db->port != 0)
		cass_cluster_set_port(db->cluster, db->port);
	if (db->protocol_version != 0)
		cass_cluster_set_protocol_version(db->cluster, db->protocol_version);
	if (db->num_threads != 0)
		cass_cluster_set_num_threads_io(db->cluster, db->num_threads);
	db->session = cass_session_new();
	if (db->metrics_path != NULL)
		db->to_metrics = timeout_add(1000, driver_cassandra_metrics_write, db);
	i_array_init(&db->results, 16);
	i_array_init(&db->callbacks, 16);
	return &db->api;
}

static void driver_cassandra_deinit_v(struct sql_db *_db)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;

        driver_cassandra_close(db, "Deinitialized");

	i_assert(array_count(&db->callbacks) == 0);
	array_free(&db->callbacks);
	i_assert(array_count(&db->results) == 0);
	array_free(&db->results);

	cass_session_free(db->session);
	cass_cluster_free(db->cluster);
	cass_timestamp_gen_free(db->timestamp_gen);
	if (db->to_metrics != NULL)
		timeout_remove(&db->to_metrics);
	i_free(db->metrics_path);
	i_free(db->hosts);
	i_free(db->error);
	i_free(db->keyspace);
	i_free(db->user);
	i_free(db->password);
	array_free(&_db->module_contexts);
	i_free(db);
}

static void driver_cassandra_result_unlink(struct cassandra_db *db,
					   struct cassandra_result *result)
{
	struct cassandra_result *const *results;
	unsigned int i, count;

	results = array_get(&db->results, &count);
	for (i = 0; i < count; i++) {
		if (results[i] == result) {
			array_delete(&db->results, i, 1);
			return;
		}
	}
	i_unreached();
}

static void driver_cassandra_result_free(struct sql_result *_result)
{
	struct cassandra_db *db = (struct cassandra_db *)_result->db;
        struct cassandra_result *result = (struct cassandra_result *)_result;
	struct timeval now;

	i_assert(!result->api.callback);
	i_assert(result->callback == NULL);

	if (_result == db->sync_result)
		db->sync_result = NULL;

	if (db->log_level >= CASS_LOG_DEBUG) {
		if (gettimeofday(&now, NULL) < 0)
			i_fatal("gettimeofday() failed: %m");
		i_debug("cassandra: Finished query '%s' (%u rows, %lld+%lld us): %s", result->query,
			result->row_count,
			timeval_diff_usecs(&result->finish_time, &result->start_time),
			timeval_diff_usecs(&now, &result->finish_time),
			result->error != NULL ? result->error : "success");
	}

	if (result->result != NULL)
		cass_result_free(result->result);
	if (result->iterator != NULL)
		cass_iterator_free(result->iterator);
	if (result->statement != NULL)
		cass_statement_free(result->statement);
	if (result->row_pool != NULL)
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
	result->finish_time = ioloop_timeval;
	driver_cassandra_result_unlink(db, result);

	i_assert((result->error != NULL) == (result->iterator == NULL));

	result->api.callback = TRUE;
	T_BEGIN {
		result->callback(&result->api, result->context);
	} T_END;
	result->api.callback = FALSE;

	free_result = db->sync_result != &result->api;
	if (db->ioloop != NULL)
		io_loop_stop(db->ioloop);

	i_assert(!free_result || result->api.refcount > 0);
	result->callback = NULL;
	if (free_result)
		sql_result_unref(&result->api);
}

static void query_resend_with_fallback(struct cassandra_result *result)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	time_t last_warning =
		ioloop_time - db->last_fallback_warning[result->query_type];

	if (last_warning >= CASSANDRA_FALLBACK_WARN_INTERVAL_SECS) {
		i_warning("%s - retrying future %s queries with consistency %s (instead of %s)",
			  result->error, cassandra_query_type_names[result->query_type],
			  cass_consistency_string(result->fallback_consistency),
			  cass_consistency_string(result->consistency));
		db->last_fallback_warning[result->query_type] = ioloop_time;
	}
	i_free_and_null(result->error);
	if (db->fallback_failures[result->query_type]++ == 0)
		db->first_fallback_sent[result->query_type] = ioloop_timeval;

	result->consistency = result->fallback_consistency;
	driver_cassandra_result_send_query(result);
}

static void query_callback(CassFuture *future, void *context)
{
	struct cassandra_result *result = context;
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	CassError error = cass_future_error_code(future);

	if (error != CASS_OK) {
		const char *errmsg;
		size_t errsize;

		cass_future_error_message(future, &errmsg, &errsize);
		i_free(result->error);
		result->error = i_strdup_printf("Query '%s' failed: %.*s",
						result->query,
						(int)errsize, errmsg);
		/* unavailable = cassandra server knows that there aren't
		   enough nodes available.

		   write timeout = cassandra server couldn't reach all the
		   needed nodes. this may be because it hasn't yet detected
		   that the servers are down, or because the servers are just
		   too busy. we'll try the fallback consistency to avoid
		   unnecessary temporary errors. */
		if ((error == CASS_ERROR_SERVER_UNAVAILABLE ||
		     error == CASS_ERROR_SERVER_WRITE_TIMEOUT) &&
		    result->fallback_consistency != result->consistency) {
			/* retry with fallback consistency */
			query_resend_with_fallback(result);
			return;
		}
		result_finish(result);
		return;
	}

	if (result->fallback_consistency != result->consistency) {
		/* non-fallback query finished successfully. if there had been
		   any fallbacks, reset them. */
		db->fallback_failures[result->query_type] = 0;
	}

	result->result = cass_future_get_result(future);
	result->iterator = cass_iterator_from_result(result->result);
	result_finish(result);
}

static void driver_cassandra_result_send_query(struct cassandra_result *result)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	CassFuture *future;

	result->statement = cass_statement_new(result->query, 0);
	cass_statement_set_consistency(result->statement, result->consistency);

	future = cass_session_execute(db->session, result->statement);
	driver_cassandra_set_callback(future, db, query_callback, result);
}

static bool
driver_cassandra_want_fallback_query(struct cassandra_result *result)
{
        struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	unsigned int failure_count = db->fallback_failures[result->query_type];
	unsigned int i, msecs = CASSANDRA_FALLBACK_FIRST_RETRY_MSECS;
	struct timeval tv;

	if (failure_count == 0)
		return FALSE;
	tv = db->first_fallback_sent[result->query_type];
	for (i = 1; i < failure_count; i++) {
		msecs *= 2;
		if (msecs >= CASSANDRA_FALLBACK_MAX_RETRY_MSECS) {
			msecs = CASSANDRA_FALLBACK_FIRST_RETRY_MSECS;
			break;
		}
	}
	timeval_add_msecs(&tv, msecs);
	return timeval_cmp(&ioloop_timeval, &tv) < 0;
}

static int driver_cassandra_send_query(struct cassandra_result *result)
{
        struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	int ret;

	if (!SQL_DB_IS_READY(&db->api)) {
		if ((ret = sql_connect(&db->api)) <= 0) {
			if (ret < 0)
				driver_cassandra_close(db, "Couldn't connect to Cassandra");
			return ret;
		}
	}

	result->start_time = ioloop_timeval;
	result->row_pool = pool_alloconly_create("cassandra result", 512);
	switch (result->query_type) {
	case CASSANDRA_QUERY_TYPE_READ:
		result->consistency = db->read_consistency;
		result->fallback_consistency = db->read_fallback_consistency;
		break;
	case CASSANDRA_QUERY_TYPE_WRITE:
		result->consistency = db->write_consistency;
		result->fallback_consistency = db->write_fallback_consistency;
		break;
	case CASSANDRA_QUERY_TYPE_DELETE:
		result->consistency = db->delete_consistency;
		result->fallback_consistency = db->delete_fallback_consistency;
		break;
	}

	if (driver_cassandra_want_fallback_query(result))
		result->consistency = result->fallback_consistency;

	driver_cassandra_result_send_query(result);
	result->query_sent = TRUE;
	return 1;
}

static void driver_cassandra_send_queries(struct cassandra_db *db)
{
	struct cassandra_result *const *results;
	unsigned int i, count;

	results = array_get(&db->results, &count);
	for (i = 0; i < count; i++) {
		if (!results[i]->query_sent) {
			if (driver_cassandra_send_query(results[i]) <= 0)
				break;
		}
	}
}

static void exec_callback(struct sql_result *_result ATTR_UNUSED,
			  void *context ATTR_UNUSED)
{
}

static void
driver_cassandra_query_full(struct sql_db *_db, const char *query,
			    enum cassandra_query_type query_type,
			    sql_query_callback_t *callback, void *context)
{
        struct cassandra_db *db = (struct cassandra_db *)_db;
	struct cassandra_result *result;

	result = i_new(struct cassandra_result, 1);
	result->api = driver_cassandra_result;
	result->api.db = _db;
	result->api.refcount = 1;
	result->callback = callback;
	result->context = context;
	result->query_type = query_type;
	result->query = i_strdup(query);
	array_append(&db->results, &result, 1);

	(void)driver_cassandra_send_query(result);
}

static void driver_cassandra_exec(struct sql_db *db, const char *query)
{
	driver_cassandra_query_full(db, query, CASSANDRA_QUERY_TYPE_WRITE, exec_callback, NULL);
}

static void driver_cassandra_query(struct sql_db *db, const char *query,
				   sql_query_callback_t *callback, void *context)
{
	driver_cassandra_query_full(db, query, CASSANDRA_QUERY_TYPE_READ, callback, context);
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
			   const CassValue *value, const char **str_r,
			   size_t *len_r)
{
	const unsigned char *output;
	void *output_dup;
	size_t output_size;
	CassError rc;
	const char *type;

	if (cass_value_is_null(value)) {
		*str_r = NULL;
		return 0;
	}

	switch (cass_data_type_type(cass_value_data_type(value))) {
	case CASS_VALUE_TYPE_INT: {
		cass_int32_t num;

		rc = cass_value_get_int32(value, &num);
		if (rc == CASS_OK) {
			const char *str = t_strdup_printf("%d", num);
			output_size = strlen(str);
			output = (const void *)str;
		}
		type = "int32";
		break;
	}
	default:
		rc = cass_value_get_bytes(value, &output, &output_size);
		type = "bytes";
		break;
	}
	if (rc != CASS_OK) {
		i_free(result->error);
		result->error = i_strdup_printf("Couldn't get value as %s: %s",
						type, cass_error_desc(rc));
		return -1;
	}
	output_dup = p_malloc(result->row_pool, output_size + 1);
	memcpy(output_dup, output, output_size);
	*str_r = output_dup;
	*len_r = output_size;
	return 0;
}

static int driver_cassandra_result_next_row(struct sql_result *_result)
{
	struct cassandra_result *result = (struct cassandra_result *)_result;
	const CassRow *row;
	const CassValue *value;
	const char *str;
	size_t size;
	unsigned int i;
	int ret = 1;

	if (result->iterator == NULL)
		return -1;

	if (!cass_iterator_next(result->iterator))
		return 0;
	result->row_count++;

	p_clear(result->row_pool);
	p_array_init(&result->fields, result->row_pool, 8);
	p_array_init(&result->field_sizes, result->row_pool, 8);

	row = cass_iterator_get_row(result->iterator);
	for (i = 0; (value = cass_row_get_column(row, i)) != NULL; i++) {
		if (driver_cassandra_get_value(result, value, &str, &size) < 0) {
			ret = -1;
			break;
		}
		array_append(&result->fields, &str, 1);
		array_append(&result->field_sizes, &size, 1);
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
	struct cassandra_result *result = (struct cassandra_result *)_result;
	const char *const *strp;
	const size_t *sizep;

	strp = array_idx(&result->fields, idx);
	sizep = array_idx(&result->field_sizes, idx);
	*size_r = *sizep;
	return (const void *)*strp;
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
driver_cassandra_transaction_unref(struct cassandra_transaction_context **_ctx)
{
	struct cassandra_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;

	pool_unref(&ctx->query_pool);
	i_free(ctx->error);
	i_free(ctx);
}

static void
transaction_set_failed(struct cassandra_transaction_context *ctx,
		       const char *error)
{
	if (ctx->failed) {
		i_assert(ctx->error != NULL);
	} else {
		i_assert(ctx->error == NULL);
		ctx->failed = TRUE;
		ctx->error = i_strdup(error);
	}
}

static void
transaction_commit_callback(struct sql_result *result, void *context)
{
	struct cassandra_transaction_context *ctx = context;

	if (sql_result_next_row(result) < 0)
		ctx->callback(sql_result_get_error(result), ctx->context);
	else
		ctx->callback(NULL, ctx->context);
	driver_cassandra_transaction_unref(&ctx);
}

static void
driver_cassandra_transaction_commit(struct sql_transaction_context *_ctx,
				    sql_commit_callback_t *callback, void *context)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;
	enum cassandra_query_type query_type;

	ctx->callback = callback;
	ctx->context = context;

	if (ctx->failed || _ctx->head == NULL) {
		callback(ctx->failed ? ctx->error : NULL, context);
		driver_cassandra_transaction_unref(&ctx);
	} else if (_ctx->head->next == NULL) {
		/* just a single query, send it */
		if (strncasecmp(_ctx->head->query, "DELETE ", 7) == 0)
			query_type = CASSANDRA_QUERY_TYPE_DELETE;
		else
			query_type = CASSANDRA_QUERY_TYPE_WRITE;
		driver_cassandra_query_full(_ctx->db, _ctx->head->query, query_type,
			  transaction_commit_callback, ctx);
	} else {
		/* multiple queries - we don't actually have a transaction though */
		callback("Multiple changes in transaction not supported", context);
	}
}

static void
commit_multi_fail(struct cassandra_transaction_context *ctx,
		  struct sql_result *result, const char *query)
{
	transaction_set_failed(ctx, t_strdup_printf(
		"%s (query: %s)", sql_result_get_error(result), query));
	sql_result_unref(result);
}

static int
driver_cassandra_transaction_commit_multi(struct cassandra_transaction_context *ctx,
					  struct sql_result **result_r)
{
	struct cassandra_db *db = (struct cassandra_db *)ctx->ctx.db;
	struct sql_result *result;
	struct sql_transaction_query *query;
	int ret = 0;

	result = driver_cassandra_sync_query(db, "BEGIN");
	if (sql_result_next_row(result) < 0) {
		commit_multi_fail(ctx, result, "BEGIN");
		return -1;
	}
	sql_result_unref(result);

	/* send queries */
	for (query = ctx->ctx.head; query != NULL; query = query->next) {
		result = driver_cassandra_sync_query(db, query->query);
		if (sql_result_next_row(result) < 0) {
			commit_multi_fail(ctx, result, query->query);
			ret = -1;
			break;
		}
		sql_result_unref(result);
	}

	*result_r = driver_cassandra_sync_query(db, ctx->failed ?
						"ROLLBACK" : "COMMIT");
	return ret;
}

static void
driver_cassandra_try_commit_s(struct cassandra_transaction_context *ctx)
{
	struct sql_transaction_context *_ctx = &ctx->ctx;
	struct cassandra_db *db = (struct cassandra_db *)_ctx->db;
	struct sql_transaction_query *single_query = NULL;
	struct sql_result *result = NULL;
	int ret = 0;

	if (_ctx->head->next == NULL) {
		/* just a single query, send it */
		single_query = _ctx->head;
		result = sql_query_s(_ctx->db, single_query->query);
	} else {
		/* multiple queries, use a transaction */
		driver_cassandra_sync_init(db);
		ret = driver_cassandra_transaction_commit_multi(ctx, &result);
		i_assert(ret == 0 || ctx->failed);
		driver_cassandra_sync_deinit(db);
	}

	if (!ctx->failed) {
		if (sql_result_next_row(result) < 0)
			transaction_set_failed(ctx, sql_result_get_error(result));
	}
	if (result != NULL)
		sql_result_unref(result);
}

static int
driver_cassandra_transaction_commit_s(struct sql_transaction_context *_ctx,
				      const char **error_r)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	if (_ctx->head != NULL)
		driver_cassandra_try_commit_s(ctx);
	*error_r = t_strdup(ctx->error);

	i_assert(ctx->refcount == 1);
	i_assert((*error_r != NULL) == ctx->failed);
	driver_cassandra_transaction_unref(&ctx);
	return *error_r == NULL ? 0 : -1;
}

static void
driver_cassandra_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	i_assert(ctx->refcount == 1);
	driver_cassandra_transaction_unref(&ctx);
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

static const char *
driver_cassandra_escape_blob(struct sql_db *_db ATTR_UNUSED,
			     const unsigned char *data, size_t size)
{
	string_t *str = t_str_new(128);

	str_append(str, "0x");
	binary_to_hex_append(str, data, size);
	return str_c(str);
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

		driver_cassandra_update,

		driver_cassandra_escape_blob
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
