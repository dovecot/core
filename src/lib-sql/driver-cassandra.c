/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
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
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassandra.h>

#define IS_CONNECTED(db) \
	((db)->api.state != SQL_DB_STATE_DISCONNECTED && \
	 (db)->api.state != SQL_DB_STATE_CONNECTING)

#define CASSANDRA_FALLBACK_WARN_INTERVAL_SECS 60
#define CASSANDRA_FALLBACK_FIRST_RETRY_MSECS 50
#define CASSANDRA_FALLBACK_MAX_RETRY_MSECS (1000*60)

#define CASS_QUERY_DEFAULT_WARN_TIMEOUT_MSECS (5*1000)

typedef void driver_cassandra_callback_t(CassFuture *future, void *context);

enum cassandra_counter_type {
	CASSANDRA_COUNTER_TYPE_QUERY_SENT,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_OK,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_NO_HOSTS,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_QUEUE_FULL,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_CLIENT_TIMEOUT,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_SERVER_TIMEOUT,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_SERVER_UNAVAILABLE,
	CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_OTHER,
	CASSANDRA_COUNTER_TYPE_QUERY_SLOW,

	CASSANDRA_COUNTER_COUNT
};
static const char *counter_names[CASSANDRA_COUNTER_COUNT] = {
	"sent",
	"recv_ok",
	"recv_err_no_hosts",
	"recv_err_queue_full",
	"recv_err_client_timeout",
	"recv_err_server_timeout",
	"recv_err_server_unavailable",
	"recv_err_other",
	"slow",
};

enum cassandra_query_type {
	CASSANDRA_QUERY_TYPE_READ,
	CASSANDRA_QUERY_TYPE_READ_MORE,
	CASSANDRA_QUERY_TYPE_WRITE,
	CASSANDRA_QUERY_TYPE_DELETE,

	CASSANDRA_QUERY_TYPE_COUNT
};

static const char *cassandra_query_type_names[CASSANDRA_QUERY_TYPE_COUNT] = {
	"read", "read-more", "write", "delete"
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
	bool debug_queries;
	bool latency_aware_routing;
	unsigned int protocol_version;
	unsigned int num_threads;
	unsigned int connect_timeout_msecs, request_timeout_msecs;
	unsigned int warn_timeout_msecs;
	unsigned int heartbeat_interval_secs, idle_timeout_secs;
	unsigned int execution_retry_interval_msecs, execution_retry_times;
	unsigned int page_size;
	in_port_t port;

	CassCluster *cluster;
	CassSession *session;
	CassTimestampGen *timestamp_gen;

	int fd_pipe[2];
	struct io *io_pipe;
	ARRAY(struct cassandra_sql_prepared_statement *) pending_prepares;
	ARRAY(struct cassandra_callback *) callbacks;
	ARRAY(struct cassandra_result *) results;
	unsigned int callback_ids;

	char *metrics_path;
	struct timeout *to_metrics;
	uint64_t counters[CASSANDRA_COUNTER_COUNT];

	struct timeval primary_query_last_sent[CASSANDRA_QUERY_TYPE_COUNT];
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
	struct timeval page0_start_time, start_time, finish_time;
	unsigned int row_count, total_row_count, page_num;
	cass_int64_t timestamp;

	pool_t row_pool;
	ARRAY_TYPE(const_string) fields;
	ARRAY(size_t) field_sizes;

	sql_query_callback_t *callback;
	void *context;

	bool is_prepared:1;
	bool query_sent:1;
	bool finished:1;
	bool paging_continues:1;
};

struct cassandra_transaction_context {
	struct sql_transaction_context ctx;
	int refcount;

	sql_commit_callback_t *callback;
	void *context;

	struct cassandra_sql_statement *stmt;
	char *query;
	cass_int64_t query_timestamp;
	char *error;

	bool begin_succeeded:1;
	bool begin_failed:1;
	bool failed:1;
};

struct cassandra_sql_arg {
	unsigned int column_idx;

	char *value_str;
	const unsigned char *value_binary;
	size_t value_binary_size;
	int64_t value_int64;
};

struct cassandra_sql_statement {
	struct sql_statement stmt;

	struct cassandra_sql_prepared_statement *prep;
	CassStatement *cass_stmt;

	ARRAY(struct cassandra_sql_arg) pending_args;
	cass_int64_t timestamp;

	struct cassandra_result *result;
};

struct cassandra_sql_prepared_statement {
	struct sql_prepared_statement prep_stmt;
	char *query_template;

	/* NULL, until the prepare is asynchronously finished */
	const CassPrepared *prepared;
	/* statements waiting for prepare to finish */
	ARRAY(struct cassandra_sql_statement *) pending_statements;
	/* an error here will cause the prepare to be retried on the next
	   execution attempt. */
	char *error;

	bool pending;
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
	{ CASS_CONSISTENCY_QUORUM, "quorum" },
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

static struct event_category event_category_cassandra = {
	.parent = &event_category_sql,
	.name = "cassandra"
};

static void driver_cassandra_prepare_pending(struct cassandra_db *db);
static void
prepare_finish_pending_statements(struct cassandra_sql_prepared_statement *prep_stmt);
static void driver_cassandra_result_send_query(struct cassandra_result *result);
static void driver_cassandra_send_queries(struct cassandra_db *db);
static void result_finish(struct cassandra_result *result);

static void
driver_cassandra_log_handler(const CassLogMessage* message,
			     void *data ATTR_UNUSED)
{
	enum log_type log_type = LOG_TYPE_ERROR;
	const char *log_level_str = "";

	switch (message->severity) {
	case CASS_LOG_DISABLED:
	case CASS_LOG_LAST_ENTRY:
		i_unreached();
	case CASS_LOG_CRITICAL:
		log_type = LOG_TYPE_PANIC;
		break;
	case CASS_LOG_ERROR:
		log_type = LOG_TYPE_ERROR;
		break;
	case CASS_LOG_WARN:
		log_type = LOG_TYPE_WARNING;
		break;
	case CASS_LOG_INFO:
		log_type = LOG_TYPE_INFO;
		break;
	case CASS_LOG_TRACE:
		log_level_str = "[TRACE] ";
		/* fall through */
	case CASS_LOG_DEBUG:
		log_type = LOG_TYPE_DEBUG;
		break;
	}

	/* NOTE: We may not be in the main thread. We can't use the
	   standard Dovecot functions that may use data stack. That's why
	   we can't use i_log_type() in here, but have to re-implement the
	   internal logging protocol. Otherwise preserve Cassandra's own
	   logging format. */
	fprintf(stderr, "\001%c%s %u.%03u %s(%s:%d:%s): %s\n",
		log_type+1, my_pid,
		(unsigned int)(message->time_ms / 1000),
		(unsigned int)(message->time_ms % 1000),
		log_level_str,
		message->file, message->line, message->function,
		message->message);
}

static void driver_cassandra_init_log(void)
{
	failure_callback_t *fatal_callback, *error_callback;
	failure_callback_t *info_callback, *debug_callback;

	i_get_failure_handlers(&fatal_callback, &error_callback,
			       &info_callback, &debug_callback);
	if (i_failure_handler_is_internal(debug_callback)) {
		/* Using internal logging protocol. Use it ourself to set log
		   levels correctly. */
		cass_log_set_callback(driver_cassandra_log_handler, NULL);
	}
}

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
	struct cassandra_sql_prepared_statement *const *prep_stmtp;
	struct cassandra_result *const *resultp;

	io_remove(&db->io_pipe);
	if (db->fd_pipe[0] != -1) {
		i_close_fd(&db->fd_pipe[0]);
		i_close_fd(&db->fd_pipe[1]);
	}
	driver_cassandra_set_state(db, SQL_DB_STATE_DISCONNECTED);

	array_foreach(&db->pending_prepares, prep_stmtp) {
		(*prep_stmtp)->pending = FALSE;
		(*prep_stmtp)->error = i_strdup(error);
		prepare_finish_pending_statements(*prep_stmtp);
	}
	array_clear(&db->pending_prepares);

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

static void driver_cassandra_log_error(struct cassandra_db *db,
				       CassFuture *future, const char *str)
{
	const char *message;
	size_t size;

	cass_future_error_message(future, &message, &size);
	e_error(db->api.event, "%s: %.*s", str, (int)size, message);
}

static void driver_cassandra_future_callback(CassFuture *future ATTR_UNUSED,
					     void *context)
{
	struct cassandra_callback *cb = context;

	/* this isn't the main thread - communicate with main thread by
	   writing the callback id to the pipe. note that we must not use
	   almost any dovecot functions here because most of them are using
	   data-stack, which isn't thread-safe. especially don't use
	   i_error() here. */
	if (write_full(cb->db->fd_pipe[1], &cb->id, sizeof(cb->id)) < 0) {
		const char *str = t_strdup_printf(
			"cassandra: write(pipe) failed: %s\n",
			strerror(errno));
		(void)write_full(STDERR_FILENO, str, strlen(str));
	}
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
		e_error(db->api.event, "read(pipe) failed: %m");
	else if (ret == 0)
		e_error(db->api.event, "read(pipe) failed: EOF");
	else if (ret % sizeof(ids[0]) != 0)
		e_error(db->api.event, "read(pipe) returned wrong amount of data");
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
		driver_cassandra_log_error(db, future,
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
	driver_cassandra_prepare_pending(db);
	driver_cassandra_send_queries(db);
}

static int driver_cassandra_connect(struct sql_db *_db)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;
	CassFuture *future;

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	if (pipe(db->fd_pipe) < 0) {
		e_error(_db->event, "pipe() failed: %m");
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

static int driver_cassandra_parse_connect_string(struct cassandra_db *db,
						 const char *connect_string,
						 const char **error_r)
{
	const char *const *args, *key, *value, *error;
	string_t *hosts = t_str_new(64);
	bool read_fallback_set = FALSE, write_fallback_set = FALSE, delete_fallback_set = FALSE;

	db->log_level = CASS_LOG_WARN;
	db->read_consistency = CASS_CONSISTENCY_LOCAL_QUORUM;
	db->write_consistency = CASS_CONSISTENCY_LOCAL_QUORUM;
	db->delete_consistency = CASS_CONSISTENCY_LOCAL_QUORUM;
	db->connect_timeout_msecs = SQL_CONNECT_TIMEOUT_SECS*1000;
	db->request_timeout_msecs = SQL_QUERY_TIMEOUT_SECS*1000;
	db->warn_timeout_msecs = CASS_QUERY_DEFAULT_WARN_TIMEOUT_MSECS;

	args = t_strsplit_spaces(connect_string, " ");
	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL) {
			*error_r = t_strdup_printf("Missing value in connect string: %s",
						   *args);
			return -1;
		}
		key = t_strdup_until(*args, value++);

		if (strcmp(key, "host") == 0) {
			if (str_len(hosts) > 0)
				str_append_c(hosts, ',');
			str_append(hosts, value);
		} else if (strcmp(key, "port") == 0) {
			if (net_str2port(value, &db->port) < 0) {
				*error_r = t_strdup_printf("Invalid port: %s", value);
				return -1;
			}
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
			if (consistency_parse(value, &db->read_consistency) < 0) {
				*error_r = t_strdup_printf("Unknown read_consistency: %s", value);
				return -1;
			}
		} else if (strcmp(key, "read_fallback_consistency") == 0) {
			if (consistency_parse(value, &db->read_fallback_consistency) < 0) {
				*error_r = t_strdup_printf("Unknown read_fallback_consistency: %s", value);
				return -1;
			}
			read_fallback_set = TRUE;
		} else if (strcmp(key, "write_consistency") == 0) {
			if (consistency_parse(value, &db->write_consistency) < 0) {
				*error_r = t_strdup_printf("Unknown write_consistency: %s", value);
				return -1;
			}
		} else if (strcmp(key, "write_fallback_consistency") == 0) {
			if (consistency_parse(value, &db->write_fallback_consistency) < 0) {
				*error_r = t_strdup_printf("Unknown write_fallback_consistency: %s", value);
				return -1;
			}
			write_fallback_set = TRUE;
		} else if (strcmp(key, "delete_consistency") == 0) {
			if (consistency_parse(value, &db->delete_consistency) < 0) {
				*error_r = t_strdup_printf("Unknown delete_consistency: %s", value);
				return -1;
			}
		} else if (strcmp(key, "delete_fallback_consistency") == 0) {
			if (consistency_parse(value, &db->delete_fallback_consistency) < 0) {
				*error_r = t_strdup_printf("Unknown delete_fallback_consistency: %s", value);
				return -1;
			}
			delete_fallback_set = TRUE;
		} else if (strcmp(key, "log_level") == 0) {
			if (log_level_parse(value, &db->log_level) < 0) {
				*error_r = t_strdup_printf("Unknown log_level: %s", value);
				return -1;
			}
		} else if (strcmp(key, "debug_queries") == 0) {
			db->debug_queries = TRUE;
		} else if (strcmp(key, "latency_aware_routing") == 0) {
			db->latency_aware_routing = TRUE;
		} else if (strcmp(key, "version") == 0) {
			if (str_to_uint(value, &db->protocol_version) < 0) {
				*error_r = t_strdup_printf("Invalid version: %s", value);
				return -1;
			}
		} else if (strcmp(key, "num_threads") == 0) {
			if (str_to_uint(value, &db->num_threads) < 0) {
				*error_r = t_strdup_printf("Invalid num_threads: %s", value);
				return -1;
			}
		} else if (strcmp(key, "heartbeat_interval") == 0) {
			if (settings_get_time(value, &db->heartbeat_interval_secs, &error) < 0) {
				*error_r = t_strdup_printf("Invalid heartbeat_interval '%s': %s", value, error);
				return -1;
			}
		} else if (strcmp(key, "idle_timeout") == 0) {
			if (settings_get_time(value, &db->idle_timeout_secs, &error) < 0) {
				*error_r = t_strdup_printf("Invalid idle_timeout '%s': %s", value, error);
				return -1;
			}
		} else if (strcmp(key, "connect_timeout") == 0) {
			if (settings_get_time_msecs(value, &db->connect_timeout_msecs, &error) < 0) {
				*error_r = t_strdup_printf("Invalid connect_timeout '%s': %s", value, error);
				return -1;
			}
		} else if (strcmp(key, "request_timeout") == 0) {
			if (settings_get_time_msecs(value, &db->request_timeout_msecs, &error) < 0) {
				*error_r = t_strdup_printf("Invalid request_timeout '%s': %s", value, error);
				return -1;
			}
		} else if (strcmp(key, "warn_timeout") == 0) {
			if (settings_get_time_msecs(value, &db->warn_timeout_msecs, &error) < 0) {
				*error_r = t_strdup_printf("Invalid warn_timeout '%s': %s", value, error);
				return -1;
			}
		} else if (strcmp(key, "metrics") == 0) {
			i_free(db->metrics_path);
			db->metrics_path = i_strdup(value);
		} else if (strcmp(key, "execution_retry_interval") == 0) {
			if (settings_get_time_msecs(value, &db->execution_retry_interval_msecs, &error) < 0) {
				*error_r = t_strdup_printf("Invalid execution_retry_interval '%s': %s", value, error);
				return -1;
			}
#ifndef HAVE_CASSANDRA_SPECULATIVE_POLICY
			*error_r = t_strdup_printf("This cassandra version does not support execution_retry_interval");
			return -1;
#endif
		} else if (strcmp(key, "execution_retry_times") == 0) {
			if (str_to_uint(value, &db->execution_retry_times) < 0) {
				*error_r = t_strdup_printf("Invalid execution_retry_times %s", value);
				return -1;
			}
#ifndef HAVE_CASSANDRA_SPECULATIVE_POLICY
			*error_r = t_strdup_printf("This cassandra version does not support execution_retry_times");
			return -1;
#endif
		} else if (strcmp(key, "page_size") == 0) {
			if (str_to_uint(value, &db->page_size) < 0) {
				*error_r = t_strdup_printf("Invalid page_size: %s", value);
				return -1;
			}
		} else {
			*error_r = t_strdup_printf("Unknown connect string: %s", key);
			return -1;
		}
	}

	if (!read_fallback_set)
		db->read_fallback_consistency = db->read_consistency;
	if (!write_fallback_set)
		db->write_fallback_consistency = db->write_consistency;
	if (!delete_fallback_set)
		db->delete_fallback_consistency = db->delete_consistency;

	if (str_len(hosts) == 0) {
		*error_r = t_strdup_printf("No hosts given in connect string");
		return -1;
	}
	if (db->keyspace == NULL) {
		*error_r = t_strdup_printf("No dbname given in connect string");
		return -1;
	}
	db->hosts = i_strdup(str_c(hosts));
	return 0;
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

	str_append(dest, "}, \"queries\": {");
	for (unsigned int i = 0; i < CASSANDRA_COUNTER_COUNT; i++) {
		str_printfa(dest, "\"%s\": %"PRIu64",", counter_names[i],
			    db->counters[i]);
	}
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
	const char *error;
	int fd;

	if (var_expand(path, db->metrics_path, tab, &error) <= 0) {
		e_error(db->api.event, "Failed to expand metrics_path=%s: %s",
			db->metrics_path, error);
		return;
	}

	fd = open(str_c(path), O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, 0600);
	if (fd == -1) {
		e_error(db->api.event, "creat(%s) failed: %m", str_c(path));
		return;
	}
	data = t_str_new(1024);
	driver_cassandra_get_metrics_json(db, data);
	if (write_full(fd, str_data(data), str_len(data)) < 0)
		e_error(db->api.event, "write(%s) failed: %m", str_c(path));
	i_close_fd(&fd);
}

static void driver_cassandra_free(struct cassandra_db **_db)
{
	struct cassandra_db *db = *_db;
	*_db = NULL;

	event_unref(&db->api.event);
	i_free(db->metrics_path);
	i_free(db->hosts);
	i_free(db->error);
	i_free(db->keyspace);
	i_free(db->user);
	i_free(db->password);
	array_free(&db->api.module_contexts);
	i_free(db);
}

static int driver_cassandra_init_full_v(const struct sql_settings *set,
					struct sql_db **db_r, const char **error_r)
{
	struct cassandra_db *db;
	char *error = NULL;
	int ret;

	db = i_new(struct cassandra_db, 1);
	db->api = driver_cassandra_db;
	db->fd_pipe[0] = db->fd_pipe[1] = -1;
	db->api.event = event_create(set->event_parent);
	event_add_category(db->api.event, &event_category_cassandra);
	event_set_append_log_prefix(db->api.event, "cassandra: ");

	T_BEGIN {
		const char *tmp;
		if ((ret = driver_cassandra_parse_connect_string(db, set->connect_string,
								 &tmp)) < 0) {
			error = i_strdup(tmp);
		}
	} T_END;

	if (ret < 0) {
		*error_r = t_strdup(error);
		i_free(error);
		driver_cassandra_free(&db);
		return -1;
	}

	driver_cassandra_init_log();
	cass_log_set_level(db->log_level);
	if (db->log_level >= CASS_LOG_DEBUG)
		event_set_forced_debug(db->api.event, TRUE);

	if (db->protocol_version > 0 && db->protocol_version < 4) {
		/* binding with column indexes requires v4 */
		db->api.v.prepared_statement_init = NULL;
		db->api.v.prepared_statement_deinit = NULL;
		db->api.v.statement_init_prepared = NULL;
	}

	db->timestamp_gen = cass_timestamp_gen_monotonic_new();
	db->cluster = cass_cluster_new();
	cass_cluster_set_timestamp_gen(db->cluster, db->timestamp_gen);
	cass_cluster_set_connect_timeout(db->cluster, db->connect_timeout_msecs);
	cass_cluster_set_request_timeout(db->cluster, db->request_timeout_msecs);
	cass_cluster_set_contact_points(db->cluster, db->hosts);
	if (db->user != NULL && db->password != NULL)
		cass_cluster_set_credentials(db->cluster, db->user, db->password);
	if (db->port != 0)
		cass_cluster_set_port(db->cluster, db->port);
	if (db->protocol_version != 0)
		cass_cluster_set_protocol_version(db->cluster, db->protocol_version);
	if (db->num_threads != 0)
		cass_cluster_set_num_threads_io(db->cluster, db->num_threads);
	if (db->latency_aware_routing)
		cass_cluster_set_latency_aware_routing(db->cluster, cass_true);
	if (db->heartbeat_interval_secs != 0)
		cass_cluster_set_connection_heartbeat_interval(db->cluster, db->heartbeat_interval_secs);
	if (db->idle_timeout_secs != 0)
		cass_cluster_set_connection_idle_timeout(db->cluster, db->idle_timeout_secs);
#ifdef HAVE_CASSANDRA_SPECULATIVE_POLICY
	if (db->execution_retry_times > 0 && db->execution_retry_interval_msecs > 0)
		cass_cluster_set_constant_speculative_execution_policy(db->cluster, db->execution_retry_interval_msecs, db->execution_retry_times);
#endif
	db->session = cass_session_new();
	if (db->metrics_path != NULL)
		db->to_metrics = timeout_add(1000, driver_cassandra_metrics_write, db);
	i_array_init(&db->results, 16);
	i_array_init(&db->callbacks, 16);
	i_array_init(&db->pending_prepares, 16);
	*db_r = &db->api;
	return 0;
}

static void driver_cassandra_deinit_v(struct sql_db *_db)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;

        driver_cassandra_close(db, "Deinitialized");

	i_assert(array_count(&db->callbacks) == 0);
	array_free(&db->callbacks);
	i_assert(array_count(&db->results) == 0);
	array_free(&db->results);
	i_assert(array_count(&db->pending_prepares) == 0);
	array_free(&db->pending_prepares);

	cass_session_free(db->session);
	cass_cluster_free(db->cluster);
	cass_timestamp_gen_free(db->timestamp_gen);
	timeout_remove(&db->to_metrics);
	sql_connection_log_finished(_db);
	driver_cassandra_free(&db);
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

static void driver_cassandra_log_result(struct cassandra_result *result,
					bool all_pages, long long reply_usecs)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	struct timeval now;
	unsigned int row_count;

	if (gettimeofday(&now, NULL) < 0)
		i_fatal("cassandra: gettimeofday() failed: %m");

	string_t *str = t_str_new(128);
	str_printfa(str, "Finished %squery '%s' (",
		    result->is_prepared ? "prepared " : "", result->query);
	if (result->timestamp != 0)
		str_printfa(str, "timestamp=%"PRId64", ", result->timestamp);
	if (all_pages) {
		str_printfa(str, "%u pages in total, ", result->page_num);
		row_count = result->total_row_count;
	} else {
		if (result->page_num > 0 || result->paging_continues)
			str_printfa(str, "page %u, ", result->page_num);
		row_count = result->row_count;
	}
	str_printfa(str, "%u rows, %lld+%lld us): %s", row_count, reply_usecs,
		    timeval_diff_usecs(&now, &result->finish_time),
		    result->error != NULL ? result->error : "success");

	struct event *event =
		sql_query_finished_event(&db->api, result->api.event,
					 result->query, FALSE, NULL)->event();
	if (db->debug_queries)
		event_set_forced_debug(event, TRUE);
	if (reply_usecs/1000 >= db->warn_timeout_msecs) {
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_SLOW]++;
		e_warning(event, "%s", str_c(str));
	} else {
		e_debug(event, "%s", str_c(str));
	}
}

static void driver_cassandra_result_free(struct sql_result *_result)
{
	struct cassandra_db *db = (struct cassandra_db *)_result->db;
        struct cassandra_result *result = (struct cassandra_result *)_result;
	long long reply_usecs;

	i_assert(!result->api.callback);
	i_assert(result->callback == NULL);

	if (_result == db->sync_result)
		db->sync_result = NULL;

	reply_usecs = timeval_diff_usecs(&result->finish_time, &result->start_time);
	driver_cassandra_log_result(result, FALSE, reply_usecs);

	if (result->page_num > 0 && !result->paging_continues) {
		/* Multi-page query finishes now. Log a debug/warning summary
		   message about it separate from the per-page messages. */
		reply_usecs = timeval_diff_usecs(&result->finish_time,
						 &result->page0_start_time);
		driver_cassandra_log_result(result, TRUE, reply_usecs);
	}

	if (result->result != NULL)
		cass_result_free(result->result);
	if (result->iterator != NULL)
		cass_iterator_free(result->iterator);
	if (result->statement != NULL)
		cass_statement_free(result->statement);
	pool_unref(&result->row_pool);
	event_unref(&result->api.event);
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
		e_warning(db->api.event, "%s - retrying future %s queries with consistency %s (instead of %s)",
			  result->error, cassandra_query_type_names[result->query_type],
			  cass_consistency_string(result->fallback_consistency),
			  cass_consistency_string(result->consistency));
		db->last_fallback_warning[result->query_type] = ioloop_time;
	}
	i_free_and_null(result->error);
	db->fallback_failures[result->query_type]++;

	result->consistency = result->fallback_consistency;
	driver_cassandra_result_send_query(result);
}

static void counters_inc_error(struct cassandra_db *db, CassError error)
{
	switch (error) {
	case CASS_ERROR_LIB_NO_HOSTS_AVAILABLE:
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_NO_HOSTS]++;
		break;
	case CASS_ERROR_LIB_REQUEST_QUEUE_FULL:
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_QUEUE_FULL]++;
		break;
	case CASS_ERROR_LIB_REQUEST_TIMED_OUT:
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_CLIENT_TIMEOUT]++;
		break;
	case CASS_ERROR_SERVER_WRITE_TIMEOUT:
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_SERVER_TIMEOUT]++;
		break;
	case CASS_ERROR_SERVER_UNAVAILABLE:
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_SERVER_UNAVAILABLE]++;
		break;
	default:
		db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_ERR_OTHER]++;
		break;
	}
}

static bool query_error_want_fallback(CassError error)
{
	switch (error) {
	case CASS_ERROR_LIB_WRITE_ERROR:
	case CASS_ERROR_LIB_REQUEST_TIMED_OUT:
		/* Communication problems on client side. Maybe it will work
		   with fallback consistency? */
		return TRUE;
	case CASS_ERROR_LIB_NO_HOSTS_AVAILABLE:
		/* The client library couldn't connect to enough Cassandra
		   nodes. The error message text is the same as for
		   CASS_ERROR_SERVER_UNAVAILABLE. */
		return TRUE;
	case CASS_ERROR_SERVER_SERVER_ERROR:
	case CASS_ERROR_SERVER_OVERLOADED:
	case CASS_ERROR_SERVER_IS_BOOTSTRAPPING:
	case CASS_ERROR_SERVER_READ_TIMEOUT:
	case CASS_ERROR_SERVER_READ_FAILURE:
	case CASS_ERROR_SERVER_WRITE_FAILURE:
		/* Servers are having trouble. Maybe with fallback consistency
		   we can reach non-troubled servers? */
		return TRUE;
	case CASS_ERROR_SERVER_UNAVAILABLE:
		/* Cassandra server knows that there aren't enough nodes
		   available. "All hosts in current policy attempted and were
		   either unavailable or failed". */
		return TRUE;
	case CASS_ERROR_SERVER_WRITE_TIMEOUT:
		/* Cassandra server couldn't reach all the needed nodes.
		   This may be because it hasn't yet detected that the servers
		   are down, or because the servers are just too busy. We'll
		   try the fallback consistency to avoid unnecessary temporary
		   errors. */
		return TRUE;
	default:
		return FALSE;
	}
}

static void query_callback(CassFuture *future, void *context)
{
	struct cassandra_result *result = context;
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	CassError error = cass_future_error_code(future);

	if (error != CASS_OK) {
		const char *errmsg;
		size_t errsize;
		int msecs;

		cass_future_error_message(future, &errmsg, &errsize);
		i_free(result->error);

		msecs = timeval_diff_msecs(&ioloop_timeval, &result->start_time);
		counters_inc_error(db, error);
		/* Timeouts bring uncertainty whether the query succeeded or
		   not. Also _SERVER_UNAVAILABLE could have actually written
		   enough copies of the data for the query to succeed. */
		result->api.error_type = error == CASS_ERROR_SERVER_WRITE_TIMEOUT ||
			error == CASS_ERROR_SERVER_UNAVAILABLE ||
			error == CASS_ERROR_LIB_REQUEST_TIMED_OUT ?
			SQL_RESULT_ERROR_TYPE_WRITE_UNCERTAIN :
			SQL_RESULT_ERROR_TYPE_UNKNOWN;
		result->error = i_strdup_printf("Query '%s' failed: %.*s (in %u.%03u secs%s)",
			result->query, (int)errsize, errmsg, msecs/1000, msecs%1000,
			result->page_num == 0 ? "" : t_strdup_printf(", page %u", result->page_num));

		if (query_error_want_fallback(error) &&
		    result->fallback_consistency != result->consistency) {
			/* retry with fallback consistency */
			query_resend_with_fallback(result);
			return;
		}
		result_finish(result);
		return;
	}
	db->counters[CASSANDRA_COUNTER_TYPE_QUERY_RECV_OK]++;

	if (result->fallback_consistency != result->consistency) {
		/* non-fallback query finished successfully. if there had been
		   any fallbacks, reset them. */
		db->fallback_failures[result->query_type] = 0;
	}

	result->result = cass_future_get_result(future);
	result->iterator = cass_iterator_from_result(result->result);
	result_finish(result);
}

static void driver_cassandra_init_statement(struct cassandra_result *result)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;

	cass_statement_set_consistency(result->statement, result->consistency);

#ifdef HAVE_CASSANDRA_SPECULATIVE_POLICY
	cass_statement_set_is_idempotent(result->statement, cass_true);
#endif
	if (db->page_size > 0)
		cass_statement_set_paging_size(result->statement, db->page_size);
}

static void driver_cassandra_result_send_query(struct cassandra_result *result)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;
	CassFuture *future;

	i_assert(result->statement != NULL);

	db->counters[CASSANDRA_COUNTER_TYPE_QUERY_SENT]++;
	if (result->query_type != CASSANDRA_QUERY_TYPE_READ_MORE)
		driver_cassandra_init_statement(result);

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
	/* double the retries every time. */
	for (i = 1; i < failure_count; i++) {
		msecs *= 2;
		if (msecs >= CASSANDRA_FALLBACK_MAX_RETRY_MSECS) {
			msecs = CASSANDRA_FALLBACK_MAX_RETRY_MSECS;
			break;
		}
	}
	/* If last primary query sent timestamp + msecs is older than current
	   time, we need to retry the primary query. Note that this practically
	   prevents multiple primary queries from being attempted
	   simultaneously, because the caller updates primary_query_last_sent
	   immediately when returning.

	   The only time when multiple primary queries can be running in
	   parallel is when the earlier query is being slow and hasn't finished
	   early enough. This could even be a wanted feature, since while the
	   first query might have to wait for a timeout, Cassandra could have
	   been fixed in the meantime and the second query finishes
	   successfully. */
	tv = db->primary_query_last_sent[result->query_type];
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

	if (result->page0_start_time.tv_sec == 0)
		result->page0_start_time = ioloop_timeval;
	result->start_time = ioloop_timeval;
	result->row_pool = pool_alloconly_create("cassandra result", 512);
	switch (result->query_type) {
	case CASSANDRA_QUERY_TYPE_READ:
		result->consistency = db->read_consistency;
		result->fallback_consistency = db->read_fallback_consistency;
		break;
	case CASSANDRA_QUERY_TYPE_READ_MORE:
		/* consistency is already set and we don't want to fallback
		   at this point anymore. */
		result->fallback_consistency = result->consistency;
		break;
	case CASSANDRA_QUERY_TYPE_WRITE:
		result->consistency = db->write_consistency;
		result->fallback_consistency = db->write_fallback_consistency;
		break;
	case CASSANDRA_QUERY_TYPE_DELETE:
		result->consistency = db->delete_consistency;
		result->fallback_consistency = db->delete_fallback_consistency;
		break;
	case CASSANDRA_QUERY_TYPE_COUNT:
		i_unreached();
	}

	if (driver_cassandra_want_fallback_query(result))
		result->consistency = result->fallback_consistency;
	else
		db->primary_query_last_sent[result->query_type] = ioloop_timeval;

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
		if (!results[i]->query_sent && results[i]->statement != NULL) {
			if (driver_cassandra_send_query(results[i]) <= 0)
				break;
		}
	}
}

static void exec_callback(struct sql_result *_result ATTR_UNUSED,
			  void *context ATTR_UNUSED)
{
}

static struct cassandra_result *
driver_cassandra_query_init(struct cassandra_db *db, const char *query,
			    enum cassandra_query_type query_type,
			    bool is_prepared,
			    sql_query_callback_t *callback, void *context)
{
	struct cassandra_result *result;

	result = i_new(struct cassandra_result, 1);
	result->api = driver_cassandra_result;
	result->api.db = &db->api;
	result->api.refcount = 1;
	result->callback = callback;
	result->context = context;
	result->query_type = query_type;
	result->query = i_strdup(query);
	result->is_prepared = is_prepared;
	result->api.event = event_create(db->api.event);
	array_append(&db->results, &result, 1);
	return result;
}

static void
driver_cassandra_query_full(struct sql_db *_db, const char *query,
			    enum cassandra_query_type query_type,
			    sql_query_callback_t *callback, void *context)
{
	struct cassandra_db *db = (struct cassandra_db *)_db;
	struct cassandra_result *result;

	result = driver_cassandra_query_init(db, query, query_type, FALSE,
					     callback, context);
	result->statement = cass_statement_new(query, 0);
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
driver_cassandra_sync_query(struct cassandra_db *db, const char *query,
			    enum cassandra_query_type query_type)
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

	driver_cassandra_query_full(&db->api, query, query_type,
				    cassandra_query_s_callback, db);
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
	result = driver_cassandra_sync_query(db, query,
					     CASSANDRA_QUERY_TYPE_READ);
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

	if (cass_value_is_null(value) != 0) {
		*str_r = NULL;
		*len_r = 0;
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
	case CASS_VALUE_TYPE_TIMESTAMP:
	case CASS_VALUE_TYPE_BIGINT: {
		cass_int64_t num;

		rc = cass_value_get_int64(value, &num);
		if (rc == CASS_OK) {
			const char *str = t_strdup_printf("%lld", (long long)num);
			output_size = strlen(str);
			output = (const void *)str;
		}
		type = "int64";
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

static int driver_cassandra_result_next_page(struct cassandra_result *result)
{
	struct cassandra_db *db = (struct cassandra_db *)result->api.db;

	if (db->page_size == 0) {
		/* no paging */
		return 0;
	}
	if (cass_result_has_more_pages(result->result) == cass_false)
		return 0;

	/* callers that don't support sql_query_more() will still get a useful
	   error message. */
	i_free(result->error);
	result->error = i_strdup("Paged query has more results, but not supported by the caller");
	return SQL_RESULT_NEXT_MORE;
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

	if (cass_iterator_next(result->iterator) == 0)
		return driver_cassandra_result_next_page(result);
	result->row_count++;
	result->total_row_count++;

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

static void
driver_cassandra_result_more(struct sql_result **_result, bool async,
			     sql_query_callback_t *callback, void *context)
{
	struct cassandra_db *db = (struct cassandra_db *)(*_result)->db;
	struct cassandra_result *new_result;
	struct cassandra_result *old_result =
		(struct cassandra_result *)*_result;

	/* Initialize the next page as a new sql_result */
	new_result = driver_cassandra_query_init(db, old_result->query,
						 CASSANDRA_QUERY_TYPE_READ_MORE,
						 old_result->is_prepared,
						 callback, context);

	/* Preserve the statement and update its paging state */
	new_result->statement = old_result->statement;
	old_result->statement = NULL;
	cass_statement_set_paging_state(new_result->statement,
					old_result->result);
	old_result->paging_continues = TRUE;
	/* The caller did support paging. Clear out the "...not supported by
	   the caller" error text, so it won't be in the debug log output. */
	i_free_and_null(old_result->error);

	new_result->timestamp = old_result->timestamp;
	new_result->consistency = old_result->consistency;
	new_result->page_num = old_result->page_num + 1;
	new_result->page0_start_time = old_result->page0_start_time;
	new_result->total_row_count = old_result->total_row_count;

	sql_result_unref(*_result);
	*_result = NULL;

	if (async)
		(void)driver_cassandra_send_query(new_result);
	else {
		i_assert(db->api.state == SQL_DB_STATE_IDLE);
		driver_cassandra_sync_init(db);
		(void)driver_cassandra_send_query(new_result);
		if (new_result->result == NULL) {
			db->io_pipe = io_loop_move_io(&db->io_pipe);
			io_loop_run(db->ioloop);
		}
		driver_cassandra_sync_deinit(db);

		callback(&new_result->api, context);
	}
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
	ctx->ctx.event = event_create(db->event);
	ctx->refcount = 1;
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

	event_unref(&ctx->ctx.event);
	i_free(ctx->query);
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
	struct sql_commit_result commit_result;

	i_zero(&commit_result);
	if (sql_result_next_row(result) < 0) {
		commit_result.error = sql_result_get_error(result);
		commit_result.error_type = sql_result_get_error_type(result);
		e_debug(sql_transaction_finished_event(&ctx->ctx)->
			add_str("error", commit_result.error)->event(),
			"Transaction failed");
	} else {
		e_debug(sql_transaction_finished_event(&ctx->ctx)->event(),
			"Transaction committed");
	}
	ctx->callback(&commit_result, ctx->context);
	driver_cassandra_transaction_unref(&ctx);
}

static void
driver_cassandra_transaction_commit(struct sql_transaction_context *_ctx,
				    sql_commit_callback_t *callback, void *context)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;
	struct cassandra_db *db = (struct cassandra_db *)_ctx->db;
	enum cassandra_query_type query_type;
	struct sql_commit_result result;

	i_zero(&result);
	ctx->callback = callback;
	ctx->context = context;

	if (ctx->failed || (ctx->query == NULL && ctx->stmt == NULL)) {
		if (ctx->failed)
			result.error = ctx->error;

		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", "Rolled back")->event(),
			"Transaction rolled back");
		callback(&result, context);
		driver_cassandra_transaction_unref(&ctx);
		return;
	}

	/* just a single query, send it */
	const char *query = ctx->query != NULL ?
		ctx->query : sql_statement_get_query(&ctx->stmt->stmt);
	if (strncasecmp(query, "DELETE ", 7) == 0)
		query_type = CASSANDRA_QUERY_TYPE_DELETE;
	else
		query_type = CASSANDRA_QUERY_TYPE_WRITE;

	if (ctx->query != NULL) {
		struct cassandra_result *cass_result;

		cass_result = driver_cassandra_query_init(db, query, query_type,
			FALSE, transaction_commit_callback, ctx);
		cass_result->statement = cass_statement_new(query, 0);
		if (ctx->query_timestamp != 0) {
			cass_result->timestamp = ctx->query_timestamp;
			cass_statement_set_timestamp(cass_result->statement,
						     ctx->query_timestamp);
		}
		(void)driver_cassandra_send_query(cass_result);
	} else {
		ctx->stmt->result =
			driver_cassandra_query_init(db, query, query_type, TRUE,
				transaction_commit_callback, ctx);
		if (ctx->stmt->cass_stmt == NULL) {
			/* wait for prepare to finish */
		} else {
			ctx->stmt->result->statement = ctx->stmt->cass_stmt;
			ctx->stmt->result->timestamp = ctx->stmt->timestamp;
			(void)driver_cassandra_send_query(ctx->stmt->result);
			pool_unref(&ctx->stmt->stmt.pool);
		}
	}
}

static void
driver_cassandra_try_commit_s(struct cassandra_transaction_context *ctx)
{
	struct sql_transaction_context *_ctx = &ctx->ctx;
	struct cassandra_db *db = (struct cassandra_db *)_ctx->db;
	struct sql_result *result = NULL;
	enum cassandra_query_type query_type;

	/* just a single query, send it */
	if (strncasecmp(ctx->query, "DELETE ", 7) == 0)
		query_type = CASSANDRA_QUERY_TYPE_DELETE;
	else
		query_type = CASSANDRA_QUERY_TYPE_WRITE;
	driver_cassandra_sync_init(db);
	result = driver_cassandra_sync_query(db, ctx->query, query_type);
	driver_cassandra_sync_deinit(db);

	if (sql_result_next_row(result) < 0)
		transaction_set_failed(ctx, sql_result_get_error(result));
	sql_result_unref(result);
}

static int
driver_cassandra_transaction_commit_s(struct sql_transaction_context *_ctx,
				      const char **error_r)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;

	if (ctx->stmt != NULL) {
		/* nothing should be using this - don't bother implementing */
		i_panic("cassandra: sql_transaction_commit_s() not supported for prepared statements");
	}

	if (ctx->query != NULL && !ctx->failed)
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

	if (ctx->query != NULL || ctx->stmt != NULL) {
		transaction_set_failed(ctx, "Multiple changes in transaction not supported");
		return;
	}
	ctx->query = i_strdup(query);
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

static CassError
driver_cassandra_bind_int(struct cassandra_sql_statement *stmt,
			  unsigned int column_idx, int64_t value)
{
	const CassDataType *data_type;
	CassValueType value_type;

	i_assert(stmt->prep != NULL);

	/* statements require exactly correct value type */
	data_type = cass_prepared_parameter_data_type(stmt->prep->prepared, column_idx);
	value_type = cass_data_type_type(data_type);

	switch (value_type) {
	case CASS_VALUE_TYPE_INT:
		if (value < -2147483648 || value > 2147483647)
			return CASS_ERROR_LIB_INVALID_VALUE_TYPE;
		return cass_statement_bind_int32(stmt->cass_stmt, column_idx, value);
	case CASS_VALUE_TYPE_TIMESTAMP:
	case CASS_VALUE_TYPE_BIGINT:
		return cass_statement_bind_int64(stmt->cass_stmt, column_idx, value);
	case CASS_VALUE_TYPE_SMALL_INT:
		if (value < -32768 || value > 32767)
			return CASS_ERROR_LIB_INVALID_VALUE_TYPE;
		return cass_statement_bind_int16(stmt->cass_stmt, column_idx, value);
	case CASS_VALUE_TYPE_TINY_INT:
		if (value < -128 || value > 127)
			return CASS_ERROR_LIB_INVALID_VALUE_TYPE;
		return cass_statement_bind_int8(stmt->cass_stmt, column_idx, value);
	default:
		return CASS_ERROR_LIB_INVALID_VALUE_TYPE;
	}
}

static void prepare_finish_arg(struct cassandra_sql_statement *stmt,
			       const struct cassandra_sql_arg *arg)
{
	CassError rc;

	if (arg->value_str != NULL) {
		rc = cass_statement_bind_string(stmt->cass_stmt, arg->column_idx,
						arg->value_str);
	} else if (arg->value_binary != NULL) {
		rc = cass_statement_bind_bytes(stmt->cass_stmt, arg->column_idx,
					       arg->value_binary,
					       arg->value_binary_size);
	} else {
		rc = driver_cassandra_bind_int(stmt, arg->column_idx,
					       arg->value_int64);
	}
	if (rc != CASS_OK) {
		e_error(stmt->stmt.db->event, "Statement '%s': Failed to bind column %u: %s",
			stmt->stmt.query_template, arg->column_idx,
			cass_error_desc(rc));
	}
}

static void prepare_finish_statement(struct cassandra_sql_statement *stmt)
{
	const struct cassandra_sql_arg *arg;

	if (stmt->prep->prepared == NULL) {
		i_assert(stmt->prep->error != NULL);

		if (stmt->result != NULL) {
			stmt->result->error = i_strdup(stmt->prep->error);
			result_finish(stmt->result);
		}
		return;
	}
	stmt->cass_stmt = cass_prepared_bind(stmt->prep->prepared);

	if (stmt->timestamp != 0)
		cass_statement_set_timestamp(stmt->cass_stmt, stmt->timestamp);

	if (array_is_created(&stmt->pending_args)) {
		array_foreach(&stmt->pending_args, arg)
			prepare_finish_arg(stmt, arg);
	}
	if (stmt->result != NULL) {
		stmt->result->statement = stmt->cass_stmt;
		stmt->result->timestamp = stmt->timestamp;
		(void)driver_cassandra_send_query(stmt->result);
		pool_unref(&stmt->stmt.pool);
	}
}

static void
prepare_finish_pending_statements(struct cassandra_sql_prepared_statement *prep_stmt)
{
	struct cassandra_sql_statement *const *stmtp;

	array_foreach(&prep_stmt->pending_statements, stmtp)
		prepare_finish_statement(*stmtp);
	array_clear(&prep_stmt->pending_statements);
}

static void prepare_callback(CassFuture *future, void *context)
{
	struct cassandra_sql_prepared_statement *prep_stmt = context;
	CassError error = cass_future_error_code(future);

	if (error != CASS_OK) {
		const char *errmsg;
		size_t errsize;

		cass_future_error_message(future, &errmsg, &errsize);
		i_free(prep_stmt->error);
		prep_stmt->error = i_strndup(errmsg, errsize);
	} else {
		prep_stmt->prepared = cass_future_get_prepared(future);
	}

	prepare_finish_pending_statements(prep_stmt);
}

static void prepare_start(struct cassandra_sql_prepared_statement *prep_stmt)
{
	struct cassandra_db *db = (struct cassandra_db *)prep_stmt->prep_stmt.db;
	CassFuture *future;

	if (!SQL_DB_IS_READY(&db->api)) {
		if (!prep_stmt->pending) {
			prep_stmt->pending = TRUE;
			array_append(&db->pending_prepares, &prep_stmt, 1);

			if (sql_connect(&db->api) < 0)
				i_unreached();
		}
		return;
	}

	/* clear the current error in case we're retrying */
	i_free_and_null(prep_stmt->error);

	future = cass_session_prepare(db->session, prep_stmt->query_template);
	driver_cassandra_set_callback(future, db, prepare_callback, prep_stmt);
}

static void driver_cassandra_prepare_pending(struct cassandra_db *db)
{
	struct cassandra_sql_prepared_statement *const *prep_stmtp;

	i_assert(SQL_DB_IS_READY(&db->api));

	array_foreach(&db->pending_prepares, prep_stmtp) {
		(*prep_stmtp)->pending = FALSE;
		prepare_start(*prep_stmtp);
	}
	array_clear(&db->pending_prepares);
}

static struct sql_prepared_statement *
driver_cassandra_prepared_statement_init(struct sql_db *db,
					 const char *query_template)
{
	struct cassandra_sql_prepared_statement *prep_stmt =
		i_new(struct cassandra_sql_prepared_statement, 1);
	prep_stmt->prep_stmt.db = db;
	prep_stmt->query_template = i_strdup(query_template);
	i_array_init(&prep_stmt->pending_statements, 4);
	prepare_start(prep_stmt);
	return &prep_stmt->prep_stmt;
}

static void
driver_cassandra_prepared_statement_deinit(struct sql_prepared_statement *_prep_stmt)
{
	struct cassandra_sql_prepared_statement *prep_stmt =
		(struct cassandra_sql_prepared_statement *)_prep_stmt;

	i_assert(array_count(&prep_stmt->pending_statements) == 0);
	if (prep_stmt->prepared != NULL)
		cass_prepared_free(prep_stmt->prepared);
	array_free(&prep_stmt->pending_statements);
	i_free(prep_stmt->query_template);
	i_free(prep_stmt->error);
	i_free(prep_stmt);
}

static struct sql_statement *
driver_cassandra_statement_init(struct sql_db *db ATTR_UNUSED,
				const char *query_template ATTR_UNUSED)
{
	pool_t pool = pool_alloconly_create("cassandra sql statement", 1024);
	struct cassandra_sql_statement *stmt =
		p_new(pool, struct cassandra_sql_statement, 1);
	stmt->stmt.pool = pool;
	return &stmt->stmt;
}

static struct sql_statement *
driver_cassandra_statement_init_prepared(struct sql_prepared_statement *_prep_stmt)
{
	struct cassandra_sql_prepared_statement *prep_stmt =
		(struct cassandra_sql_prepared_statement *)_prep_stmt;
	pool_t pool = pool_alloconly_create("cassandra prepared sql statement", 1024);
	struct cassandra_sql_statement *stmt =
		p_new(pool, struct cassandra_sql_statement, 1);

	stmt->stmt.pool = pool;
	stmt->stmt.query_template =
		p_strdup(stmt->stmt.pool, prep_stmt->query_template);
	stmt->prep = prep_stmt;

	if (prep_stmt->prepared != NULL) {
		/* statement is already prepared. we can use it immediately. */
		stmt->cass_stmt = cass_prepared_bind(prep_stmt->prepared);
	} else {
		if (prep_stmt->error != NULL)
			prepare_start(prep_stmt);
		/* need to wait until prepare is finished */
		array_append(&prep_stmt->pending_statements, &stmt, 1);
	}
	return &stmt->stmt;
}

static void
driver_cassandra_statement_abort(struct sql_statement *_stmt)
{
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;

	if (stmt->cass_stmt != NULL)
		cass_statement_free(stmt->cass_stmt);
}

static void
driver_cassandra_statement_set_timestamp(struct sql_statement *_stmt,
					 const struct timespec *ts)
{
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;
	cass_int64_t ts_usecs =
		(cass_int64_t)ts->tv_sec * 1000000ULL +
		ts->tv_nsec / 1000;

	i_assert(stmt->result == NULL);

	if (stmt->cass_stmt != NULL)
		cass_statement_set_timestamp(stmt->cass_stmt, ts_usecs);
	stmt->timestamp = ts_usecs;
}

static struct cassandra_sql_arg *
driver_cassandra_add_pending_arg(struct cassandra_sql_statement *stmt,
				 unsigned int column_idx)
{
	struct cassandra_sql_arg *arg;

	if (!array_is_created(&stmt->pending_args))
		p_array_init(&stmt->pending_args, stmt->stmt.pool, 8);
	arg = array_append_space(&stmt->pending_args);
	arg->column_idx = column_idx;
	return arg;
}

static void
driver_cassandra_statement_bind_str(struct sql_statement *_stmt,
				    unsigned int column_idx,
				    const char *value)
{
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;
	if (stmt->cass_stmt != NULL)
		cass_statement_bind_string(stmt->cass_stmt, column_idx, value);
	else if (stmt->prep != NULL) {
		struct cassandra_sql_arg *arg =
			driver_cassandra_add_pending_arg(stmt, column_idx);
		arg->value_str = p_strdup(_stmt->pool, value);
	}
}

static void
driver_cassandra_statement_bind_binary(struct sql_statement *_stmt,
				       unsigned int column_idx,
				       const void *value, size_t value_size)
{
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;

	if (stmt->cass_stmt != NULL) {
		cass_statement_bind_bytes(stmt->cass_stmt, column_idx,
					  value, value_size);
	} else if (stmt->prep != NULL) {
		struct cassandra_sql_arg *arg =
			driver_cassandra_add_pending_arg(stmt, column_idx);
		arg->value_binary = value_size == 0 ? &uchar_nul :
			p_memdup(_stmt->pool, value, value_size);
		arg->value_binary_size = value_size;
	}
}

static void
driver_cassandra_statement_bind_int64(struct sql_statement *_stmt,
				      unsigned int column_idx, int64_t value)
{
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;

	if (stmt->cass_stmt != NULL)
		driver_cassandra_bind_int(stmt, column_idx, value);
	else if (stmt->prep != NULL) {
		struct cassandra_sql_arg *arg =
			driver_cassandra_add_pending_arg(stmt, column_idx);
		arg->value_int64 = value;
	}
}

static void
driver_cassandra_statement_query(struct sql_statement *_stmt,
				 sql_query_callback_t *callback, void *context)
{
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;
	struct cassandra_db *db = (struct cassandra_db *)_stmt->db;
	const char *query = sql_statement_get_query(_stmt);
	bool is_prepared = stmt->cass_stmt != NULL || stmt->prep != NULL;

	stmt->result = driver_cassandra_query_init(db, query,
						   CASSANDRA_QUERY_TYPE_READ,
						   is_prepared,
						   callback, context);
	if (stmt->cass_stmt != NULL) {
		stmt->result->statement = stmt->cass_stmt;
		stmt->result->timestamp = stmt->timestamp;
	} else if (stmt->prep != NULL) {
		/* wait for prepare to finish */
		return;
	} else {
		stmt->result->statement = cass_statement_new(query, 0);
		stmt->result->timestamp = stmt->timestamp;
		if (stmt->timestamp != 0) {
			cass_statement_set_timestamp(stmt->result->statement,
						     stmt->timestamp);
		}
	}
	(void)driver_cassandra_send_query(stmt->result);
	pool_unref(&_stmt->pool);
}

static struct sql_result *
driver_cassandra_statement_query_s(struct sql_statement *_stmt ATTR_UNUSED)
{
	i_panic("cassandra: sql_statement_query_s() not supported");
}

static void
driver_cassandra_update_stmt(struct sql_transaction_context *_ctx,
			     struct sql_statement *_stmt,
			     unsigned int *affected_rows)
{
	struct cassandra_transaction_context *ctx =
		(struct cassandra_transaction_context *)_ctx;
	struct cassandra_sql_statement *stmt =
		(struct cassandra_sql_statement *)_stmt;

	i_assert(affected_rows == NULL);

	if (ctx->query != NULL || ctx->stmt != NULL) {
		transaction_set_failed(ctx, "Multiple changes in transaction not supported");
		return;
	}
	if (stmt->prep != NULL)
		ctx->stmt = stmt;
	else {
		ctx->query = i_strdup(sql_statement_get_query(_stmt));
		ctx->query_timestamp = stmt->timestamp;
		pool_unref(&_stmt->pool);
	}
}

const struct sql_db driver_cassandra_db = {
	.name = "cassandra",
	.flags = SQL_DB_FLAG_PREP_STATEMENTS,

	.v = {
		.init_full = driver_cassandra_init_full_v,
		.deinit = driver_cassandra_deinit_v,
		.connect = driver_cassandra_connect,
		.disconnect = driver_cassandra_disconnect,
		.escape_string = driver_cassandra_escape_string,
		.exec = driver_cassandra_exec,
		.query = driver_cassandra_query,
		.query_s = driver_cassandra_query_s,

		.transaction_begin = driver_cassandra_transaction_begin,
		.transaction_commit = driver_cassandra_transaction_commit,
		.transaction_commit_s = driver_cassandra_transaction_commit_s,
		.transaction_rollback = driver_cassandra_transaction_rollback,

		.update = driver_cassandra_update,

		.escape_blob = driver_cassandra_escape_blob,

		.prepared_statement_init = driver_cassandra_prepared_statement_init,
		.prepared_statement_deinit = driver_cassandra_prepared_statement_deinit,
		.statement_init = driver_cassandra_statement_init,
		.statement_init_prepared = driver_cassandra_statement_init_prepared,
		.statement_abort = driver_cassandra_statement_abort,
		.statement_set_timestamp = driver_cassandra_statement_set_timestamp,
		.statement_bind_str = driver_cassandra_statement_bind_str,
		.statement_bind_binary = driver_cassandra_statement_bind_binary,
		.statement_bind_int64 = driver_cassandra_statement_bind_int64,
		.statement_query = driver_cassandra_statement_query,
		.statement_query_s = driver_cassandra_statement_query_s,
		.update_stmt = driver_cassandra_update_stmt,
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
		driver_cassandra_result_get_error,
		driver_cassandra_result_more,
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
