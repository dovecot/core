/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "str.h"
#include "time-util.h"
#include "settings.h"
#include "sql-api-private.h"

#ifdef BUILD_PGSQL
#include <libpq-fe.h>

/* <settings checks> */
#define PGSQL_SQLPOOL_SET_NAME "pgsql"
/* </settings checks> */

struct pgsql_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) sqlpool_hosts;
	unsigned int connection_limit;

	const char *host;
	ARRAY_TYPE(const_string) parameters;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("pgsql_"#name, name, struct pgsql_settings)
static const struct setting_define pgsql_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = PGSQL_SQLPOOL_SET_NAME,
	  .offset = offsetof(struct pgsql_settings, sqlpool_hosts),
	  .filter_array_field_name = "pgsql_host", },
	DEF(UINT, connection_limit),

	DEF(STR, host),
	DEF(STRLIST, parameters),

	SETTING_DEFINE_LIST_END
};

static const struct pgsql_settings pgsql_default_settings = {
	.sqlpool_hosts = ARRAY_INIT,
	.connection_limit = SQL_DEFAULT_CONNECTION_LIMIT,

	.host = "",
	.parameters = ARRAY_INIT,
};

const struct setting_parser_info pgsql_setting_parser_info = {
	.name = "pgsql",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_pgsql",
#endif

	.defines = pgsql_setting_defines,
	.defaults = &pgsql_default_settings,

	.struct_size = sizeof(struct pgsql_settings),
	.pool_offset1 = 1 + offsetof(struct pgsql_settings, pool),
};

struct pgsql_db {
	struct sql_db api;

	const struct pgsql_settings *set;
	PGconn *pg;

	char *error;
	const char *connect_state;

	bool fatal_error:1;
};

struct pgsql_binary_value {
	unsigned char *value;
	size_t size;
};

struct pgsql_result {
	struct sql_result api;

	PGresult *pgres;

	unsigned int rownum, rows;
	unsigned int fields_count;
	const char **fields;
	const char **values;
	char *query;

	ARRAY(struct pgsql_binary_value) binary_values;

	sql_query_callback_t *callback;
	void *context;

	bool timeout:1;
};

struct pgsql_transaction_context {
	struct sql_transaction_context ctx;
	int refcount;

	sql_commit_callback_t *callback;
	void *context;

	pool_t query_pool;
	const char *error;

	bool failed:1;
};

struct pgsql_db_cache {
	/* Contains the sqlpool connection */
	struct sql_db *db;

	const struct pgsql_settings *set;
};

extern const struct sql_db driver_pgsql_db;
extern const struct sql_result driver_pgsql_result;

static ARRAY(struct pgsql_db_cache) pgsql_db_cache;

static void result_finish(struct pgsql_result *result);

static struct event_category event_category_pgsql = {
	.parent = &event_category_sql,
	.name = "pgsql"
};

static void pgsql_notice_processor(void *arg, const char *message)
{
	struct pgsql_db *db = arg;
	e_info(db->api.event, "%s", message);
}

static void driver_pgsql_close(struct pgsql_db *db)
{
	if (db->api.state == SQL_DB_STATE_DISCONNECTED)
		return;
	db->fatal_error = FALSE;

	PQfinish(db->pg);
	db->pg = NULL;

	sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);
	sql_connection_log_finished(&db->api);
}

static const char *last_error(struct pgsql_db *db)
{
	const char *msg, *pos, *orig;
	size_t len;

	orig = msg = PQerrorMessage(db->pg);
	if (msg == NULL)
		return "(no error set)";

	len = strlen(msg);
	/* The error can contain multiple lines, but we only want the last */
	while ((pos = strchr(msg, '\n')) != NULL && (pos - orig) < (ptrdiff_t)len - 1)
		msg = pos + 1;

	len = strlen(msg);
	/* Error message should contain trailing \n, we don't want it */
	return len == 0 || msg[len-1] != '\n' ? msg :
		t_strndup(msg, len-1);
}

static int driver_pgsql_connect(struct sql_db *_db)
{
	struct pgsql_db *db = container_of(_db, struct pgsql_db, api);

	i_assert(db->api.state == SQL_DB_STATE_DISCONNECTED);

	ARRAY_TYPE(const_string) keywords, values;
	t_array_init(&keywords, 16);
	t_array_init(&values, 16);

	/* Connection-level timeouts. PQconnectdbParams() resolves duplicate
	   keywords last-wins, so these are only defaults: a matching
	   pgsql_parameters entry below overrides them for free.

	   A dead peer never has anything unacknowledged in flight while
	   we're waiting on a query result, so tcp_user_timeout alone never
	   fires - it only bounds the keepalive probing window.
	   keepalives_idle must also be set, or that window never opens
	   (Linux default is 7200s). tcp_user_timeout itself is libpq 12+;
	   an unknown keyword is a hard connect failure, not a warning, so
	   it stays out of the table and is only added after a runtime
	   version check against whichever libpq is actually loaded. */
	const struct {
		const char *key, *value;
	} connect_defaults[] = {
		{ "connect_timeout",
		  t_strdup_printf("%u", SQL_CONNECT_TIMEOUT_SECS) },
		{ "keepalives_idle", "30" },
	};
	for (unsigned int di = 0; di < N_ELEMENTS(connect_defaults); di++) {
		array_push_back(&keywords, &connect_defaults[di].key);
		array_push_back(&values, &connect_defaults[di].value);
	}

	const char *tcp_user_timeout_str = "tcp_user_timeout";
	const char *tcp_user_timeout_val =
		t_strdup_printf("%u", SQL_QUERY_TIMEOUT_SECS * 1000);
	if (PQlibVersion() >= 120000) {
		array_push_back(&keywords, &tcp_user_timeout_str);
		array_push_back(&values, &tcp_user_timeout_val);
	}

	const char *host_str = "host";
	array_push_back(&keywords, &host_str);
	array_push_back(&values, &db->set->host);

	/* statement_timeout is a server-side GUC, set through the libpq
	   "options" connection parameter so it is re-applied on every
	   reconnect. Unlike the plain keyword/value pairs above, "options"
	   cannot simply be injected: it is a single opaque string and libpq
	   resolves a duplicate "options" keyword last-wins on the *whole*
	   string, so pushing our own pair after the user's would silently
	   discard any options the operator configured, and pushing it before
	   would silently discard our statement_timeout the moment the
	   operator sets pgsql_parameters/options for anything else (a
	   search_path, an application_name). The parameters loop therefore
	   scans for "options" and merges: our fragment first, the operator's
	   string(s) appended after it, so a later "-c" within the merged
	   string still wins. */
	string_t *options = t_str_new(64);
	str_printfa(options, "-c statement_timeout=%u",
		    SQL_QUERY_TIMEOUT_SECS * 1000);

	/* pgsql_parameters is a STRLIST, and array_is_created() may be FALSE
	   if none was ever set - a bare "host"-only configuration is
	   legitimate (e.g. peer/trust auth with no explicit user/dbname). */
	unsigned int i, count = 0;
	const char *const *strings = !array_is_created(&db->set->parameters) ?
		NULL : array_get(&db->set->parameters, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(strings[i], "options") == 0) {
			str_append_c(options, ' ');
			str_append(options, strings[i + 1]);
		} else {
			array_push_back(&keywords, &strings[i]);
			array_push_back(&values, &strings[i + 1]);
		}
	}

	const char *options_str = "options";
	const char *options_val = str_c(options);
	array_push_back(&keywords, &options_str);
	array_push_back(&values, &options_val);

	array_append_zero(&keywords);
	array_append_zero(&values);
	sql_db_set_state(&db->api, SQL_DB_STATE_CONNECTING);
	db->pg = PQconnectdbParams(array_front(&keywords),
				   array_front(&values), 0);
	if (db->pg == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "pgsql: PQconnectdbParams() failed (out of memory)");
	}

	(void)PQsetNoticeProcessor(db->pg, pgsql_notice_processor, db);

	if (PQstatus(db->pg) == CONNECTION_BAD) {
		const char *name = PQdb(db->pg);
		if (name == NULL)
			name = db->set->host;
		e_error(_db->event, "Connect failed to database %s: %s",
			name, last_error(db));
		i_free(db->api.last_connect_error);
		db->api.last_connect_error = i_strdup(last_error(db));
		driver_pgsql_close(db);
		return -1;
	}
	if (PQserverVersion(db->pg) >= 90500) {
		/* v9.5+ supports INSERT ... ON CONFLICT DO UPDATE */
		db->api.flags |= SQL_DB_FLAG_ON_CONFLICT_DO;
	}
	sql_db_set_state(&db->api, SQL_DB_STATE_IDLE);
	return 0;
}

static void driver_pgsql_disconnect(struct sql_db *_db)
{
	struct pgsql_db *db = container_of(_db, struct pgsql_db, api);

	driver_pgsql_close(db);
}

static void driver_pgsql_free(struct pgsql_db **_db)
{
	struct pgsql_db *db = *_db;
	*_db = NULL;

	driver_pgsql_disconnect(&db->api);
	event_unref(&db->api.event);
	settings_free(db->set);
	i_free(db->error);
	array_free(&db->api.module_contexts);
	i_free(db);
}

static enum sql_db_flags driver_pgsql_get_flags(struct sql_db *db)
{
	switch (db->state) {
	case SQL_DB_STATE_DISCONNECTED:
		/* driver_pgsql_connect() is synchronous: it always returns
		   with the state already IDLE or DISCONNECTED, so there is
		   nothing left to wait for here. */
		(void)sql_connect(db);
		break;
	case SQL_DB_STATE_IDLE:
	case SQL_DB_STATE_BUSY:
		break;
	case SQL_DB_STATE_CONNECTING:
		/* driver_pgsql_connect() never returns with the state left
		   at CONNECTING, so nothing external ever observes a
		   pgsql_db here. */
		i_unreached();
	}
	return db->flags;
}

static struct pgsql_db_cache *
driver_pgsql_db_cache_find(const struct pgsql_settings *set)
{
	struct pgsql_db_cache *cache;

	array_foreach_modifiable(&pgsql_db_cache, cache) {
		if (settings_equal(&pgsql_setting_parser_info,
				   set, cache->set, NULL))
			return cache;
	}
	return NULL;
}

static struct pgsql_db *
driver_pgsql_init_from_set(struct event *event_parent,
			   const struct pgsql_settings *set)
{
	struct pgsql_db *db;

	db = i_new(struct pgsql_db, 1);
	db->api = driver_pgsql_db;
	db->api.event = event_create(event_parent);
	db->set = set;
	event_add_category(db->api.event, &event_category_pgsql);
	event_add_str(db->api.event, "sql_driver", "pgsql");
	event_set_append_log_prefix(db->api.event,
				    t_strdup_printf("pgsql(%s): ", set->host));
	return db;
}

static int
driver_pgsql_init_v(struct event *event, struct sql_db **db_r,
		    const char **error_r)
{
	const struct pgsql_settings *set;

	if (settings_get(event, &pgsql_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;
	if (array_is_empty(&set->sqlpool_hosts)) {
		*error_r = "pgsql { .. } named list filter is missing";
		settings_free(set);
		return -1;
	}

	if (event_get_ptr(event, SQLPOOL_EVENT_PTR) == NULL) {
		/* See if there is already such a database */
		struct pgsql_db_cache *cache =
			driver_pgsql_db_cache_find(set);
		if (cache != NULL)
			settings_free(set);
		else {
			/* Use sqlpool for managing multiple connections.
			   Leave an extra reference to it, so it won't be freed
			   while it's still in the cache array. */
			struct sql_db *db =
				driver_sqlpool_init(&driver_pgsql_db, event,
						    PGSQL_SQLPOOL_SET_NAME,
						    &set->sqlpool_hosts,
						    set->connection_limit);
			cache = array_append_space(&pgsql_db_cache);
			cache->db = db;
			cache->set = set;
		}
		sql_ref(cache->db);
		*db_r = cache->db;
		return 0;
	}
	/* We're being initialized by sqlpool - create a real pgsql
	 connection. */

	struct pgsql_db *db = driver_pgsql_init_from_set(event, set);
	event_drop_parent_log_prefixes(db->api.event, 1);
	sql_init_common(&db->api);
	*db_r = &db->api;
	return 0;
}

static void driver_pgsql_deinit_v(struct sql_db *_db)
{
	struct pgsql_db *db = container_of(_db, struct pgsql_db, api);

	driver_pgsql_free(&db);
}

static void driver_pgsql_set_idle(struct pgsql_db *db)
{
	i_assert(db->api.state == SQL_DB_STATE_BUSY);

	if (db->fatal_error) {
		if (db->pg != NULL && PQstatus(db->pg) == CONNECTION_BAD)
			driver_pgsql_close(db);
		else {
			/* fatal_error was set due to a SQL error (e.g. bad
			   column name), not a connection failure. The connection
			   is still usable, so just clear the error and go idle. */
			db->fatal_error = FALSE;
			sql_db_set_state(&db->api, SQL_DB_STATE_IDLE);
		}
	} else
		sql_db_set_state(&db->api, SQL_DB_STATE_IDLE);
}

static void
driver_pgsql_result_free_binary_values(struct pgsql_result *result)
{
	struct pgsql_binary_value *value;

	if (!array_is_created(&result->binary_values))
		return;

	array_foreach_modifiable(&result->binary_values, value) {
		PQfreemem(value->value);
		i_zero(value);
	}
}

static void driver_pgsql_result_free(struct sql_result *_result)
{
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);

	i_assert(!result->api.callback);
	i_assert(result->callback == NULL);

	if (result->pgres != NULL) {
		PQclear(result->pgres);
		result->pgres = NULL;
	}

	driver_pgsql_result_free_binary_values(result);
	array_free(&result->binary_values);

	event_unref(&result->api.event);
	i_free(result->query);
	i_free(result->fields);
	i_free(result->values);
	i_free(result);
}

static void result_finish(struct pgsql_result *result)
{
	struct pgsql_db *db =
		container_of(result->api.db, struct pgsql_db, api);
	int duration;

	/* PGRES_FATAL_ERROR covers both a lost connection and a SQL error;
	   driver_pgsql_set_idle() tells them apart via PQstatus(). */
	if (PQstatus(db->pg) == CONNECTION_BAD || result->pgres == NULL ||
	    PQresultStatus(result->pgres) == PGRES_FATAL_ERROR)
		db->fatal_error = TRUE;

	/* A statement_timeout cancellation is a PGRES_FATAL_ERROR like any
	   other, but retrying it - the default for a fatal error - would
	   double the wall-clock time the caller waits, since a blocking
	   PQexec() cannot be bounded by anything but the server-side
	   timeout that just fired. SQLSTATE 57014 (query_canceled) is what
	   the server reports for a cancelled statement; treat it as
	   non-retryable and record it so sql_result_get_error() can report
	   "Query timed out" instead of the raw cancellation message. */
	const char *sqlstate = result->pgres == NULL ? NULL :
		PQresultErrorField(result->pgres, PG_DIAG_SQLSTATE);
	bool query_canceled = null_strcmp(sqlstate, "57014") == 0;

	if (db->fatal_error) {
		result->api.failed = TRUE;
		result->api.failed_try_retry = !query_canceled;
		result->timeout = query_canceled;
	}

	/* emit event */
	if (result->api.failed) {
		const char *error = result->timeout ? "Timed out" : last_error(db);
		struct event_passthrough *e =
			sql_query_finished_event(&db->api, result->api.event,
						 result->query, TRUE, &duration);
		e->add_str("error", error);
		e_debug(e->event(), SQL_QUERY_FINISHED_FMT": %s", result->query,
			duration, error);
	} else {
		struct event_passthrough *e =
			sql_query_finished_event(&db->api, result->api.event,
						 result->query, FALSE, &duration);
		e_debug(e->event(), SQL_QUERY_FINISHED_FMT,
			result->query, duration);
	}
	/* Release connection back to IDLE before invoking callback so that
	   nested queries (e.g. from dict-sql iterate handlers) can reuse this
	   connection. The result has been fully buffered by PQexec() and
	   no longer needs the connection state to be BUSY. */
	driver_pgsql_set_idle(db);
	result->api.callback = TRUE;
	T_BEGIN {
		if (result->callback != NULL)
			result->callback(&result->api, result->context);
	} T_END;
	result->api.callback = FALSE;
	result->callback = NULL;
}

static void do_query(struct pgsql_result *result, const char *query)
{
	struct pgsql_db *db =
		container_of(result->api.db, struct pgsql_db, api);

	i_assert(SQL_DB_IS_READY(&db->api));

	sql_db_set_state(&db->api, SQL_DB_STATE_BUSY);
	result->query = i_strdup(query);
	result->pgres = PQexec(db->pg, query);
	result_finish(result);
}

static int
driver_pgsql_escape_string(struct sql_db *_db, const char *string,
			   const char **output_r, const char **error_r)
{
	struct pgsql_db *db = container_of(_db, struct pgsql_db, api);
	size_t len = strlen(string);
	char *to;

#ifdef HAVE_PQESCAPE_STRING_CONN
	if (db->api.state == SQL_DB_STATE_DISCONNECTED) {
		/* try connecting again */
		(void)sql_connect(&db->api);
	}
	if (db->api.state != SQL_DB_STATE_DISCONNECTED) {
		int error;

		to = t_buffer_get(len * 2 + 1);
		len = PQescapeStringConn(db->pg, to, string, len, &error);
		if (error != 0) {
			*error_r = last_error(db);
			return -1;
		}
		t_buffer_alloc(len + 1);
		*output_r = to;
		return 0;
	} else {
		*error_r = SQL_ERRSTR_NOT_CONNECTED;
		return -1;
	}
#else
	to = t_buffer_get(len * 2 + 1);
	len = PQescapeString(to, string, len);
	t_buffer_alloc(len + 1);
	*output_r = to;
	return 0;
#endif
}

static struct pgsql_result *new_result(struct sql_db *db)
{
	struct pgsql_result *result = i_new(struct pgsql_result, 1);
	result->api = driver_pgsql_result;
	result->api.db = db;
	result->api.refcount = 1;
	result->api.event = event_create(db->event);
	return result;
}

static void driver_pgsql_exec(struct sql_db *db, const char *query)
{
	struct pgsql_result *result;

	result = new_result(db);
	do_query(result, query);
	sql_result_unref(&result->api);
}

static struct sql_result *
driver_pgsql_sync_query(struct pgsql_db *db, const char *query)
{
	if (db->api.state == SQL_DB_STATE_DISCONNECTED) {
		if (sql_connect(&db->api) < 0) {
			sql_not_connected_result.refcount++;
			return &sql_not_connected_result;
		}
	}

	struct pgsql_result *result = new_result(&db->api);
	do_query(result, query);
	return &result->api;
}

static struct sql_result *
driver_pgsql_query_s(struct sql_db *_db, const char *query)
{
	struct pgsql_db *db = container_of(_db, struct pgsql_db, api);

	return driver_pgsql_sync_query(db, query);
}

static int driver_pgsql_result_next_row(struct sql_result *_result)
{
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);
	struct pgsql_db *db = container_of(_result->db, struct pgsql_db, api);

	/* The cached binary values belong to the row we're leaving. The
	   sql_result API returns field values only until the next row is
	   fetched, so drop them - otherwise every following row would be
	   given the first row's values. */
	driver_pgsql_result_free_binary_values(result);

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
		return result->rows > 0 ? 1 : 0;
	case PGRES_EMPTY_QUERY:
	case PGRES_NONFATAL_ERROR:
	default:
		/* db->fatal_error is left alone: result_finish() decided it. */
		_result->failed = TRUE;
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
	if (result->fields_count == 0)
		return;
	result->fields = i_new(const char *, result->fields_count);
	for (i = 0; i < result->fields_count; i++)
		result->fields[i] = PQfname(result->pgres, i);
}

static unsigned int
driver_pgsql_result_get_fields_count(struct sql_result *_result)
{
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);

	driver_pgsql_result_fetch_fields(result);
	return result->fields_count;
}

static const char *
driver_pgsql_result_get_field_name(struct sql_result *_result, unsigned int idx)
{
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);

	driver_pgsql_result_fetch_fields(result);
	i_assert(idx < result->fields_count);
	return result->fields[idx];
}

static int driver_pgsql_result_find_field(struct sql_result *_result,
					  const char *field_name)
{
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);
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
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);

	if (PQgetisnull(result->pgres, result->rownum, idx) != 0)
		return NULL;

	return PQgetvalue(result->pgres, result->rownum, idx);
}

static const unsigned char *
driver_pgsql_result_get_field_value_binary(struct sql_result *_result,
					   unsigned int idx, size_t *size_r)
{
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);
	const char *value;
	struct pgsql_binary_value *binary_value;

	if (PQgetisnull(result->pgres, result->rownum, idx) != 0) {
		*size_r = 0;
		return NULL;
	}

	value = PQgetvalue(result->pgres, result->rownum, idx);

	if (!array_is_created(&result->binary_values))
		i_array_init(&result->binary_values, idx + 1);

	binary_value = array_idx_get_space(&result->binary_values, idx);
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
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);
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
	struct pgsql_result *result =
		container_of(_result, struct pgsql_result, api);
	struct pgsql_db *db = container_of(_result->db, struct pgsql_db, api);
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
	ctx->ctx.event = event_create(db->event);
	/* we need to be able to handle multiple open transactions, so at least
	   for now just keep them in memory until commit time. */
	ctx->query_pool = pool_alloconly_create("pgsql transaction", 1024);
	return &ctx->ctx;
}

static void
driver_pgsql_transaction_free(struct pgsql_transaction_context *ctx)
{
	pool_unref(&ctx->query_pool);
	event_unref(&ctx->ctx.event);
	i_free(ctx);
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
	struct pgsql_db *db = container_of(ctx->ctx.db, struct pgsql_db, api);
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

			if (str_to_uint(PQcmdTuples(pg_result->pgres),
					query->affected_rows) < 0)
				i_unreached();
		}
		sql_result_unref(result);
	}

	return driver_pgsql_sync_query(db, ctx->failed ?
				       "ROLLBACK" : "COMMIT");
}

static void
driver_pgsql_try_commit_s(struct pgsql_transaction_context *ctx,
			  const char **error_r)
{
	struct sql_transaction_context *_ctx = &ctx->ctx;
	struct sql_transaction_query *single_query = NULL;
	struct sql_result *result;

	i_assert(_ctx->head != NULL);
	if (_ctx->head->next == NULL) {
		/* just a single query, send it */
		single_query = _ctx->head;
		result = sql_query_s(_ctx->db, single_query->query);
		if (result->failed) {
			ctx->failed = TRUE;
			ctx->error = driver_pgsql_result_get_error(result);
		}
	} else {
		/* multiple queries, use a transaction */
		result = driver_pgsql_transaction_commit_multi(ctx);
	}

	if (ctx->failed) {
		i_assert(ctx->error != NULL);
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", ctx->error)->event(),
			"Transaction failed: %s", ctx->error);
		*error_r = ctx->error;
	} else if (result != NULL) {
		if (sql_result_next_row(result) < 0)
			*error_r = sql_result_get_error(result);
		else if (single_query != NULL &&
			 single_query->affected_rows != NULL) {
			struct pgsql_result *pg_result =
				container_of(result, struct pgsql_result, api);

			if (str_to_uint(PQcmdTuples(pg_result->pgres),
					single_query->affected_rows) < 0)
				i_unreached();
		}
	}

	if (!ctx->failed) {
		e_debug(sql_transaction_finished_event(_ctx)->event(),
			"Transaction committed");
	}

	if (result != NULL)
		sql_result_unref(result);
}

static int
driver_pgsql_transaction_commit_s(struct sql_transaction_context *_ctx,
				  const char **error_r)
{
	struct pgsql_transaction_context *ctx =
		container_of(_ctx, struct pgsql_transaction_context, ctx);
	struct pgsql_db *db = container_of(_ctx->db, struct pgsql_db, api);

	*error_r = NULL;

	if (_ctx->head != NULL) {
		driver_pgsql_try_commit_s(ctx, error_r);
		if (_ctx->db->state == SQL_DB_STATE_DISCONNECTED) {
			*error_r = t_strdup(*error_r);
			e_info(db->api.event, "Disconnected from database, "
			       "retrying commit");
			if (sql_connect(_ctx->db) >= 0) {
				ctx->failed = FALSE;
				*error_r = NULL;
				driver_pgsql_try_commit_s(ctx, error_r);
			}
		}
	}

	driver_pgsql_transaction_free(ctx);
	return *error_r == NULL ? 0 : -1;
}

static void
driver_pgsql_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct pgsql_transaction_context *ctx =
		container_of(_ctx, struct pgsql_transaction_context, ctx);
	e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", "Rolled back")->event(),
		"Transaction rolled back");

	driver_pgsql_transaction_free(ctx);
}

static void
driver_pgsql_update(struct sql_transaction_context *_ctx, const char *query,
		    unsigned int *affected_rows)
{
	struct pgsql_transaction_context *ctx =
		container_of(_ctx, struct pgsql_transaction_context, ctx);

	sql_transaction_add_query(_ctx, ctx->query_pool, query, affected_rows);
}

static const char *
driver_pgsql_escape_blob(struct sql_db *_db ATTR_UNUSED,
			 const unsigned char *data, size_t size)
{
	string_t *str = t_str_new(128);

	str_append(str, "E'\\\\x");
	binary_to_hex_append(str, data, size);
	str_append_c(str, '\'');
	return str_c(str);
}

const struct sql_db driver_pgsql_db = {
	.name = "pgsql",
	.flags = SQL_DB_FLAG_BLOCKING | SQL_DB_FLAG_POOLED,

	.v = {
		.get_flags = driver_pgsql_get_flags,
		.init = driver_pgsql_init_v,
		.deinit = driver_pgsql_deinit_v,
		.connect = driver_pgsql_connect,
		.disconnect = driver_pgsql_disconnect,
		.escape_string = driver_pgsql_escape_string,
		.exec = driver_pgsql_exec,
		.query_s = driver_pgsql_query_s,

		.transaction_begin = driver_pgsql_transaction_begin,
		.transaction_commit_s = driver_pgsql_transaction_commit_s,
		.transaction_rollback = driver_pgsql_transaction_rollback,

		.update = driver_pgsql_update,

		.escape_blob = driver_pgsql_escape_blob,
	}
};

const struct sql_result driver_pgsql_result = {
	.v = {
		.free = driver_pgsql_result_free,
		.next_row = driver_pgsql_result_next_row,
		.get_fields_count = driver_pgsql_result_get_fields_count,
		.get_field_name = driver_pgsql_result_get_field_name,
		.find_field = driver_pgsql_result_find_field,
		.get_field_value = driver_pgsql_result_get_field_value,
		.get_field_value_binary = driver_pgsql_result_get_field_value_binary,
		.find_field_value = driver_pgsql_result_find_field_value,
		.get_values = driver_pgsql_result_get_values,
		.get_error = driver_pgsql_result_get_error,
	}
};

const char *driver_pgsql_version = DOVECOT_ABI_VERSION;

void driver_pgsql_init(void)
{
	i_array_init(&pgsql_db_cache, 4);
	sql_driver_register(&driver_pgsql_db);
}

void driver_pgsql_deinit(void)
{
	struct pgsql_db_cache *cache;

	if (!array_is_created(&pgsql_db_cache))
		return;

	array_foreach_modifiable(&pgsql_db_cache, cache) {
		settings_free(cache->set);
		sql_unref(&cache->db);
	}
	array_free(&pgsql_db_cache);
	sql_driver_unregister(&driver_pgsql_db);
}

#endif
