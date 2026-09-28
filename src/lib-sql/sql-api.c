/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "str.h"
#include "time-util.h"
#include "settings.h"
#include "settings-parser.h"
#include "sql-api-private.h"

#include <ctype.h>
#include <time.h>

struct sql_query_result_delayed {
	struct sql_query_result_delayed *prev, *next;

	struct sql_db *db;
	struct timeout *to;

	struct sql_result *result;
	sql_query_callback_t *callback;
	void *context;
};

struct sql_commit_result_delayed {
	struct sql_commit_result_delayed *prev, *next;

	struct sql_db *db;
	struct timeout *to;

	char *error;
	sql_commit_callback_t *callback;
	void *context;
};

struct event_category event_category_sql = {
	.name = "sql",
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct sql_settings)
static const struct setting_define sql_setting_defines[] = {
	DEF(STR, sql_driver),

	SETTING_DEFINE_LIST_END
};
static const struct sql_settings sql_default_settings = {
	.sql_driver = "",
};
const struct setting_parser_info sql_setting_parser_info = {
	.name = "sql",

	.defines = sql_setting_defines,
	.defaults = &sql_default_settings,

	.struct_size = sizeof(struct sql_settings),
	.pool_offset1 = 1 + offsetof(struct sql_settings, pool),
};

struct sql_db_module_register sql_db_module_register = { 0 };
ARRAY_TYPE(sql_drivers) sql_drivers;

static void sql_query_delayed_callback(struct sql_query_result_delayed *cb);
static void sql_commit_delayed_callback(struct sql_commit_result_delayed *cb);

struct sql_result_error {
	struct sql_result result;
	char *error;
};

static void sql_result_error_free(struct sql_result *_result)
{
	struct sql_result_error *result =
		container_of(_result, struct sql_result_error, result);
	i_free(result->error);
	i_free(result);
}

static int sql_result_error_next_row(struct sql_result *result ATTR_UNUSED)
{
	return -1;
}

static const char *
sql_result_error_get_error(struct sql_result *_result)
{
	struct sql_result_error *result =
		container_of(_result, struct sql_result_error, result);
	return result->error;
}

static const struct sql_result_vfuncs sql_result_error_vfuncs = {
	.free = sql_result_error_free,
	.next_row = sql_result_error_next_row,
	.get_error = sql_result_error_get_error,
};

static struct sql_result *sql_result_new_error(const char *error)
{
	struct sql_result_error *result = i_new(struct sql_result_error, 1);
	result->result.v = sql_result_error_vfuncs;
	result->result.failed = TRUE;
	result->result.refcount = 1;
	result->error = i_strdup(error);
	return &result->result;
}

static void
sql_query_callback_delayed(struct sql_db *db, struct sql_result *result,
			   sql_query_callback_t *callback, void *context)
{
	struct sql_query_result_delayed *cb =
		i_new(struct sql_query_result_delayed, 1);
	cb->db = db;
	cb->result = result;
	cb->callback = callback;
	cb->context = context;
	cb->to = timeout_add_short(0, sql_query_delayed_callback, cb);
	DLLIST_PREPEND(&db->query_delayed_list, cb);
}

void sql_drivers_init_without_drivers(void)
{
	i_array_init(&sql_drivers, 8);
}

void sql_drivers_deinit_without_drivers(void)
{
	array_free(&sql_drivers);
}

extern struct sql_db driver_sqlpool_db;

void sql_drivers_init(void)
{
	/* Access driver-sqlpool in some way to avoid dropping the .o entirely
	   when linking libsql.a to auth process when sql drivers are built as
	   plugins. */
	if (driver_sqlpool_db.v.init != NULL)
		i_unreached();

	sql_drivers_init_without_drivers();
	sql_drivers_init_all();
}

void sql_drivers_deinit(void)
{
	sql_drivers_deinit_all();
	sql_drivers_deinit_without_drivers();
}

static const struct sql_db *sql_driver_lookup(const char *name)
{
	const struct sql_db *const *drivers;
	unsigned int i, count;

	drivers = array_get(&sql_drivers, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(drivers[i]->name, name) == 0)
			return drivers[i];
	}
	return NULL;
}

void sql_driver_register(const struct sql_db *driver)
{
	if (sql_driver_lookup(driver->name) != NULL) {
		i_fatal("sql_driver_register(%s): Already registered",
			driver->name);
	}
	array_push_back(&sql_drivers, &driver);
}

void sql_driver_unregister(const struct sql_db *driver)
{
	unsigned int i;

	if (!array_lsearch_ptr_idx(&sql_drivers, driver, &i))
		i_unreached();
	array_delete(&sql_drivers, i, 1);
}

int sql_init_auto(struct event *event, struct sql_db **db_r,
		  const char **error_r)
{
	const struct sql_db *driver;
	struct sql_db *db;
	struct sql_settings *sql_set;
	const char *error;

	i_assert(event != NULL);

	if (settings_get(event, &sql_setting_parser_info, 0,
			 &sql_set, error_r) < 0)
		return -1;

	if (sql_set->sql_driver[0] == '\0') {
		*error_r = "sql_driver setting is empty";
		settings_free(sql_set);
		return 0;
	}
	driver = sql_driver_lookup(sql_set->sql_driver);
	if (driver == NULL) {
		*error_r = t_strdup_printf("Unknown database driver '%s'",
					   sql_set->sql_driver);
		settings_free(sql_set);
		return -1;
	}

	if (driver->v.init(event, &db, &error) < 0) {
		*error_r = t_strdup_printf("sql %s: %s",
					   sql_set->sql_driver, error);
		settings_free(sql_set);
		return -1;
	}

	settings_free(sql_set);
	*db_r = db;
	return 1;
}


void sql_init_common(struct sql_db *db)
{
	db->refcount = 1;
	i_array_init(&db->module_contexts, 5);
	hash_table_create(&db->prepared_stmt_hash, default_pool, 0,
			  str_hash, strcmp);
}

void sql_ref(struct sql_db *db)
{
	i_assert(db->refcount > 0);
	db->refcount++;
}

void default_sql_prepared_statement_deinit(struct sql_prepared_statement *prep_stmt)
{
	i_free(prep_stmt->query_template);
	i_free(prep_stmt);
}

static void sql_prepared_statements_free(struct sql_db *db)
{
	struct hash_iterate_context *iter;
	struct sql_prepared_statement *prep_stmt;
	char *query;

	iter = hash_table_iterate_init(db->prepared_stmt_hash);
	while (hash_table_iterate(iter, db->prepared_stmt_hash, &query, &prep_stmt)) {
		i_assert(prep_stmt->refcount == 0);
		if (prep_stmt->db->v.prepared_statement_deinit != NULL)
			prep_stmt->db->v.prepared_statement_deinit(prep_stmt);
		else
			default_sql_prepared_statement_deinit(prep_stmt);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_clear(db->prepared_stmt_hash, TRUE);
}

void sql_unref(struct sql_db **_db)
{
	struct sql_db *db = *_db;

	*_db = NULL;

	i_assert(db->refcount > 0);
	if (db->v.unref != NULL)
		db->v.unref(db);
	if (--db->refcount > 0)
		return;

	timeout_remove(&db->to_reconnect);
	sql_prepared_statements_free(db);
	hash_table_destroy(&db->prepared_stmt_hash);
	db->v.deinit(db);
}

enum sql_db_flags sql_get_flags(struct sql_db *db)
{
	if (db->v.get_flags != NULL)
		return db->v.get_flags(db);
	else
		return db->flags;
}

int sql_connect(struct sql_db *db)
{
	time_t now;

	switch (db->state) {
	case SQL_DB_STATE_DISCONNECTED:
		break;
	case SQL_DB_STATE_CONNECTING:
		return 0;
	default:
		return 1;
	}

	/* don't try reconnecting more than once a second */
	now = time(NULL);
	if (db->last_connect_try + (time_t)db->connect_delay > now)
		return -1;
	db->last_connect_try = now;

	return db->v.connect(db);
}

static void sql_call_delayed_callbacks(struct sql_db *db)
{
	/* flush any pending results */
	while (db->query_delayed_list != NULL)
		sql_query_delayed_callback(db->query_delayed_list);
	while (db->commit_delayed_list != NULL)
		sql_commit_delayed_callback(db->commit_delayed_list);
}

void sql_disconnect(struct sql_db *db)
{
	timeout_remove(&db->to_reconnect);
	sql_call_delayed_callbacks(db);
	db->v.disconnect(db);
}

int sql_escape_string(struct sql_db *db, const char *string,
		      const char **output_r, const char **error_r)
{
	return db->v.escape_string(db, string, output_r, error_r);
}

const char *sql_escape_blob(struct sql_db *db,
			    const unsigned char *data, size_t size)
{
	return db->v.escape_blob(db, data, size);
}

void sql_exec(struct sql_db *db, const char *query)
{
	db->v.exec(db, query);
}

static void sql_query_delayed_callback(struct sql_query_result_delayed *cb)
{
	timeout_remove(&cb->to);
	DLLIST_REMOVE(&cb->db->query_delayed_list, cb);
	cb->callback(cb->result, cb->context);
	sql_result_unref(cb->result);
	i_free(cb);
}

#undef sql_query
void sql_query(struct sql_db *db, const char *query,
	       sql_query_callback_t *callback, void *context)
{
	if (db->v.query != NULL) {
		db->v.query(db, query, callback, context);
		return;
	}

	sql_query_callback_delayed(db, sql_query_s(db, query),
				   callback, context);
}

struct sql_result *sql_query_s(struct sql_db *db, const char *query)
{
	return db->v.query_s(db, query);
}

struct sql_prepared_statement *
default_sql_prepared_statement_init(struct sql_db *db,
				    const char *query_template)
{
	struct sql_prepared_statement *prep_stmt;

	prep_stmt = i_new(struct sql_prepared_statement, 1);
	prep_stmt->db = db;
	prep_stmt->refcount = 1;
	prep_stmt->query_template = i_strdup(query_template);
	return prep_stmt;
}

static struct sql_statement *
default_sql_statement_init_prepared(struct sql_prepared_statement *stmt)
{
	return sql_statement_init(stmt->db, stmt->query_template);
}

/* Scanner states: SQUOTE/DQUOTE/BACKTICK track a quoted string or quoted
   identifier. A '?' is a bind placeholder only in CODE. This is a skip
   lexer, not a full SQL lexer: it recognizes no keywords, numbers or
   operators, and its only output is placeholder offsets. A backslash
   inside a '...'-quoted string, any unquoted comment introducer ('--',
   '/ *', '//', '#'), an unquoted dollar-quote open tag ('$$' or
   '$tag$') and an unquoted '$' followed by a digit (a PostgreSQL
   positional parameter, '$1') are constructs it refuses to guess at
   and rejects at scan time instead - see sql_template_scan()'s
   declaration for why each one is unsafe to guess at. There is
   therefore no comment or dollar-quote state to be in: entering either
   is itself the error. Everything else - a quoted identifier's own
   dialect-specific syntax, such as sqlite's '[ident]', and a '$' that
   is not a dollar-quote open tag, such as one inside a mysql
   identifier - is simply scanned as CODE; see the declaration for the
   one residual case that is not fully safe either. */
enum sql_template_scan_state {
	SQL_TEMPLATE_SCAN_CODE = 0,
	SQL_TEMPLATE_SCAN_SQUOTE,
	SQL_TEMPLATE_SCAN_DQUOTE,
	SQL_TEMPLATE_SCAN_BACKTICK,
};

/* Returns TRUE if query_template[i] (a '$') is not itself a
   continuation of a preceding identifier, i.e. it could open a
   PostgreSQL dollar-quote or positional parameter rather than just
   being part of an unquoted identifier such as mysql's "my$col". Both
   mysql and PostgreSQL allow '$' anywhere in an unquoted identifier,
   including doubled or repeated ("a$$b", "a$tag$b" are each a single
   identifier there), and identifier matching is greedy, so neither
   ever falls into dollar-quote state mid-identifier.

   This check is deliberately ASCII-only, unlike the tag itself (see
   sql_template_scan_is_dollar_quote()): a byte with the high bit set
   before the '$' is treated as a boundary, not as an identifier
   character, even though it may be one in mysql or PostgreSQL.
   Treating it as a boundary only ever rejects a construct that was
   actually just part of an identifier, never the reverse - the
   direction that would hide a real placeholder.

   This is judged from a single preceding character, not a full token
   classification, so a '$' right after a bare digit run is also
   treated as identifier continuation, the same as after a letter -
   unlike a real SQL lexer, which would still treat it as a boundary
   there, since digits alone lex as a number, not an identifier. A
   number literal directly abutting a dollar-quoted string or
   positional parameter, with no operator between them, is already a
   syntax error in every dialect this file supports, so no valid query
   is affected by treating it the same as an identifier. */
static bool
sql_template_dollar_at_boundary(const char *query_template, unsigned int i)
{
	if (i == 0)
		return TRUE;
	char prev = query_template[i - 1];
	return !i_isalnum(prev) && prev != '_' && prev != '$';
}

/* Returns TRUE if query_template[i] (a '$' at an identifier boundary,
   per sql_template_dollar_at_boundary()) opens a PostgreSQL
   dollar-quoted string - "$$" or "$tag$", where tag follows the rules
   for an unquoted identifier, including the non-ASCII letters that
   rule allows. */
static bool
sql_template_scan_is_dollar_quote(const char *query_template, unsigned int i)
{
	unsigned int j = i + 1;
	if (query_template[j] == '$')
		return TRUE;
	if (!i_isalpha(query_template[j]) && query_template[j] != '_' &&
	    ((unsigned char)query_template[j] & 0x80) == 0)
		return FALSE;
	for (j++; i_isalnum(query_template[j]) || query_template[j] == '_' ||
	     ((unsigned char)query_template[j] & 0x80) != 0; j++) ;
	return query_template[j] == '$';
}

bool sql_template_scan(const char *query_template,
		       ARRAY_TYPE(uint) *offsets_r, const char **error_r)
{
	enum sql_template_scan_state state = SQL_TEMPLATE_SCAN_CODE;

	for (unsigned int i = 0; query_template[i] != '\0'; i++) {
		char c = query_template[i];

		switch (state) {
		case SQL_TEMPLATE_SCAN_CODE:
			if (c == '\'')
				state = SQL_TEMPLATE_SCAN_SQUOTE;
			else if (c == '"')
				state = SQL_TEMPLATE_SCAN_DQUOTE;
			else if (c == '`')
				state = SQL_TEMPLATE_SCAN_BACKTICK;
			else if (c == '?') {
				array_push_back(offsets_r, &i);
			} else if (c == '#' ||
				  (c == '-' && query_template[i+1] == '-') ||
				  (c == '/' && (query_template[i+1] == '*' ||
						query_template[i+1] == '/'))) {
				const char *what = c == '#' ? "'#'" :
					c == '-' ? "'--'" :
					query_template[i+1] == '*' ? "'/*'" : "'//'";
				/* No offset: it would be into this generated
				   template, after %{variable} substitutions
				   have already collapsed to '?', not into the
				   admin's own query text - a wrong number is
				   worse than none. */
				*error_r = t_strdup_printf(
					"query template has a %s comment "
					"outside a quoted string - comments "
					"are not allowed in a query template; "
					"bind placeholders after it cannot be "
					"located reliably", what);
				return FALSE;
			} else if (c == '$' &&
				  sql_template_dollar_at_boundary(query_template, i) &&
				  i_isdigit(query_template[i+1])) {
				*error_r = "query template has a '$' followed "
					"by a digit outside a quoted string - "
					"that is a PostgreSQL positional "
					"parameter ($1, $2, ...), not a bind "
					"placeholder; use '?' placeholders "
					"instead";
				return FALSE;
			} else if (c == '$' &&
				  sql_template_dollar_at_boundary(query_template, i) &&
				  sql_template_scan_is_dollar_quote(query_template, i)) {
				*error_r = "query template has a dollar-quoted "
					"string outside a quoted string - a "
					"dollar-quoted string is not allowed in "
					"a query template; bind placeholders "
					"after it cannot be located reliably";
				return FALSE;
			}
			break;
		case SQL_TEMPLATE_SCAN_SQUOTE:
			if (c == '\\') {
				/* Whether this escapes the next character
				   (mysql, PostgreSQL's E'...') or is just a
				   literal backslash (standard-conforming
				   string) decides whether the string closes
				   at the next quote or keeps going - and
				   getting that wrong can both hide a real
				   placeholder inside the reopened string and
				   count a literal '?' still inside this one,
				   changing offsets without changing the
				   total count, so a mismatch check would not
				   catch it. Escape a quote with '' (a
				   doubled single quote), which every one of
				   these dialects treats the same way,
				   instead of '\''. */
				*error_r = "query template has a backslash "
					"inside a '...'-quoted string - bind "
					"placeholders after it cannot be "
					"located reliably; escape a quote as "
					"'' (a doubled single quote), not \\'";
				return FALSE;
			}
			if (c == '\'')
				state = SQL_TEMPLATE_SCAN_CODE;
			break;
		case SQL_TEMPLATE_SCAN_DQUOTE:
			if (c == '"')
				state = SQL_TEMPLATE_SCAN_CODE;
			break;
		case SQL_TEMPLATE_SCAN_BACKTICK:
			if (c == '`')
				state = SQL_TEMPLATE_SCAN_CODE;
			break;
		}
	}
	return TRUE;
}

bool sql_template_placeholder_count(const char *query_template,
				    unsigned int *count_r,
				    const char **error_r)
{
	ARRAY_TYPE(uint) offsets;

	t_array_init(&offsets, 4);
	if (!sql_template_scan(query_template, &offsets, error_r))
		return FALSE;
	*count_r = array_count(&offsets);
	return TRUE;
}

/* tolerant=FALSE is used to build the query that actually executes: a
   template/bind count mismatch means the statement was built wrong, and
   silently executing the wrong query is worse than aborting, so it
   panics exactly as before. tolerant=TRUE is used only to render a
   statement for logging: it must never abort the process over a
   mismatch it did not cause, so instead an unbound placeholder is
   emitted as '?' and any surplus bound args are simply never
   consumed. */
static int
sql_statement_build_query(struct sql_statement *stmt, bool tolerant,
			  const bool *no_log_fields, unsigned int no_log_count,
			  const char **query_r, const char **error_r)
{
	if (stmt->template_scan_error != NULL) {
		*error_r = stmt->template_scan_error;
		return -1;
	}

	string_t *query = str_new(default_pool, 128);
	const char *const *args;
	const bool *need_escaping_flags;
	const unsigned int *offsets;
	unsigned int args_count, need_escaping_count, offset_count;
	unsigned int prev = 0;

	args = array_get(&stmt->args, &args_count);
	need_escaping_flags = array_get(&stmt->args_need_escaping, &need_escaping_count);
	offsets = array_get(&stmt->placeholders, &offset_count);
	for (unsigned int arg_pos = 0; arg_pos < offset_count; arg_pos++) {
		unsigned int off = offsets[arg_pos];

		/* append until the placeholder */
		str_append_data(query, stmt->query_template + prev, off - prev);
		bool have_arg = arg_pos < args_count && args[arg_pos] != NULL;
		if (!have_arg && !tolerant) {
			i_panic("lib-sql: Missing bind for arg #%u in statement: %s",
				arg_pos, stmt->query_template);
		}
		if (!have_arg) {
			str_append_c(query, '?');
		} else if (arg_pos < no_log_count && no_log_fields[arg_pos]) {
			str_append_c(query, '?');
		} else if (arg_pos < need_escaping_count && need_escaping_flags[arg_pos]) {
			const char *escaped;

			/* Escape in a nested data stack frame so the
			   driver's temporary escape buffer is freed
			   immediately. The escaped value is appended to the
			   heap-allocated query before the frame is popped. */
			T_BEGIN {
				if (sql_escape_string(stmt->db, args[arg_pos],
						      &escaped, error_r) < 0)
					escaped = NULL;
				else {
					str_append_c(query, '\'');
					str_append(query, escaped);
					str_append_c(query, '\'');
				}
			} T_END_PASS_STR_IF(escaped == NULL, error_r);
			if (escaped == NULL) {
				str_free(&query);
				return -1;
			}
		} else {
			str_append(query, args[arg_pos]);
		}
		prev = off + 1;
	}
	str_append(query, stmt->query_template + prev);

	if (offset_count != args_count && !tolerant) {
		i_panic("lib-sql: Too many bind args (%u) for statement: %s",
			args_count, stmt->query_template);
	}
	*query_r = t_strdup(str_c(query));
	str_free(&query);
	return 0;
}

const char *sql_statement_get_log_query(struct sql_statement *stmt)
{
	const char *query, *error;
	if (stmt->no_log_expanded_values)
		return stmt->query_template;

	const bool *no_log_fields = NULL;
	unsigned int no_log_count = 0;
	if (array_is_created(&stmt->no_log_fields))
		no_log_fields = array_get(&stmt->no_log_fields, &no_log_count);

	if (sql_statement_build_query(stmt, TRUE, no_log_fields, no_log_count,
				      &query, &error) < 0)
		return stmt->query_template;
	return query;
}

int sql_statement_get_query(struct sql_statement *stmt,
			    const char **query_r, const char **error_r)
{
	return sql_statement_build_query(stmt, FALSE, NULL, 0, query_r, error_r);
}

void default_sql_statement_query(struct sql_statement *stmt,
			    sql_query_callback_t *callback, void *context)
{
	const char *query, *error;
	if (sql_statement_get_query(stmt, &query, &error) < 0) {
		sql_query_callback_delayed(stmt->db,
					   sql_result_new_error(error),
					   callback, context);
		pool_unref(&stmt->pool);
		return;
	}
	sql_query(stmt->db, query, callback, context);
	pool_unref(&stmt->pool);
}

struct sql_result *default_sql_statement_query_s(struct sql_statement *stmt)
{
	const char *query, *error;
	if (sql_statement_get_query(stmt, &query, &error) < 0) {
		struct sql_result *result = sql_result_new_error(error);
		pool_unref(&stmt->pool);
		return result;
	}
	struct sql_result *result = sql_query_s(stmt->db, query);
	pool_unref(&stmt->pool);
	return result;
}

void default_sql_update_stmt(struct sql_transaction_context *ctx,
				    struct sql_statement *stmt,
				    unsigned int *affected_rows)
{
	const char *query, *error;
	if (sql_statement_get_query(stmt, &query, &error) < 0) {
		if (ctx->failed_error == NULL)
			ctx->failed_error = i_strdup(error);
		pool_unref(&stmt->pool);
		return;
	}
	ctx->db->v.update(ctx, query, affected_rows);
	pool_unref(&stmt->pool);
}

struct sql_prepared_statement *
sql_prepared_statement_init(struct sql_db *db, const char *query_template)
{
	struct sql_prepared_statement *stmt;

	stmt = hash_table_lookup(db->prepared_stmt_hash, query_template);
	if (stmt != NULL) {
		stmt->refcount++;
		return stmt;
	}

	if (db->v.prepared_statement_init != NULL)
		stmt = db->v.prepared_statement_init(db, query_template);
	else
		stmt = default_sql_prepared_statement_init(db, query_template);

	hash_table_insert(db->prepared_stmt_hash, stmt->query_template, stmt);
	return stmt;
}

void sql_prepared_statement_unref(struct sql_prepared_statement **_prep_stmt)
{
	struct sql_prepared_statement *prep_stmt = *_prep_stmt;

	if (prep_stmt == NULL)
		return;

	*_prep_stmt = NULL;

	i_assert(prep_stmt->refcount > 0);
	prep_stmt->refcount--;
}

static void
sql_statement_init_fields(struct sql_statement *stmt, struct sql_db *db)
{
	stmt->db = db;
	p_array_init(&stmt->args, stmt->pool, 8);
	p_array_init(&stmt->args_need_escaping, stmt->pool, 8);
	p_array_init(&stmt->placeholders, stmt->pool, 4);

	const char *error;
	if (!sql_template_scan(stmt->query_template, &stmt->placeholders, &error))
		stmt->template_scan_error = p_strdup(stmt->pool, error);
}

struct sql_statement *
sql_statement_init(struct sql_db *db, const char *query_template)
{
	struct sql_statement *stmt;

	if (db->v.statement_init != NULL)
		stmt = db->v.statement_init(db, query_template);
	else {
		pool_t pool = pool_alloconly_create("sql statement", 1024);
		stmt = p_new(pool, struct sql_statement, 1);
		stmt->pool = pool;
	}
	stmt->query_template = p_strdup(stmt->pool, query_template);
	sql_statement_init_fields(stmt, db);
	return stmt;
}

struct sql_statement *
sql_statement_init_prepared(struct sql_prepared_statement *prep_stmt)
{
	struct sql_statement *stmt;

	if (prep_stmt->db->v.statement_init_prepared == NULL)
		return default_sql_statement_init_prepared(prep_stmt);

	/* sql_statement_init_fields() scans the template here too, even
	   though a backend that binds a prepared statement natively (e.g.
	   Cassandra, by index) never reads the resulting offsets: an
	   unparseable construct is still rejected, and stmt->query_template
	   must already be set by the backend's statement_init_prepared for
	   the scan to have anything to scan. */
	stmt = prep_stmt->db->v.statement_init_prepared(prep_stmt);
	sql_statement_init_fields(stmt, prep_stmt->db);
	return stmt;
}

void sql_statement_abort(struct sql_statement **_stmt)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	if (stmt->db->v.statement_abort != NULL)
		stmt->db->v.statement_abort(stmt);
	pool_unref(&stmt->pool);
}

void sql_statement_set_timestamp(struct sql_statement *stmt,
				 const struct timespec *ts)
{
	if (stmt->db->v.statement_set_timestamp != NULL)
		stmt->db->v.statement_set_timestamp(stmt, ts);
}

void sql_statement_set_no_log_expanded_values(struct sql_statement *stmt,
					      bool no_expand)
{
	stmt->no_log_expanded_values = no_expand;

	if (stmt->db->v.statement_set_no_log_expanded_values != NULL) {
		stmt->db->v.statement_set_no_log_expanded_values(stmt,
			no_expand);
	}
}

void sql_statement_set_no_log_expanded_value_field(struct sql_statement *stmt,
						    unsigned int column_idx)
{
	if (!array_is_created(&stmt->no_log_fields))
		p_array_init(&stmt->no_log_fields, stmt->pool, column_idx + 1);
	stmt->no_log_expanded_values = FALSE;
	bool no_log = TRUE;
	array_idx_set(&stmt->no_log_fields, column_idx, &no_log);

	if (stmt->db->v.statement_set_no_log_expanded_value_field != NULL) {
		stmt->db->v.statement_set_no_log_expanded_value_field(stmt,
			column_idx);
	}
}

void sql_statement_bind_str(struct sql_statement *stmt,
			    unsigned int column_idx, const char *value)
{
	const char *value_dup = p_strdup(stmt->pool, value);
	array_idx_set(&stmt->args, column_idx, &value_dup);
	bool needs_escaping = TRUE;
	array_idx_set(&stmt->args_need_escaping, column_idx, &needs_escaping);

	if (stmt->db->v.statement_bind_str != NULL)
		stmt->db->v.statement_bind_str(stmt, column_idx, value);
}

void sql_statement_bind_binary(struct sql_statement *stmt,
			       unsigned int column_idx, const void *value,
			       size_t value_size)
{
	const char *value_str =
		p_strdup_printf(stmt->pool, "%s",
				sql_escape_blob(stmt->db, value, value_size));
	array_idx_set(&stmt->args, column_idx, &value_str);

	if (stmt->db->v.statement_bind_binary != NULL) {
		stmt->db->v.statement_bind_binary(stmt, column_idx,
						  value, value_size);
	}
}

void sql_statement_bind_int64(struct sql_statement *stmt,
			      unsigned int column_idx, int64_t value)
{
	const char *value_str = p_strdup_printf(stmt->pool, "%"PRId64, value);
	array_idx_set(&stmt->args, column_idx, &value_str);

	if (stmt->db->v.statement_bind_int64 != NULL)
		stmt->db->v.statement_bind_int64(stmt, column_idx, value);
}

void sql_statement_bind_double(struct sql_statement *stmt,
			       unsigned int column_idx, double value)
{
	const char *value_str = p_strdup_printf(stmt->pool, "%f", value);
	array_idx_set(&stmt->args, column_idx, &value_str);

	if (stmt->db->v.statement_bind_double != NULL)
		stmt->db->v.statement_bind_double(stmt, column_idx, value);
}

void sql_statement_bind_uuid(struct sql_statement *stmt,
			     unsigned int column_idx, const guid_128_t uuid)
{
	const char *value_str = p_strdup(stmt->pool, guid_128_to_uuid_string(uuid, FORMAT_RECORD));
	array_idx_set(&stmt->args, column_idx, &value_str);

	if (stmt->db->v.statement_bind_uuid != NULL)
		stmt->db->v.statement_bind_uuid(stmt, column_idx, uuid);
}

#undef sql_statement_query
void sql_statement_query(struct sql_statement **_stmt,
			 sql_query_callback_t *callback, void *context)
{
	struct sql_statement *stmt = *_stmt;
	*_stmt = NULL;

	T_BEGIN {
		if (stmt->template_scan_error != NULL) {
			/* An unscannable template must never reach a
			   driver: one that binds natively (mysql, pgsql,
			   sqlite) would execute it without ever consulting
			   stmt->placeholders, and one that renders offsets
			   into the query text (cassandra) would consume the
			   partial offset array the failed scan left behind.
			   Fail via sql_statement_abort(), not a raw
			   pool_unref(): a pooled driver's statement_init()
			   (sqlpool) has already created its own nested
			   per-connection statement, and only the vfunc chain
			   sql_statement_abort() walks knows how to free
			   that too. */
			struct sql_db *db = stmt->db;
			struct sql_result *result =
				sql_result_new_error(stmt->template_scan_error);
			sql_statement_abort(&stmt);
			sql_query_callback_delayed(db, result, callback, context);
		} else if (stmt->db->v.statement_query != NULL)
			stmt->db->v.statement_query(stmt, callback, context);
		else if (stmt->db->v.statement_query_s != NULL) {
			struct sql_db *db = stmt->db;
			struct sql_query_result_delayed *cb =
				i_new(struct sql_query_result_delayed, 1);
			cb->db = db;
			cb->callback = callback;
			cb->context = context;
			cb->result = sql_statement_query_s(&stmt);
			cb->to = timeout_add_short(0, sql_query_delayed_callback, cb);
			DLLIST_PREPEND(&db->query_delayed_list, cb);
		} else
			default_sql_statement_query(stmt, callback, context);
	} T_END;
}

struct sql_result *sql_statement_query_s(struct sql_statement **_stmt)
{
	struct sql_statement *stmt = *_stmt;
	struct sql_result *result;

	*_stmt = NULL;
	T_BEGIN {
		if (stmt->template_scan_error != NULL) {
			result = sql_result_new_error(stmt->template_scan_error);
			sql_statement_abort(&stmt);
		} else if (stmt->db->v.statement_query_s != NULL)
			result = stmt->db->v.statement_query_s(stmt);
		else
			result = default_sql_statement_query_s(stmt);
	} T_END;
	return result;
}

void sql_result_ref(struct sql_result *result)
{
	result->refcount++;
}

void sql_result_unref(struct sql_result *result)
{
	i_assert(result->refcount > 0);
	if (--result->refcount > 0)
		return;

	i_free(result->map);
	result->v.free(result);
}

static const struct sql_field_def *
sql_field_def_find(const struct sql_field_def *fields, const char *name)
{
	unsigned int i;

	for (i = 0; fields[i].name != NULL; i++) {
		if (strcasecmp(fields[i].name, name) == 0)
			return &fields[i];
	}
	return NULL;
}

static void
sql_result_build_map(struct sql_result *result,
		     const struct sql_field_def *fields, size_t dest_size)
{
	const struct sql_field_def *def;
	const char *name;
	unsigned int i, count, field_size = 0;

	count = sql_result_get_fields_count(result);

	result->map_size = count;
	result->map = i_new(struct sql_field_map, result->map_size);
	for (i = 0; i < count; i++) {
		name = sql_result_get_field_name(result, i);
		def = sql_field_def_find(fields, name);
		if (def != NULL) {
			result->map[i].type = def->type;
			result->map[i].offset = def->offset;
			switch (def->type) {
			case SQL_TYPE_STR:
				field_size = sizeof(const char *);
				break;
			case SQL_TYPE_UINT:
				field_size = sizeof(unsigned int);
				break;
			case SQL_TYPE_ULLONG:
				field_size = sizeof(unsigned long long);
				break;
			case SQL_TYPE_BOOL:
				field_size = sizeof(bool);
				break;
			case SQL_TYPE_UUID:
				field_size = GUID_128_SIZE;
				break;
			}
			i_assert(def->offset + field_size <= dest_size);
		} else {
			result->map[i].offset = SIZE_MAX;
		}
	}
}

void sql_result_setup_fetch(struct sql_result *result,
			    const struct sql_field_def *fields,
			    void *dest, size_t dest_size)
{
	if (result->map == NULL)
		sql_result_build_map(result, fields, dest_size);
	result->fetch_dest = dest;
	result->fetch_dest_size = dest_size;
}

static void sql_result_fetch(struct sql_result *result)
{
	unsigned int i, count;
	const char *value;
	void *ptr;

	memset(result->fetch_dest, 0, result->fetch_dest_size);
	count = result->map_size;
	for (i = 0; i < count; i++) {
		if (result->map[i].offset == SIZE_MAX)
			continue;

		value = sql_result_get_field_value(result, i);
		ptr = PTR_OFFSET(result->fetch_dest, result->map[i].offset);

		switch (result->map[i].type) {
		case SQL_TYPE_STR: {
			*((const char **)ptr) = value;
			break;
		}
		case SQL_TYPE_UINT: {
			if (value != NULL &&
			    str_to_uint(value, (unsigned int *)ptr) < 0)
				e_error(result->event,
					"Value not uint: %s", value);
			break;
		}
		case SQL_TYPE_ULLONG: {
			if (value != NULL &&
			    str_to_ullong(value, (unsigned long long *)ptr) < 0)
				e_error(result->event,
					"Value not ullong: %s", value);
			break;
		}
		case SQL_TYPE_BOOL: {
			if (value != NULL && (*value == 't' || *value == '1'))
				*((bool *)ptr) = TRUE;
			break;
		}
		case SQL_TYPE_UUID: {
			if (value != NULL)
				guid_128_from_uuid_string(value, *((guid_128_t *)ptr));
			break;
		}
		}
	}
}

int sql_result_next_row(struct sql_result *result)
{
	int ret;

	if ((ret = result->v.next_row(result)) <= 0)
		return ret;

	if (result->fetch_dest != NULL)
		sql_result_fetch(result);
	return 1;
}

#undef sql_result_more
void sql_result_more(struct sql_result **result,
		     sql_query_callback_t *callback, void *context)
{
	i_assert((*result)->v.more != NULL);

	(*result)->v.more(result, TRUE, callback, context);
}

static void
sql_result_more_sync_callback(struct sql_result *result, void *context)
{
	struct sql_result **dest_result = context;

	*dest_result = result;
}

void sql_result_more_s(struct sql_result **result)
{
	i_assert((*result)->v.more != NULL);

	(*result)->v.more(result, FALSE, sql_result_more_sync_callback, result);
	/* the callback must have been called */
	i_assert(*result != NULL);
}

unsigned int sql_result_get_fields_count(struct sql_result *result)
{
	return result->v.get_fields_count(result);
}

const char *sql_result_get_field_name(struct sql_result *result,
				      unsigned int idx)
{
	return result->v.get_field_name(result, idx);
}

int sql_result_find_field(struct sql_result *result, const char *field_name)
{
	return result->v.find_field(result, field_name);
}

const char *sql_result_get_field_value(struct sql_result *result,
				       unsigned int idx)
{
	return result->v.get_field_value(result, idx);
}

const unsigned char *
sql_result_get_field_value_binary(struct sql_result *result,
				  unsigned int idx, size_t *size_r)
{
	return result->v.get_field_value_binary(result, idx, size_r);
}

const char *sql_result_find_field_value(struct sql_result *result,
					const char *field_name)
{
	return result->v.find_field_value(result, field_name);
}

const char *const *sql_result_get_values(struct sql_result *result)
{
	return result->v.get_values(result);
}

const char *sql_result_get_error(struct sql_result *result)
{
	return result->v.get_error(result);
}

enum sql_result_error_type sql_result_get_error_type(struct sql_result *result)
{
	return result->error_type;
}

static void
sql_result_not_connected_free(struct sql_result *result ATTR_UNUSED)
{
}

static int
sql_result_not_connected_next_row(struct sql_result *result ATTR_UNUSED)
{
	return -1;
}

static const char *
sql_result_not_connected_get_error(struct sql_result *result ATTR_UNUSED)
{
	return SQL_ERRSTR_NOT_CONNECTED;
}

struct sql_transaction_context *sql_transaction_begin(struct sql_db *db)
{
	return db->v.transaction_begin(db);
}

void sql_transaction_set_non_atomic(struct sql_transaction_context *ctx)
{
	ctx->non_atomic = TRUE;
}

static void sql_commit_delayed_callback(struct sql_commit_result_delayed *cb)
{
	struct sql_commit_result result = {
		.error = cb->error,
	};
	timeout_remove(&cb->to);
	DLLIST_REMOVE(&cb->db->commit_delayed_list, cb);
	cb->callback(&result, cb->context);
	i_free(cb->error);
	i_free(cb);
}

static void
sql_commit_schedule_delayed(struct sql_db *db, const char *error,
			    sql_commit_callback_t *callback, void *context)
{
	struct sql_commit_result_delayed *cb = i_new(struct sql_commit_result_delayed, 1);
	cb->db = db;
	cb->error = i_strdup(error);
	cb->callback = callback;
	cb->context = context;
	cb->to = timeout_add_short(0, sql_commit_delayed_callback, cb);
	DLLIST_PREPEND(&db->commit_delayed_list, cb);
}

#undef sql_transaction_commit
void sql_transaction_commit(struct sql_transaction_context **_ctx,
			    sql_commit_callback_t *callback, void *context)
{
	struct sql_transaction_context *ctx = *_ctx;
	struct sql_db *db = ctx->db;
	*_ctx = NULL;

	if (ctx->failed_error != NULL) {
		sql_commit_schedule_delayed(db, ctx->failed_error, callback, context);
		i_free(ctx->failed_error);
		ctx->db->v.transaction_rollback(ctx);
		return;
	}

	if (ctx->db->v.transaction_commit != NULL) {
		ctx->db->v.transaction_commit(ctx, callback, context);
		return;
	}

	const char *error = NULL;
	ctx->db->v.transaction_commit_s(ctx, &error);
	sql_commit_schedule_delayed(db, error, callback, context);
}

int sql_transaction_commit_s(struct sql_transaction_context **_ctx,
			     const char **error_r)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	if (ctx->failed_error != NULL) {
		*error_r = t_strdup(ctx->failed_error);
		i_free(ctx->failed_error);
		ctx->db->v.transaction_rollback(ctx);
		return -1;
	}
	return ctx->db->v.transaction_commit_s(ctx, error_r);
}

void sql_transaction_rollback(struct sql_transaction_context **_ctx)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx->failed_error);
	ctx->db->v.transaction_rollback(ctx);
}

void sql_update(struct sql_transaction_context *ctx, const char *query)
{
	ctx->db->v.update(ctx, query, NULL);
}

void sql_update_stmt(struct sql_transaction_context *ctx,
		     struct sql_statement **_stmt)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	T_BEGIN {
		if (stmt->template_scan_error != NULL) {
			if (ctx->failed_error == NULL)
				ctx->failed_error = i_strdup(stmt->template_scan_error);
			sql_statement_abort(&stmt);
		} else if (ctx->db->v.update_stmt != NULL)
			ctx->db->v.update_stmt(ctx, stmt, NULL);
		else
			default_sql_update_stmt(ctx, stmt, NULL);
	} T_END;
}

void sql_update_get_rows(struct sql_transaction_context *ctx, const char *query,
			 unsigned int *affected_rows)
{
	ctx->db->v.update(ctx, query, affected_rows);
}

void sql_update_stmt_get_rows(struct sql_transaction_context *ctx,
			      struct sql_statement **_stmt,
			      unsigned int *affected_rows)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	T_BEGIN {
		if (stmt->template_scan_error != NULL) {
			if (ctx->failed_error == NULL)
				ctx->failed_error = i_strdup(stmt->template_scan_error);
			sql_statement_abort(&stmt);
		} else if (ctx->db->v.update_stmt != NULL)
			ctx->db->v.update_stmt(ctx, stmt, affected_rows);
		else
			default_sql_update_stmt(ctx, stmt, affected_rows);
	} T_END;
}

void sql_db_set_state(struct sql_db *db, enum sql_db_state state)
{
	enum sql_db_state old_state = db->state;

	if (db->state == state)
		return;

	db->state = state;
	if (db->state_change_callback != NULL) {
		db->state_change_callback(db, old_state,
					  db->state_change_context);
	}
}

static struct sql_transaction_query *
sql_transaction_add(struct sql_transaction_context *ctx, pool_t pool,
		    unsigned int *affected_rows)
{
	struct sql_transaction_query *tquery;

	tquery = p_new(pool, struct sql_transaction_query, 1);
	tquery->trans = ctx;
	tquery->affected_rows = affected_rows;

	if (ctx->head == NULL)
		ctx->head = tquery;
	else
		ctx->tail->next = tquery;
	ctx->tail = tquery;
	return tquery;
}

void sql_transaction_add_query(struct sql_transaction_context *ctx, pool_t pool,
			       const char *query, unsigned int *affected_rows)
{
	struct sql_transaction_query *tquery =
		sql_transaction_add(ctx, pool, affected_rows);
	tquery->query = p_strdup(pool, query);
}

void sql_transaction_add_stmt(struct sql_transaction_context *ctx, pool_t pool,
			      struct sql_statement *stmt,
			      unsigned int *affected_rows)
{
	struct sql_transaction_query *tquery =
		sql_transaction_add(ctx, pool, affected_rows);
	tquery->stmt = stmt;
}

void sql_connection_log_finished(struct sql_db *db)
{
	struct event_passthrough *e = event_create_passthrough(db->event)->
		set_name(SQL_CONNECTION_FINISHED)->
		add_str("name", db->name)->
		add_str("error", db->last_connect_error);
	e_debug(e->event(),
		"Connection finished (queries=%"PRIu64", slow queries=%"PRIu64")",
		db->succeeded_queries + db->failed_queries,
		db->slow_queries);
	i_free(db->last_connect_error);
}

struct event_passthrough *
sql_query_finished_event(struct sql_db *db, struct event *event, const char *query,
			 bool success, int *duration_r)
{
	long long diff;
	struct timeval tv, tv2;
	event_get_create_time(event, &tv);
	i_gettimeofday(&tv2);
	struct event_passthrough *e = event_create_passthrough(event)->
			set_name(SQL_QUERY_FINISHED)->
			add_str("query_first_word", t_strcut(query, ' '));
	diff = timeval_diff_msecs(&tv2, &tv);

	if (!success) {
		db->failed_queries++;
	} else {
		db->succeeded_queries++;
	}

	if (diff >= SQL_SLOW_QUERY_MSEC) {
		e->add_str("slow_query", "y");
		db->slow_queries++;
	}
	i_assert(diff <= INT_MAX);
	*duration_r = (int)diff;

	return e;
}

struct event_passthrough *sql_transaction_finished_event(struct sql_transaction_context *ctx)
{
	return event_create_passthrough(ctx->event)->
		set_name(SQL_TRANSACTION_FINISHED);
}

void sql_wait(struct sql_db *db)
{
	if (db->v.wait != NULL)
		db->v.wait(db);
	sql_call_delayed_callbacks(db);
}


struct sql_result sql_not_connected_result = {
	.v = {
		sql_result_not_connected_free,
		sql_result_not_connected_next_row,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		sql_result_not_connected_get_error,
		NULL,
	},
	.failed_try_retry = TRUE
};
