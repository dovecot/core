/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-auth.h"
#include "auth-common.h"

#if defined(PASSDB_SQL) || defined(USERDB_SQL)

#include "auth-request.h"
#include "auth-settings.h"
#include "db-sql.h"
#include "sql-api-private.h"

/* A zeroed struct sql_db has every vfunc but escape_string NULL, which
   sql_statement_init() and friends treat as "use the generic fallback",
   not as a driver to dereference - safe to pass to
   db_sql_create_statement() as long as no actual query ever gets sent
   through it. escape_string is wired up as a trivial passthrough so
   sql_statement_get_log_query() can be exercised on a non-masked bind
   too, without needing a real driver. */
static int
test_db_escape_string(struct sql_db *db ATTR_UNUSED, const char *string,
		      const char **output_r, const char **error_r ATTR_UNUSED)
{
	*output_r = string;
	return 0;
}

static struct sql_db test_db = {
	.v = {
		.escape_string = test_db_escape_string,
	},
};

static struct auth_request test_request = {
	.fields = { .user = "user" },
};

static void test_db_sql_reject(const char *query)
{
	struct sql_statement *stmt = NULL;
	const char *error = NULL;

	/* request may be NULL here: the placeholder check must return
	   before db_sql_create_statement() ever dereferences request. */
	int ret = db_sql_create_statement(&test_db, query, NULL, &stmt, &error);
	test_assert(ret < 0);
	test_assert(stmt == NULL);
	test_assert(error != NULL && strstr(error, "bind placeholder") != NULL);
}

/* A query with no %{variable} at all (e.g. a jsonb operator) still gets
   rejected if it contains a standalone '?' - see
   sql_statement_init_from_var_expand_program()'s comment for why - but
   the error text must not tell the admin to move a %{variable}
   substitution into the concat filter: there is no substitution here
   to move. */
static void test_db_sql_reject_no_variable(const char *query)
{
	struct sql_statement *stmt = NULL;
	const char *error = NULL;

	int ret = db_sql_create_statement(&test_db, query, NULL, &stmt, &error);
	test_assert(ret < 0);
	test_assert(stmt == NULL);
	test_assert(error != NULL && strstr(error, "bind placeholder") != NULL);
	if (error != NULL)
		test_assert(strstr(error, "concat") == NULL);
}

/* A query where a literal '?' is mixed in alongside a real %{variable}
   substitution - the count mismatch must be diagnosed as the literal '?'
   being extra, not as the substitution being embedded in a literal. */
static void test_db_sql_reject_extra_placeholder(const char *query)
{
	struct sql_statement *stmt = NULL;
	const char *error = NULL;

	int ret = db_sql_create_statement(&test_db, query, NULL, &stmt, &error);
	test_assert(ret < 0);
	test_assert(stmt == NULL);
	test_assert(error != NULL && strstr(error, "cannot be mixed with") != NULL);
	if (error != NULL)
		test_assert(strstr(error, "concat filter") == NULL);
}

static void test_db_sql_accept(const char *query, const char *expected_template)
{
	struct sql_statement *stmt = NULL;
	const char *error = NULL;

	int ret = db_sql_create_statement(&test_db, query, &test_request,
					  &stmt, &error);
	test_assert(ret == 0);
	if (ret == 0) {
		test_assert_strcmp(stmt->query_template, expected_template);
		sql_statement_abort(&stmt);
	}
}

/* Builds a statement using the concat filter to join %{variable} with
   other text into a single standalone bind value, and checks that it
   produced exactly one placeholder bound to the expected value. */
static void
test_db_sql_accept_bind(const char *query, struct auth_request *request,
			const char *expected_template,
			const char *expected_bound)
{
	struct sql_statement *stmt = NULL;
	const char *error = NULL;

	int ret = db_sql_create_statement(&test_db, query, request,
					  &stmt, &error);
	test_assert(ret == 0);
	if (ret == 0) {
		test_assert_strcmp(stmt->query_template, expected_template);
		test_assert_ucmp(array_count(&stmt->args), ==, 1);
		test_assert_strcmp(array_idx_elem(&stmt->args, 0),
				   expected_bound);
		sql_statement_abort(&stmt);
	}
}

void test_db_sql(void)
{
	test_begin(
		"db_sql_create_statement rejects non-standalone placeholders");

	/* %{variable} concatenated with other text inside a quoted SQL
	   string literal - the quote-stripping compat rule only strips a
	   quote pair that surrounds a single %{variable}, so these still
	   contain the literal '@'/'%' character next to the variable's
	   quotes, and the resulting '?' stays trapped inside the string. */
	test_db_sql_reject(
		"SELECT id FROM users WHERE addr = '%{user}@%{domain}'");
	test_db_sql_reject(
		"SELECT id FROM users WHERE addr LIKE '%{user}%'");
	test_db_sql_reject(
		"SELECT id FROM users WHERE u = 'x'%{user}'");
	test_db_sql_reject(
		"SELECT id FROM users WHERE u = '%{a}''%{b}'");
	/* the quote-stripping compat rule only strips single quotes - a
	   double-quoted %{variable} is left as-is, still embedded in a
	   string literal, and rejected the same way. */
	test_db_sql_reject(
		"SELECT id FROM users WHERE u = \"%{user}\"");
	/* a "--" comment is rejected outright, regardless of what it
	   contains - not because the %{variable} inside it would fail to
	   reach the database as a placeholder */
	test_db_sql_reject("SELECT '?' -- %{user}");

	/* a pre-existing literal '?' unrelated to any %{variable} must
	   still be rejected, not just the new cases above - and diagnosed
	   as a literal '?' next to a real substitution, not as the
	   substitution itself being embedded in a literal. */
	test_db_sql_reject_extra_placeholder(
		"SELECT id FROM users WHERE d ? 'k' AND u='%{user}'");

	/* no %{variable} anywhere, but a jsonb-style operator makes the
	   query still contain a standalone placeholder - must still be
	   rejected, with an error that talks about neither %{variable} nor
	   the concat filter. A literal '?' with nothing else in the query,
	   e.g. "SELECT '?'", is valid SQL with no bind values at all and
	   is not rejected. */
	test_db_sql_reject_no_variable(
		"SELECT id FROM users WHERE data ? 'key'");

	/* a standalone substitution must pass the placeholder check and
	   reach the (request-dependent) expansion step instead. */
	test_db_sql_accept("SELECT id FROM users WHERE addr = %{user}",
			   "SELECT id FROM users WHERE addr = ?");
	/* the legacy '%{var}' form strips its surrounding quotes */
	test_db_sql_accept("SELECT id FROM users WHERE u = '%{user}'",
			   "SELECT id FROM users WHERE u = ?");
	test_db_sql_accept(
		"SELECT id FROM users WHERE u = '%{user}' AND n = 'it''s'",
		"SELECT id FROM users WHERE u = ? AND n = 'it''s'");
	/* a literal '?' with no substitutions is valid SQL, not an error */
	test_db_sql_accept("SELECT '?'", "SELECT '?'");
	/* an arithmetic operator next to the placeholder is fine */
	test_db_sql_accept("UPDATE t SET value = value - %{user}",
			   "UPDATE t SET value = value - ?");

	/* the concat filter joins %{variable} with other text into a
	   single standalone bind value, so the whole pipeline is one
	   %{...} substitution and still binds as exactly one placeholder. */
	struct auth_request bind_request = {
		.fields = { .user = "joe@foo.org" },
	};
	test_db_sql_accept_bind(
		"SELECT password FROM users "
		"WHERE userid = %{user | username | concat('@example.com')}",
		&bind_request,
		"SELECT password FROM users WHERE userid = ?",
		"joe@example.com");
	test_db_sql_accept_bind(
		"SELECT id FROM users WHERE userid LIKE %{user | concat('%')}",
		&bind_request,
		"SELECT id FROM users WHERE userid LIKE ?",
		"joe@foo.org%");

	/* %{password} used as a filter argument, not as the top-level
	   variable, must still be recognized and masked in the logged
	   query - while a second, unrelated bind in the same statement is
	   still logged expanded, proving the masking is per-bind, not
	   per-statement. */
	static const struct auth_settings password_request_settings;
	struct auth_request password_request = {
		.fields = { .user = "user" },
		.mech_password = "secret",
		.set = &password_request_settings,
	};
	struct sql_statement *masked_stmt = NULL;
	const char *masked_error = NULL;
	int masked_ret = db_sql_create_statement(
		&test_db,
		"SELECT * FROM users WHERE name = %{user} "
		"AND token = %{user | concat(password)}",
		&password_request, &masked_stmt, &masked_error);
	test_assert(masked_ret == 0);
	if (masked_ret == 0) {
		test_assert_strcmp(
			sql_statement_get_log_query(masked_stmt),
			"SELECT * FROM users WHERE name = 'user' "
			"AND token = ?");
		sql_statement_abort(&masked_stmt);
	}

	test_end();
}

#else
void test_db_sql(void)
{
}
#endif
