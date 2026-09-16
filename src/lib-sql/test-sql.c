/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "settings.h"
#include "test-common.h"
#include "sql-api-private.h"
#include "driver-test.h"

static struct sql_db *setup_sql(void)
{
	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "sqlite",
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	sql_driver_test_register();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	test_assert(sql != NULL && error == NULL);

	test_assert(sql_connect(sql) == 0);
	sql_disconnect(sql);
	settings_simple_deinit(&set);
	return sql;
}

static void deinit_sql(struct sql_db **_sql)
{
	struct sql_db *sql = *_sql;
	if (sql == NULL)
		return;
	*_sql = NULL;

	sql_driver_test_clear_expected_results(sql);
	sql_unref(&sql);

	sql_driver_test_unregister();
	sql_drivers_deinit_without_drivers();
}

#define setup_result_1(sql) \
	struct test_driver_result_set rset_1 = { \
		.rows = 2, \
		.cols = 1, \
		.col_names = (const char *[]){"foo", NULL}, \
		.row_data = (const char **[]){ \
			(const char*[]){"value1", NULL}, \
			(const char*[]){"value2", NULL}, \
		}, \
	}; \
	struct test_driver_result result_1 = { \
		.nqueries = 1, \
		.queries = (const char *[]){"SELECT foo FROM bar"}, \
		.result = &rset_1 \
	}; \
	sql_driver_test_add_expected_result(sql, &result_1);

#define setup_result_2(sql) \
	struct test_driver_result_set rset_2 = { \
		.rows = 2, \
		.cols = 1, \
		.col_names = (const char *[]){"foo", NULL}, \
		.row_data = (const char **[]){ \
			(const char*[]){"value1", NULL}, \
			(const char*[]){"value2", NULL}, \
		}, \
	}; \
	struct test_driver_result result_2 = { \
		.nqueries = 1, \
		.queries = (const char *[]){"SELECT foo FROM bar WHERE baz = 'foz'"}, \
		.result = &rset_2 \
	}; \
	sql_driver_test_add_expected_result(sql, &result_2);


static void test_result_1(struct sql_result *cursor)
{
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value2");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
}

static void test_sql_api(void)
{
	test_begin("sql api");

	struct sql_db *sql = setup_sql();
	setup_result_1(sql);
	struct sql_result *cursor = sql_query_s(sql, "SELECT foo FROM bar");

	test_result_1(cursor);

	sql_result_unref(cursor);

	deinit_sql(&sql);

	test_end();
}

static void test_sql_stmt_api(void)
{
	test_begin("sql statement api");

	struct sql_db *sql = setup_sql();
	setup_result_1(sql);

	struct sql_statement *stmt =
		sql_statement_init(sql, "SELECT foo FROM bar");
	struct sql_result *cursor = sql_statement_query_s(&stmt);

	test_result_1(cursor);

	sql_result_unref(cursor);

	deinit_sql(&sql);
	test_end();
}

static void test_sql_stmt_prepared_api(void)
{
	test_begin("sql prepared statement api");

	struct sql_db *sql = setup_sql();
	setup_result_1(sql);

	struct sql_prepared_statement *prep_stmt =
		sql_prepared_statement_init(sql, "SELECT foo FROM bar");
	struct sql_statement *stmt =
		sql_statement_init_prepared(prep_stmt);
	sql_prepared_statement_unref(&prep_stmt);
	struct sql_result *cursor = sql_statement_query_s(&stmt);

	test_result_1(cursor);

	sql_result_unref(cursor);

	setup_result_2(sql);

	prep_stmt = sql_prepared_statement_init(sql, "SELECT foo FROM bar WHERE baz = ?");
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "foz");
	sql_prepared_statement_unref(&prep_stmt);
	cursor = sql_statement_query_s(&stmt);

	test_result_1(cursor);

	sql_result_unref(cursor);

	deinit_sql(&sql);
	test_end();
}

struct sql_template_scan_case {
	const char *template;
	unsigned int offsets[3];
	unsigned int offset_count;
	/* TRUE if sql_template_scan() is expected to fail on this template
	   instead of returning offsets. */
	bool expect_error;
};

static void test_sql_template_scan(void)
{
	static const struct sql_template_scan_case cases[] = {
		/* baseline */
		{ "SELECT a FROM t WHERE a = ?", { 26 }, 1, FALSE },
		/* a literal '?' inside a quoted string constant is not a
		   placeholder */
		{ "SELECT a FROM t WHERE a = '?'", { 0 }, 0, FALSE },
		{ "SELECT '?'", { 0 }, 0, FALSE },
		{ "SELECT a FROM t WHERE a = 'a?b' AND b = ?", { 40 }, 1, FALSE },
		{ "SELECT a FROM t WHERE a = '?@?'", { 0 }, 0, FALSE },
		{ "SELECT a FROM t WHERE a LIKE '?%'", { 0 }, 0, FALSE },
		/* an arithmetic operator on either side, as used by an
		   atomic increment/decrement */
		{ "UPDATE counters SET value=value+? WHERE class = ? AND name = ?",
		  { 32, 48, 61 }, 3, FALSE },
		{ "UPDATE t SET value=value-? WHERE class = ?", { 25, 41 }, 2, FALSE },
		{ "UPDATE t SET value=value*? WHERE class = ?", { 25, 41 }, 2, FALSE },
		{ "UPDATE t SET value=value/? WHERE class = ?", { 25, 41 }, 2, FALSE },
		{ "UPDATE t SET value=value%? WHERE class = ?", { 25, 41 }, 2, FALSE },
		/* adjacent placeholders, and no delimiter at all */
		{ "SELECT a FROM t WHERE a IN (?,?)", { 28, 30 }, 2, FALSE },
		{ "SELECT a FROM t WHERE a=?AND b=?", { 24, 31 }, 2, FALSE },
		/* statement terminator, and a PostgreSQL cast */
		{ "SELECT a FROM t WHERE a = ?;", { 26 }, 1, FALSE },
		{ "SELECT a FROM t WHERE a = ?::text", { 26 }, 1, FALSE },
		/* newlines around a placeholder */
		{ "SELECT a FROM t WHERE a = ?\nAND b = ?\r\n", { 26, 36 }, 2, FALSE },
		/* a comment is rejected at scan time, not silently skipped -
		   the same policy as a backslash inside a quoted string,
		   since this scanner has no state for a comment body and
		   cannot reliably tell where one ends */
		{ "SELECT a FROM t WHERE a = ? -- trailing ? comment", { 0 }, 0, TRUE },
		{ "SELECT a FROM t WHERE a = ? -- ? comment\nAND b = ?",
		  { 0 }, 0, TRUE },
		/* a block comment, including one abutting a placeholder with
		   no whitespace */
		{ "SELECT a FROM t WHERE a = /* block ? comment */ ?", { 0 }, 0, TRUE },
		{ "SELECT a FROM t WHERE a = ?/* ? */", { 0 }, 0, TRUE },
		{ "SELECT a FROM t WHERE a = ? /* unterminated ? ", { 0 }, 0, TRUE },
		/* '' doubling keeps the string open */
		{ "SELECT a FROM t WHERE a = 'it''s ?' AND b = ?", { 44 }, 1, FALSE },
		/* a backslash inside a '...'-quoted string is refused: a
		   mysql-style escape (backslash escapes the following quote,
		   so the string is 'it's' and the real placeholder is found)
		   and a standard-conforming string (backslash is a literal
		   character, so the string closes right after it, then
		   reopens at the next quote and swallows the real
		   placeholder) disagree on where the placeholder is, not just
		   on the count - the scanner cannot tell them apart. */
		{ "SELECT a FROM t WHERE a = 'it\\'s ?' AND b = ?", { 0 }, 0, TRUE },
		/* a backslash at the end of a string is refused the same way,
		   even though here every dialect agrees on where the string
		   ends: the scanner does not attempt to tell the two cases
		   apart, since doing so would mean teaching it per-dialect
		   escape rules. */
		{ "SELECT a FROM t WHERE a = 'C:\\' AND b = ?", { 0 }, 0, TRUE },
		/* a quoted identifier hides a '?' the same way a string
		   does, in both mysql/sqlite's "..." and mysql's `...`; a
		   backslash there is always literal, so it is not
		   special-cased */
		{ "SELECT \"x?y\" FROM t WHERE a = ?", { 30 }, 1, FALSE },
		{ "SELECT a FROM t WHERE `x?y` = ?", { 30 }, 1, FALSE },
		/* an unterminated string runs to the end */
		{ "SELECT a FROM t WHERE a = ? AND b = 'unterminated ?", { 26 }, 1, FALSE },
		/* PostgreSQL jsonb ?/?|/?& operators are not special-cased:
		   every '?' outside a string is a placeholder */
		{ "SELECT a FROM t WHERE data ? 'key'", { 27 }, 1, FALSE },
		{ "SELECT a FROM t WHERE data ?| ? AND b = ?", { 27, 30, 40 }, 3, FALSE },
		{ "SELECT a FROM t WHERE data ?& array[?]", { 27, 36 }, 2, FALSE },
		/* none, and an empty template */
		{ "SELECT a FROM t", { 0 }, 0, FALSE },
		{ "", { 0 }, 0, FALSE },
		/* a lone placeholder */
		{ "?", { 0 }, 1, FALSE },
		/* an empty string literal, and one containing only a quote */
		{ "SELECT a FROM t WHERE a = '' AND b = ?", { 37 }, 1, FALSE },
		{ "SELECT a FROM t WHERE a = '''' AND b = ?", { 39 }, 1, FALSE },
		/* every unquoted comment introducer and every unquoted
		   dollar-quote open tag is rejected at scan time (see
		   sql_template_scan()'s declaration in sql-api-private.h) -
		   that closes the whole "a phantom placeholder inside the
		   construct pairs with a lost real one past it, at the same
		   total count" class for both, since entering one of these
		   constructs is itself the error, not something this
		   scanner tries to skip past. An unquoted '$' followed by a
		   digit is rejected too, but for an unrelated reason: it is
		   a PostgreSQL positional parameter, not something this
		   scanner miscounts (see the same declaration). A sqlite
		   '[ident]', a PostgreSQL array subscript like 'array[?]'
		   (see above), or a bare '$' that is none of the above, is
		   left unrejected; see the same declaration for why. */
		/* mysql '#' comment */
		{ "a = ? # x ? y", { 0 }, 0, TRUE },
		/* "--" is rejected even without mysql's required trailing
		   whitespace/control character */
		{ "a = ? --x ?", { 0 }, 0, TRUE },
		/* CQL line comment */
		{ "a = ? // x ? y", { 0 }, 0, TRUE },
		/* a block comment, PostgreSQL-nested or not: the scanner
		   rejects at the first "/ *" without looking for a matching
		   close */
		{ "a = ? /* a /* b */ ? */", { 0 }, 0, TRUE },
		/* mysql's executable comment syntax starts with the same
		   "/ *" and is rejected the same way */
		{ "SELECT /*! ? */ ? FROM t", { 0 }, 0, TRUE },
		/* a PostgreSQL dollar-quoted string with no raw quote
		   character in its body: on its own this would only ever
		   overcount (the '?' inside it as an extra phantom, still
		   caught by the placeholder/bind-value count check), but
		   every dollar-quoted string is rejected uniformly, not
		   case by case */
		{ "a = ? AND b = $$x?y$$", { 0 }, 0, TRUE },
		/* a dollar-quoted string whose body contains a raw quote
		   character is the dangerous case this rejection exists
		   for: without it, the stray quote in "y's" would open
		   this scanner's own string tracking, run past the
		   dollar-quoted string's real end, and swallow the real
		   placeholder after "b = " - the same equal-total mismatch
		   as the E-string backslash case */
		{ "a = $$x?y's$$ AND b = ?", { 0 }, 0, TRUE },
		/* the same dangerous case with a non-ASCII byte right
		   before the open tag: this must still reject, since
		   treating that byte as an identifier character (and so the
		   '$' as not a boundary) would let the scanner's own string
		   tracking run past the dollar-quoted string's end the same
		   way and swallow the real placeholder after "b = " */
		{ "a = \xc3\xa1$$x?y's$$ AND b = ?", { 0 }, 0, TRUE },
		/* a bare '$' that isn't a dollar-quote open tag is not
		   rejected - e.g. mysql allows '$' inside an unquoted
		   identifier, and dict-sql splices config-supplied field
		   names into the template */
		{ "SELECT a FROM t WHERE a$b = ?", { 28 }, 1, FALSE },
		/* a dollar-quote open tag with an explicit tag ("$tag$"),
		   not just "$$", is rejected the same way */
		{ "a = ? AND b = $tag$x?y$tag$", { 0 }, 0, TRUE },
		/* a dollar-quote tag may contain non-ASCII letters, since
		   both mysql and PostgreSQL allow them in an unquoted
		   identifier */
		{ "a = ? AND b = $t\xc3\xa1g$x?y$t\xc3\xa1g$", { 0 }, 0, TRUE },
		{ "a = ? AND b = $\xc3\xa1$x?y$\xc3\xa1$", { 0 }, 0, TRUE },
		/* the identifier-boundary check above the '$' is
		   ASCII-only, unlike the tag itself: a non-ASCII byte right
		   before the '$' is not recognized as an identifier
		   character, so this still rejects as a dollar-quote open
		   tag, even though "a$$b" below (an ASCII identifier
		   character before the '$') does not */
		{ "a = ? AND b = \xc3\xa1$$x?y$$", { 0 }, 0, TRUE },
		/* an unquoted '$' followed by a digit is a PostgreSQL
		   positional parameter, not a bind placeholder; mixing it
		   with '?' placeholders in the same query silently binds
		   two different parameters to the same value, so it is
		   rejected outright */
		{ "x = $1 AND y = ?", { 0 }, 0, TRUE },
		/* ... but not when the '$' does not sit at an identifier
		   boundary: mysql's "my$1col" is a single identifier, the
		   '$' just another identifier character */
		{ "my$1col = ?", { 10 }, 1, FALSE },
		/* a "$$"/"$tag$"-shaped run is still just part of an
		   identifier, not a dollar-quote open tag, when it directly
		   follows an identifier character - mysql allows '$'
		   anywhere in an unquoted identifier, including doubled or
		   repeated */
		{ "SELECT a FROM t WHERE a$tag$b = ?", { 32 }, 1, FALSE },
		{ "SELECT a FROM t WHERE a$$b = ?", { 29 }, 1, FALSE },
		/* the same holds at the end of an identifier, with nothing
		   after the "$$" */
		{ "SELECT a FROM t WHERE a$$ = ?", { 28 }, 1, FALSE },
		/* sqlite bracket-quoted identifier: not rejected, since
		   doing so would also reject the real placeholder in the
		   array subscript above, so the '?' inside it still counts
		   as an (extra, phantom) placeholder */
		{ "SELECT [x?y] WHERE a=?", { 9, 21 }, 2, FALSE },
	};

	test_begin("sql template placeholder scan");
	for (unsigned int i = 0; i < N_ELEMENTS(cases); i++) T_BEGIN {
		ARRAY_TYPE(uint) offsets;
		const char *error;

		t_array_init(&offsets, 4);
		bool ok = sql_template_scan(cases[i].template, &offsets, &error);
		test_assert_idx(ok != cases[i].expect_error, i);
		if (!cases[i].expect_error) {
			test_assert_ucmp_idx(array_count(&offsets), ==,
					     cases[i].offset_count, i);
			for (unsigned int j = 0; j < cases[i].offset_count &&
			     j < array_count(&offsets); j++) {
				const unsigned int *off = array_idx(&offsets, j);
				test_assert_ucmp_idx(*off, ==, cases[i].offsets[j], i);
			}
		}
	} T_END;
	test_end();
}

static void test_sql_stmt_unparseable_template(void)
{
	test_begin("sql statement template with an unparseable backslash");

	struct sql_db *sql = setup_sql();
	struct sql_statement *stmt;
	const char *query, *error;

	/* a static E'...' literal containing a backslash-escaped quote,
	   followed by the real bind placeholder - this is what
	   db_sql_build_template() produces from a password_query with such
	   a literal plus one %{variable}. Before the scanner refused this,
	   it miscounted the placeholder inside the E-string as the one real
	   placeholder (matching the single bound value, so no count
	   mismatch was raised) and lost the real one, silently binding the
	   value into the wrong place in the rendered query. */
	stmt = sql_statement_init(sql,
		"SELECT password FROM users WHERE note = E'it\\'s ?' AND b = ?");
	sql_statement_bind_str(stmt, 0, "ALICE");
	test_assert(sql_statement_get_query(stmt, &query, &error) < 0);
	test_assert(error != NULL);
	/* logging must not crash or panic either - it falls back to the
	   raw, unexpanded template */
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT password FROM users WHERE note = E'it\\'s ?' AND b = ?");
	sql_statement_abort(&stmt);

	deinit_sql(&sql);
	test_end();
}

static void test_sql_stmt_literal_question_mark(void)
{
	test_begin("sql statement literal '?' in quoted string");

	struct sql_db *sql = setup_sql();
	struct sql_statement *stmt;

	/* the '?' inside 'a?b' is not a bind placeholder: it must not
	   consume a bound arg, and the real placeholder at the end must
	   still get "bval". */
	stmt = sql_statement_init(sql,
		"SELECT foo FROM bar WHERE foo = 'a?b' AND b = ?");
	sql_statement_bind_str(stmt, 0, "bval");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT foo FROM bar WHERE foo = 'a?b' AND b = 'bval'");
	sql_statement_abort(&stmt);

	/* a PostgreSQL jsonb ?| operator is not special-cased: every '?'
	   outside a quoted string is a real placeholder, so this needs
	   three bound values, not two. */
	stmt = sql_statement_init(sql,
		"SELECT foo FROM bar WHERE data ?| ? AND b = ?");
	sql_statement_bind_str(stmt, 0, "op");
	sql_statement_bind_str(stmt, 1, "arr");
	sql_statement_bind_str(stmt, 2, "bval");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT foo FROM bar WHERE data 'op'| 'arr' AND b = 'bval'");
	sql_statement_abort(&stmt);

	deinit_sql(&sql);
	test_end();
}

static void test_sql_stmt_arithmetic_placeholder(void)
{
	test_begin("sql statement placeholder next to an arithmetic operator");

	struct sql_db *sql = setup_sql();
	struct sql_statement *stmt;

	/* a bind placeholder immediately after an arithmetic operator, as
	   used by an atomic increment ("value = value + ?"), must still be
	   recognized as a real placeholder. */
	stmt = sql_statement_init(sql,
		"UPDATE counters SET value=value+? WHERE class = ? AND name = ?");
	sql_statement_bind_int64(stmt, 0, 5);
	sql_statement_bind_str(stmt, 1, "class1");
	sql_statement_bind_str(stmt, 2, "name1");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "UPDATE counters SET value=value+5 WHERE class = 'class1' AND name = 'name1'");
	sql_statement_abort(&stmt);

	/* '-', '*', '/' and '%' are not whitelisted characters - they are
	   simply not quote or comment syntax, so the scanner recognizes the
	   placeholder next to them the same way. */
	static const struct {
		char op;
	} ops[] = { { '-' }, { '*' }, { '/' }, { '%' } };
	for (unsigned int i = 0; i < N_ELEMENTS(ops); i++) T_BEGIN {
		const char *template = t_strdup_printf(
			"UPDATE t SET value=value%c? WHERE class = ?", ops[i].op);
		const char *expected = t_strdup_printf(
			"UPDATE t SET value=value%c5 WHERE class = 'c1'", ops[i].op);
		stmt = sql_statement_init(sql, template);
		sql_statement_bind_int64(stmt, 0, 5);
		sql_statement_bind_str(stmt, 1, "c1");
		test_assert_strcmp_idx(sql_statement_get_log_query(stmt),
				       expected, i);
		sql_statement_abort(&stmt);
	} T_END;

	deinit_sql(&sql);
	test_end();
}

static void test_sql_stmt_delimiter_free_placeholder(void)
{
	test_begin("sql statement placeholder without a delimiter character");

	struct sql_db *sql = setup_sql();
	struct sql_statement *stmt;

	/* two placeholders directly adjacent to each other */
	stmt = sql_statement_init(sql, "SELECT a FROM t WHERE a IN (?,?)");
	sql_statement_bind_str(stmt, 0, "x");
	sql_statement_bind_str(stmt, 1, "y");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT a FROM t WHERE a IN ('x','y')");
	sql_statement_abort(&stmt);

	/* no delimiter at all around either placeholder */
	stmt = sql_statement_init(sql, "SELECT a FROM t WHERE a=?AND b=?");
	sql_statement_bind_str(stmt, 0, "x");
	sql_statement_bind_str(stmt, 1, "y");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT a FROM t WHERE a='x'AND b='y'");
	sql_statement_abort(&stmt);

	deinit_sql(&sql);
	test_end();
}

static void test_sql_stmt_comment_and_quoted_identifier(void)
{
	test_begin("sql statement placeholder near a comment or quoted identifier");

	struct sql_db *sql = setup_sql();
	struct sql_statement *stmt;
	const char *query, *error;

	/* a comment is rejected at statement init, not silently skipped -
	   sql_statement_get_query() surfaces the scan error instead of
	   building a query from offsets the scanner could not trust */
	stmt = sql_statement_init(sql,
		"SELECT a FROM t WHERE a = ? -- ? comment\nAND b = ?");
	sql_statement_bind_str(stmt, 0, "x");
	sql_statement_bind_str(stmt, 1, "y");
	test_assert(sql_statement_get_query(stmt, &query, &error) < 0);
	test_assert(error != NULL);
	sql_statement_abort(&stmt);

	stmt = sql_statement_init(sql,
		"SELECT a FROM t WHERE a = /* block ? comment */?");
	sql_statement_bind_str(stmt, 0, "x");
	test_assert(sql_statement_get_query(stmt, &query, &error) < 0);
	test_assert(error != NULL);
	sql_statement_abort(&stmt);

	/* a '?' inside a quoted identifier is not a placeholder */
	stmt = sql_statement_init(sql,
		"SELECT \"x?y\" FROM t WHERE a = ?");
	sql_statement_bind_str(stmt, 0, "x");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT \"x?y\" FROM t WHERE a = 'x'");
	sql_statement_abort(&stmt);

	stmt = sql_statement_init(sql,
		"SELECT a FROM t WHERE `x?y` = ?");
	sql_statement_bind_str(stmt, 0, "x");
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "SELECT a FROM t WHERE `x?y` = 'x'");
	sql_statement_abort(&stmt);

	deinit_sql(&sql);
	test_end();
}

int main(void) {
	static void (*const test_functions[])(void) = {
		test_sql_api,
		test_sql_stmt_api,
		test_sql_stmt_prepared_api,
		test_sql_template_scan,
		test_sql_stmt_unparseable_template,
		test_sql_stmt_literal_question_mark,
		test_sql_stmt_arithmetic_placeholder,
		test_sql_stmt_delimiter_free_placeholder,
		test_sql_stmt_comment_and_quoted_identifier,
		NULL
	};
	return test_run(test_functions);
}
