/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "auth-common.h"

#if defined(PASSDB_SQL) || defined(USERDB_SQL)

#include "auth-request.h"
#include "auth-worker-server.h"
#include "db-sql.h"
#include "str.h"
#include "var-expand.h"

void db_sql_connect(struct sql_db *db)
{
	if (sql_connect(db) < 0 && worker) {
		/* auth worker's sql connection failed. we can't do anything
		   useful until the connection works. there's no point in
		   having tons of worker processes all logging failures,
		   so tell the auth master to stop creating new workers (and
		   maybe close old ones). this handling is especially useful if
		   we reach the max. number of connections for sql server. */
		auth_worker_server_send_error();
	}
}

static int
db_sql_create_statement_int(struct sql_db *db,
			    const struct var_expand_program *program,
			    struct auth_request *request,
			    struct sql_statement **stmt_r, const char **error_r)
{
	ARRAY_TYPE(const_expansion_program) parts;
	struct sql_statement *stmt = sql_statement_init_from_var_expand_program(
		db, program, &parts, error_r);
	if (stmt == NULL)
		return -1;
	/* Hand the statement out as soon as it exists, so the caller can
	   abort it on any later failure in this function. */
	*stmt_r = stmt;

	const struct var_expand_params params = {
		.table = auth_request_get_var_expand_table(request),
		.providers = auth_request_var_expand_providers,
		.context = request,
	};
	const struct var_expand_program *p;
	string_t *dest = t_str_new(32);
	unsigned int idx = 0;
	ARRAY(unsigned int) password_idxs;
	t_array_init(&password_idxs, 1);
	array_foreach_elem(&parts, p) {
		str_truncate(dest, 0);
		if (var_expand_program_execute_one(
			dest, p, &params, error_r) < 0)
			return -1;
		sql_statement_bind_str(stmt, idx, str_c(dest));
		if (var_expand_program_has_variable(p, "password", TRUE))
			array_push_back(&password_idxs, &idx);
		idx++;
	}

	/* A query that binds %{password} - whether it's a passdb or a
	   userdb query - hides just that bind value in the logged query,
	   leaving the rest (e.g. the username) expanded, unless
	   auth_debug_passwords asked for the password to be shown too. A
	   query with no %{password} bind never touches request->set here. */
	if (array_count(&password_idxs) == 0)
		return 0;
	if (request->set->debug_passwords)
		return 0;
	const unsigned int *pw_idx;
	array_foreach(&password_idxs, pw_idx) {
		sql_statement_set_no_log_expanded_value_field(stmt, *pw_idx);
	}
	return 0;
}

int db_sql_create_statement(struct sql_db *db, const char *query,
			    struct auth_request *request,
			    struct sql_statement **stmt_r, const char **error_r)
{
	struct var_expand_program *program;
	if (var_expand_program_create(query, &program, error_r) < 0)
		return -1;

	/* parts, dest and password_idxs inside the helper are allocated on
	   the data stack and freed with the frame instead of lingering until
	   the ioloop resets. error_r may end up t-allocated too, so it is
	   rescued out with T_END_PASS_STR_IF; the statement itself is never
	   data-stack allocated. */
	*stmt_r = NULL;
	int ret;
	T_BEGIN {
		ret = db_sql_create_statement_int(db, program, request,
						  stmt_r, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	var_expand_program_free(&program);

	if (ret < 0) {
		if (*stmt_r != NULL)
			sql_statement_abort(stmt_r);
		return -1;
	}
	return 0;
}

void db_sql_success(void)
{
	if (worker)
		auth_worker_server_send_success();
}

#endif
