/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "auth-worker-connection.h"
#include "userdb.h"
#include "userdb-blocking.h"


struct blocking_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct auth_worker_connection *conn;
	bool next;
	bool destroyed;
};

static bool user_callback(struct auth_worker_connection *conn ATTR_UNUSED,
			  const char *const *args, void *context)
{
	struct auth_request *request = context;
	enum userdb_result result;
	const char *username;

	if (strcmp(args[0], "FAIL") == 0) {
		result = USERDB_RESULT_INTERNAL_FAILURE;
		args++;
	} else if (strcmp(args[0], "NOTFOUND") == 0) {
		result = USERDB_RESULT_USER_UNKNOWN;
		args++;
	} else if (strcmp(args[0], "OK") == 0) {
		result = USERDB_RESULT_OK;
		if (args[1] == NULL) {
			username = "";
			args++;
		} else {
			username = args[1];
			args += 2;
		}

		if (username[0] != '\0' &&
		    strcmp(request->fields.user, username) != 0) {
			auth_request_set_username_forced(request, username);
			request->user_changed_by_lookup = TRUE;
		}
	} else {
		result = USERDB_RESULT_INTERNAL_FAILURE;
		e_error(authdb_event(request),
			"BUG: auth-worker sent invalid user reply");
		args = NULL;
	}

	if (args != NULL && args[0] != NULL && *args[0] != '\0') {
		auth_fields_import_args(request->fields.userdb_reply, args, 0);
		if (auth_fields_exists(request->fields.userdb_reply, "tempfail"))
			request->userdb_lookup_tempfailed = TRUE;
	}

        auth_request_userdb_callback(result, request);
	auth_request_unref(&request);
	return TRUE;
}

void userdb_blocking_lookup(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "USER\t%u\t", request->userdb->userdb->id);
	auth_request_export(request, str);

	auth_request_ref(request);
	auth_worker_call(request->pool, request->fields.user,
			 str_c(str), user_callback, request);
}

static bool iter_callback(struct auth_worker_connection *conn,
			  const char *const *args, void *context)
{
	struct blocking_userdb_iterate_context *ctx = context;

	ctx->conn = conn;
	if (strcmp(args[0], "*") == 0 && args[1] != NULL) {
		if (ctx->destroyed)
			return TRUE;
		ctx->next = FALSE;
		ctx->ctx.callback(args[1], ctx->ctx.context);
		return ctx->next || ctx->destroyed;
	}

	if (strcmp(args[0], "OK") != 0)
		ctx->ctx.failed = TRUE;
	if (!ctx->destroyed)
		ctx->ctx.callback(NULL, ctx->ctx.context);
	auth_request_unref(&ctx->ctx.auth_request);
	return TRUE;
}

struct userdb_iterate_context *
userdb_blocking_iter_init(struct auth_request *request,
			  userdb_iter_callback_t *callback, void *context)
{
	struct blocking_userdb_iterate_context *ctx;
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "LIST\t%u\t", request->userdb->userdb->id);
	auth_request_export(request, str);

	ctx = p_new(request->pool, struct blocking_userdb_iterate_context, 1);
	ctx->ctx.auth_request = request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;

	auth_request_ref(request);
	auth_worker_call(request->pool, "*",
			 str_c(str), iter_callback, ctx);
	return &ctx->ctx;
}

void userdb_blocking_iter_next(struct userdb_iterate_context *_ctx)
{
	struct blocking_userdb_iterate_context *ctx =
		(struct blocking_userdb_iterate_context *)_ctx;

	i_assert(ctx->conn != NULL);

	ctx->next = TRUE;
	auth_worker_connection_resume_input(ctx->conn);
}

int userdb_blocking_iter_deinit(struct userdb_iterate_context **_ctx)
{
	struct blocking_userdb_iterate_context *ctx =
		(struct blocking_userdb_iterate_context *)*_ctx;
	int ret = ctx->ctx.failed ? -1 : 0;

	*_ctx = NULL;

	/* iter_callback() may still be called */
	ctx->destroyed = TRUE;

	if (ctx->conn != NULL)
		auth_worker_connection_resume_input(ctx->conn);
	return ret;
}
