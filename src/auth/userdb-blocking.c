/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "auth-worker-server.h"
#include "userdb.h"
#include "userdb-blocking.h"

#include <stdlib.h>

struct blocking_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	pool_t pool;
	struct auth_worker_connection *conn;
	bool next;
	bool destroyed;
};

static bool user_callback(const char *reply, void *context)
{
	struct auth_request *request = context;
	enum userdb_result result;
	const char *args;

	if (strncmp(reply, "FAIL\t", 5) == 0) {
		result = USERDB_RESULT_INTERNAL_FAILURE;
		args = reply + 5;
	} else if (strncmp(reply, "NOTFOUND\t", 9) == 0) {
		result = USERDB_RESULT_USER_UNKNOWN;
		args = reply + 9;
	} else if (strncmp(reply, "OK\t", 3) == 0) {
		result = USERDB_RESULT_OK;
		args = reply + 3;
	} else {
		result = USERDB_RESULT_INTERNAL_FAILURE;
		i_error("BUG: auth-worker sent invalid user reply");
		args = "";
	}

	if (*args != '\0') {
		request->userdb_reply = auth_stream_reply_init(request->pool);
		auth_stream_reply_import(request->userdb_reply, args);
		if (auth_stream_reply_find(request->userdb_reply,
					   "tempfail") != NULL)
			request->userdb_lookup_failed = TRUE;
	}

        auth_request_userdb_callback(result, request);
	auth_request_unref(&request);
	return TRUE;
}

void userdb_blocking_lookup(struct auth_request *request)
{
	struct auth_stream_reply *reply;

	reply = auth_stream_reply_init(pool_datastack_create());
	auth_stream_reply_add(reply, "USER", NULL);
	auth_stream_reply_add(reply, NULL, dec2str(request->userdb->userdb->id));
	auth_request_export(request, reply);

	auth_request_ref(request);
	auth_worker_call(request->pool, reply, user_callback, request);
}

static bool iter_callback(const char *reply, void *context)
{
	struct blocking_userdb_iterate_context *ctx = context;
	pool_t pool = ctx->pool;

	if (strncmp(reply, "*\t", 2) == 0) {
		ctx->next = FALSE;
		ctx->ctx.callback(reply + 2, ctx->ctx.context);
		return ctx->next;
	}

	if (strcmp(reply, "OK") != 0)
		ctx->ctx.failed = TRUE;
	if (!ctx->destroyed)
		ctx->ctx.callback(NULL, ctx->ctx.context);
	pool_unref(&pool);
	return TRUE;
}

struct userdb_iterate_context *
userdb_blocking_iter_init(struct userdb_module *userdb,
			  userdb_iter_callback_t *callback, void *context)
{
	struct blocking_userdb_iterate_context *ctx;
	struct auth_stream_reply *reply;
	pool_t pool;

	reply = auth_stream_reply_init(pool_datastack_create());
	auth_stream_reply_add(reply, "LIST", NULL);
	auth_stream_reply_add(reply, NULL, dec2str(userdb->id));

	pool = pool_alloconly_create("userdb iter", 512);
	ctx = p_new(pool, struct blocking_userdb_iterate_context, 1);
	ctx->ctx.userdb = userdb;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	ctx->pool = pool;

	pool_ref(pool);
	ctx->conn = auth_worker_call(pool, reply, iter_callback, ctx);
	return &ctx->ctx;
}

void userdb_blocking_iter_next(struct userdb_iterate_context *_ctx)
{
	struct blocking_userdb_iterate_context *ctx =
		(struct blocking_userdb_iterate_context *)_ctx;

	ctx->next = TRUE;
	auth_worker_server_resume_input(ctx->conn);
}

int userdb_blocking_iter_deinit(struct userdb_iterate_context **_ctx)
{
	struct blocking_userdb_iterate_context *ctx =
		(struct blocking_userdb_iterate_context *)*_ctx;
	int ret = ctx->ctx.failed ? -1 : 0;

	*_ctx = NULL;

	ctx->destroyed = TRUE;
	pool_unref(&ctx->pool);
	return ret;
}
