/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "auth-worker-server.h"
#include "userdb.h"
#include "userdb-blocking.h"

#include <stdlib.h>

static void user_callback(struct auth_request *request, const char *reply)
{
	struct auth_stream_reply *stream_reply = NULL;
	enum userdb_result result;

	if (strncmp(reply, "FAIL\t", 5) == 0)
		result = USERDB_RESULT_INTERNAL_FAILURE;
	else if (strncmp(reply, "NOTFOUND\t", 9) == 0)
		result = USERDB_RESULT_USER_UNKNOWN;
	else if (strncmp(reply, "OK\t", 3) == 0) {
		result = USERDB_RESULT_OK;
		stream_reply = auth_stream_reply_init(request);
		auth_stream_reply_import(stream_reply, reply);
	} else {
		result = USERDB_RESULT_INTERNAL_FAILURE;
		i_error("BUG: auth-worker sent invalid user reply");
	}

        auth_request_userdb_callback(result, stream_reply, request);
}

void userdb_blocking_lookup(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "USER\t%u\t", request->userdb->num);
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), user_callback);
}
