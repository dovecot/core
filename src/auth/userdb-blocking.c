/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "auth-worker-server.h"
#include "userdb.h"
#include "userdb-blocking.h"

#include <stdlib.h>

static void user_callback(struct auth_request *request, const char *reply)
{
	if (*reply == '\0')
		reply = NULL;

        request->private_callback.userdb(reply, request);
}

void userdb_blocking_lookup(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "USER\t%u\t", request->userdb->num);
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), user_callback);
}
