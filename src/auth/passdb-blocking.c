/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "auth-worker-server.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-blocking.h"

#include <stdlib.h>

static void
auth_worker_reply_parse_args(struct auth_request *request,
			     const char *const *args)
{
	if (**args != '\0')
		request->passdb_password = p_strdup(request->pool, *args);
	args++;

	if (*args != NULL) {
		i_assert(auth_stream_is_empty(request->extra_fields) ||
			 request->master_user != NULL);
		auth_request_set_fields(request, args, NULL);
	}
}

static enum passdb_result
auth_worker_reply_parse(struct auth_request *request, const char *reply)
{
	enum passdb_result ret;
	const char *const *args;

	args = t_strsplit(reply, "\t");

	if (strcmp(*args, "OK") == 0 && args[1] != NULL && args[2] != NULL) {
		/* OK \t user \t password [\t extra] */
		auth_request_set_field(request, "user", args[1], NULL);
		auth_worker_reply_parse_args(request, args + 2);
		return PASSDB_RESULT_OK;
	}

	if (strcmp(*args, "FAIL") == 0 && args[1] != NULL) {
		/* FAIL \t result [\t user \t password [\t extra]] */
		ret = atoi(args[1]);
		if (ret == PASSDB_RESULT_OK) {
			/* shouldn't happen */
		} else if (args[2] == NULL) {
			/* internal failure most likely */
			return ret;
		} else if (args[3] != NULL) {
			auth_request_set_field(request, "user", args[2], NULL);
			auth_worker_reply_parse_args(request, args + 3);
			return ret;
		}
	}

	auth_request_log_error(request, "blocking",
		"Received invalid reply from worker: %s", reply);
	return PASSDB_RESULT_INTERNAL_FAILURE;
}

static void
verify_plain_callback(struct auth_request *request, const char *reply)
{
	enum passdb_result result;

	result = auth_worker_reply_parse(request, reply);
	auth_request_verify_plain_callback(result, request);
}

void passdb_blocking_verify_plain(struct auth_request *request)
{
	string_t *str;

	i_assert(auth_stream_is_empty(request->extra_fields) ||
		 request->master_user != NULL);

	str = t_str_new(64);
	str_printfa(str, "PASSV\t%u\t", request->passdb->id);
	str_append(str, request->mech_password);
	str_append_c(str, '\t');
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), verify_plain_callback);
}

static void
lookup_credentials_callback(struct auth_request *request, const char *reply)
{
	enum passdb_result result;
	const char *password = NULL, *scheme = NULL;

	result = auth_worker_reply_parse(request, reply);
	if (result == PASSDB_RESULT_OK && request->passdb_password != NULL) {
		password = request->passdb_password;
		scheme = password_get_scheme(&password);
		if (scheme == NULL) {
			auth_request_log_error(request, "blocking",
				"Received reply from worker without "
				"password scheme");
			result = PASSDB_RESULT_INTERNAL_FAILURE;
		}
	}

	passdb_handle_credentials(result, password, scheme,
				  auth_request_lookup_credentials_callback,
				  request);
}

void passdb_blocking_lookup_credentials(struct auth_request *request)
{
	string_t *str;

	i_assert(auth_stream_is_empty(request->extra_fields) ||
		 request->master_user != NULL);

	str = t_str_new(64);
	str_printfa(str, "PASSL\t%u\t%s\t",
		    request->passdb->id, request->credentials_scheme);
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), lookup_credentials_callback);
}

static void
set_credentials_callback(struct auth_request *request, const char *reply)
{
	bool success;

	success = strcmp(reply, "OK") == 0 || strncmp(reply, "OK\t", 3) == 0;
	request->private_callback.set_credentials(success, request);
}

void passdb_blocking_set_credentials(struct auth_request *request,
				     const char *new_credentials)
{
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "SETCRED\t%u\t%s\t",
		    request->passdb->id, new_credentials);
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), set_credentials_callback);
}
