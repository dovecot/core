/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "auth-worker-server.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-blocking.h"

#include <stdlib.h>

static enum passdb_result
check_failure(struct auth_request *request, const char **reply)
{
	/* OK / FAIL */
	if (strncmp(*reply, "OK\t", 3) == 0) {
		*reply += 3;
		return PASSDB_RESULT_OK;
	}

	/* FAIL \t result */
	if (strncmp(*reply, "FAIL\t", 5) != 0) {
		auth_request_log_error(request, "blocking",
			"Received unknown reply from worker: %s", *reply);
		return PASSDB_RESULT_INTERNAL_FAILURE;
	} else {
		return atoi(*reply + 5);
	}
}

static int get_pass_reply(struct auth_request *request, const char *reply,
			  const char **password_r, const char **scheme_r)
{
	const char *p;

	p = strchr(reply, '\t');
	if (p == NULL) {
		*password_r = NULL;
		*scheme_r = NULL;
		return 0;
	}

	*password_r = t_strdup_until(reply, p);
	reply = p + 1;

	if (**password_r == '\0') {
		*password_r = NULL;
		*scheme_r = NULL;
	} else {
		request->passdb_password =
			p_strdup(request->pool, *password_r);

		*scheme_r = password_get_scheme(password_r);
		if (*scheme_r == NULL) {
			auth_request_log_error(request, "blocking",
				"Received reply from worker without "
				"password scheme");
			return -1;
		}
	}

	if (*reply != '\0') {
		i_assert(request->extra_fields == NULL);

		request->extra_fields = str_new(request->pool, 128);
		str_append(request->extra_fields, reply);
	}
	return 0;
}

static void
verify_plain_callback(struct auth_request *request, const char *reply)
{
	enum passdb_result result;
	const char *password, *scheme;

	result = check_failure(request, &reply);
	if (result >= 0) {
		if (get_pass_reply(request, reply, &password, &scheme) < 0)
			result = PASSDB_RESULT_INTERNAL_FAILURE;
	}

	auth_request_verify_plain_callback(result, request);
}

void passdb_blocking_verify_plain(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(64);
	str_append(str, "PASSV\t");
	str_append(str, request->mech_password);
	str_append_c(str, '\t');
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), verify_plain_callback);
}

static void
lookup_credentials_callback(struct auth_request *request, const char *reply)
{
	enum passdb_result result;
	const char *password, *scheme;

	result = check_failure(request, &reply);
	if (result >= 0) {
		if (get_pass_reply(request, reply, &password, &scheme) < 0)
			result = PASSDB_RESULT_INTERNAL_FAILURE;
	}

	passdb_handle_credentials(result, request->credentials,
				  password, scheme,
				  auth_request_lookup_credentials_callback,
				  request);
}

void passdb_blocking_lookup_credentials(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "PASSL\t%d\t", request->credentials);
	auth_request_export(request, str);

	auth_worker_call(request, str_c(str), lookup_credentials_callback);
}
