/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "auth-worker-connection.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-blocking.h"


static void
auth_worker_reply_parse_args(struct auth_request *request,
			     const char *const *args)
{
	if (**args != '\0')
		request->passdb_password = p_strdup(request->pool, *args);
	args++;

	if (*args != NULL)
		auth_request_set_fields(request, args, NULL);
}

enum passdb_result
passdb_blocking_auth_worker_reply_parse(struct auth_request *request,
					const char *const *args)
{
	enum passdb_result ret;

	if (strcmp(*args, "OK") == 0 && args[1] != NULL && args[2] != NULL) {
		/* OK \t user \t password [\t extra] */
		if (args[1][0] != '\0')
			auth_request_set_field(request, "user", args[1], NULL);
		auth_worker_reply_parse_args(request, args + 2);
		return PASSDB_RESULT_OK;
	}

	if (strcmp(*args, "NEXT") == 0 && args[1] != NULL) {
		/* NEXT \t user [\t extra] */
		if (args[1][0] != '\0')
			auth_request_set_field(request, "user", args[1], NULL);
		auth_worker_reply_parse_args(request, args + 1);
		return PASSDB_RESULT_NEXT;
	}

	if (strcmp(*args, "FAIL") == 0 && args[1] != NULL) {
		int result;
		/* FAIL \t result [\t user \t password [\t extra]] */
		if (str_to_int(args[1], &result) < 0) {
			/* shouldn't happen */
		} else {
			ret = (enum passdb_result)result;
			if (ret == PASSDB_RESULT_OK) {
				/* shouldn't happen */
			} else if (args[2] == NULL) {
				/* internal failure most likely */
				return ret;
			} else if (args[3] != NULL) {
				if (*args[2] != '\0') {
					auth_request_set_field(request, "user",
							       args[2], NULL);
				}
				auth_worker_reply_parse_args(request, args + 3);
				return ret;
			}
		}
	}

	e_error(authdb_event(request), "Received invalid reply from worker: %s",
		t_strarray_join(args, "\t"));
	return PASSDB_RESULT_INTERNAL_FAILURE;
}

static bool
verify_plain_callback(struct auth_worker_connection *conn ATTR_UNUSED,
		      const char *const *args, void *context)
{
	struct auth_request *request = context;
	enum passdb_result result;

	result = passdb_blocking_auth_worker_reply_parse(request, args);
	auth_request_verify_plain_callback(result, request);
	auth_request_unref(&request);
	return TRUE;
}

void passdb_blocking_verify_plain(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "PASSV\t%u\t", request->passdb->passdb->id);
	str_append_tabescaped(str, request->mech_password);
	str_append_c(str, '\t');
	auth_request_export(request, str);

	auth_request_ref(request);
	auth_worker_call(request->pool, request->fields.user, str_c(str),
			 verify_plain_callback, request);
}

static bool
lookup_credentials_callback(struct auth_worker_connection *conn ATTR_UNUSED,
			    const char *const *args, void *context)
{
	struct auth_request *request = context;
	enum passdb_result result;
	const char *password = NULL, *scheme = NULL;

	result = passdb_blocking_auth_worker_reply_parse(request, args);
	if (result == PASSDB_RESULT_OK && request->passdb_password != NULL) {
		password = request->passdb_password;
		scheme = password_get_scheme(&password);
		if (scheme == NULL) {
			e_error(authdb_event(request),
				"Received reply from worker without "
				"password scheme");
			result = PASSDB_RESULT_INTERNAL_FAILURE;
		}
	}

	passdb_handle_credentials(result, password, scheme,
				  auth_request_lookup_credentials_callback,
				  request);
	auth_request_unref(&request);
	return TRUE;
}

void passdb_blocking_lookup_credentials(struct auth_request *request)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "PASSL\t%u\t", request->passdb->passdb->id);
	str_append_tabescaped(str, request->wanted_credentials_scheme);
	str_append_c(str, '\t');
	auth_request_export(request, str);

	auth_request_ref(request);
	auth_worker_call(request->pool, request->fields.user, str_c(str),
			 lookup_credentials_callback, request);
}

static bool
set_credentials_callback(struct auth_worker_connection *conn ATTR_UNUSED,
			 const char *const *args, void *context)
{
	struct auth_request *request = context;
	bool success;

	success = strcmp(args[0], "OK") == 0;
	request->private_callback.set_credentials(success, request);
	auth_request_unref(&request);
	return TRUE;
}

void passdb_blocking_set_credentials(struct auth_request *request,
				     const char *new_credentials)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "SETCRED\t%u\t", request->passdb->passdb->id);
	str_append_tabescaped(str, new_credentials);
	str_append_c(str, '\t');
	auth_request_export(request, str);

	auth_request_ref(request);
	auth_worker_call(request->pool, request->fields.user, str_c(str),
			 set_credentials_callback, request);
}
