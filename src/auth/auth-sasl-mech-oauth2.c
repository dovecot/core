/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "auth-sasl.h"
#include "auth-sasl-oauth2.h"
#include "auth-request.h"

#include "auth-sasl-oauth2.h"

static void
oauth2_verify_finish(enum passdb_result result,
		     struct auth_request *auth_request)
{
	struct sasl_server_req_ctx *srctx = &auth_request->sasl.req;
	struct sasl_server_mech_request *request =
		sasl_server_request_get_mech_request(srctx);
	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, request);
	struct sasl_server_oauth2_failure failure;

	i_zero(&failure);

	switch (result) {
	case PASSDB_RESULT_INTERNAL_FAILURE:
		sasl_server_oauth2_request_fail(srctx, NULL);
		return;
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		/* user is explicitly disabled, don't allow it to log in */
		failure.status = "insufficient_scope";
		break;
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_PASSWORD_MISMATCH:
		failure.status = "invalid_token";
		break;
	case PASSDB_RESULT_NEXT:
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
	case PASSDB_RESULT_OK:
		/* sending success */
		sasl_server_oauth2_request_succeed(srctx);
		return;
	default:
		i_unreached();
	}

	if (oauth2_req->db != NULL) {
		failure.openid_configuration =
			db_oauth2_get_openid_configuration_url(oauth2_req->db);
	}
	sasl_server_oauth2_request_fail(srctx, &failure);
}

static void
oauth2_verify_callback(enum passdb_result result,
		       const unsigned char *credentials ATTR_UNUSED,
		       size_t size ATTR_UNUSED,
		       struct auth_request *auth_request)
{
	if (result == PASSDB_RESULT_USER_UNKNOWN)
		result = PASSDB_RESULT_OK;
	oauth2_verify_finish(result, auth_request);
}

static void
mech_oauth2_verify_token_continue(struct oauth2_auth_request *oauth2_req,
				  const char *const *args)
{
	struct auth_request *request = oauth2_req->request.request;
	int parsed;
	enum passdb_result result;

	/* OK result user fields */
	if (args[0] == NULL || args[1] == NULL) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(request->event,
			"BUG: Invalid auth worker response: empty");
	} else if (str_to_int(args[1], &parsed) < 0) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(request->event,
			"BUG: Invalid auth worker response: cannot parse '%s'",
			args[1]);
	} else if (args[2] == NULL) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(request->event,
			"BUG: Invalid auth worker response: cannot parse '%s'",
			args[1]);
	} else {
		result = parsed;
	}

	if (result == PASSDB_RESULT_OK) {
		request->passdb_success = TRUE;
		auth_request_set_password_verified(request);
		auth_request_set_fields(request, args + 3, NULL);
		auth_request_lookup_credentials(request, "",
						oauth2_verify_callback);
		auth_request_unref(&request);
		return;
	}

	oauth2_verify_finish(result, request);
	auth_request_unref(&request);
}

static bool
mech_oauth2_verify_token_input_args(
	struct auth_worker_connection *conn ATTR_UNUSED,
	const char *const *args, void *context)
{
	struct oauth2_auth_request *oauth2_req = context;

	mech_oauth2_verify_token_continue(oauth2_req, args);
	return TRUE;
}

static void
mech_oauth2_verify_token_local_continue(struct db_oauth2_request *db_req,
					enum passdb_result result,
					const char *error,
					struct oauth2_auth_request *oauth2_req)
{
	struct auth_request *request = oauth2_req->request.request;

	if (result == PASSDB_RESULT_OK) {
		auth_request_set_password_verified(request);
		auth_request_set_field(request, "token", db_req->token, NULL);
		auth_request_lookup_credentials(request, "",
						oauth2_verify_callback);
		auth_request_unref(&request);
		pool_unref(&db_req->pool);
		return;
	} else if (result == PASSDB_RESULT_INTERNAL_FAILURE) {
		e_error(request->event, "oauth2 failed: %s", error);
	} else {
		e_info(request->event, "oauth2 failed: %s", error);
	}
	oauth2_verify_finish(result, request);
	auth_request_unref(&request);
	pool_unref(&db_req->pool);
}

static void
auth_sasl_oauth2_verify_token(struct oauth2_auth_request *oauth2_req,
			      const char *token)
{
	struct auth_request *auth_request = oauth2_req->request.request;

	auth_request_ref(auth_request);
	if (!db_oauth2_use_worker(oauth2_req->db)) {
		pool_t pool = pool_alloconly_create(
			MEMPOOL_GROWING"oauth2 request", 256);
		struct db_oauth2_request *db_req =
			p_new(pool, struct db_oauth2_request, 1);
		db_req->pool = pool;
		db_req->auth_request = auth_request;
		db_oauth2_lookup(
			oauth2_req->db, db_req, token,	db_req->auth_request,
			mech_oauth2_verify_token_local_continue, oauth2_req);
	} else {
		string_t *str = t_str_new(128);
		str_append(str, "TOKEN\tOAUTH2\t");
		str_append_tabescaped(str, token);
		str_append_c(str, '\t');
		auth_request_export(auth_request, str);
		auth_worker_call(
			oauth2_req->db_req.pool,
			auth_request->fields.user, str_c(str),
			mech_oauth2_verify_token_input_args, oauth2_req);
	}
}

void auth_sasl_oauth2_initialize(void)
{
	const char *mech, *error;
	array_foreach_elem(&global_auth_settings->mechanisms, mech) {
		if (strcasecmp(mech, SASL_MECH_NAME_OAUTHBEARER) == 0 ||
		    strcasecmp(mech, SASL_MECH_NAME_XOAUTH2) == 0) {
			if (db_oauth2_init(auth_event, FALSE,
					   &db_oauth2, &error) < 0)
				i_fatal("Cannot initialize oauth2: %s", error);
		}
	}
}
