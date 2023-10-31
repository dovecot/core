/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "sasl-server-oauth2.h"
#include "auth-worker-connection.h"
#include "auth-request.h"
#include "db-oauth2.h"
#include "auth-sasl.h"
#include "auth-sasl-oauth2.h"

/*
 * Token verification
 */

static struct db_oauth2 *db_oauth2 = NULL;

struct oauth2_token_lookup {
	struct sasl_server_oauth2_request request;

	struct db_oauth2 *db;
	struct db_oauth2_request db_req;
	lookup_credentials_callback_t *callback;
};

static void
oauth2_verify_finish(enum passdb_result result,
		     struct auth_request *auth_request)
{
	struct sasl_server_req_ctx *srctx = &auth_request->sasl.req;
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
mech_oauth2_verify_token_continue(struct oauth2_token_lookup *lookup,
				  const char *const *args)
{
	struct sasl_server_req_ctx *srctx = lookup->request.rctx;
	struct auth_request *auth_request =
		container_of(srctx, struct auth_request, sasl.req);
	int parsed;
	enum passdb_result result;

	/* OK result user fields */
	if (args[0] == NULL || args[1] == NULL) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(auth_request->event,
			"BUG: Invalid auth worker response: empty");
	} else if (str_to_int(args[1], &parsed) < 0) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(auth_request->event,
			"BUG: Invalid auth worker response: cannot parse '%s'",
			args[1]);
	} else if (args[2] == NULL) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(auth_request->event,
			"BUG: Invalid auth worker response: cannot parse '%s'",
			args[1]);
	} else {
		result = parsed;
	}

	if (result == PASSDB_RESULT_OK) {
		auth_request->passdb_success = TRUE;
		auth_request_set_password_verified(auth_request);
		auth_request_set_fields(auth_request, args + 3, NULL);
		auth_request_lookup_credentials(auth_request, "",
						oauth2_verify_callback);
		auth_request_unref(&auth_request);
		return;
	}

	oauth2_verify_finish(result, auth_request);
	auth_request_unref(&auth_request);
}

static bool
mech_oauth2_verify_token_input_args(
	struct auth_worker_connection *conn ATTR_UNUSED,
	const char *const *args, void *context)
{
	struct oauth2_token_lookup *lookup = context;

	mech_oauth2_verify_token_continue(lookup, args);
	return TRUE;
}

static void
mech_oauth2_verify_token_local_continue(struct db_oauth2_request *db_req,
					enum passdb_result result,
					const char *error,
					struct oauth2_token_lookup *lookup)
{
	struct sasl_server_req_ctx *srctx = lookup->request.rctx;
	struct auth_request *auth_request =
		container_of(srctx, struct auth_request, sasl.req);

	if (result == PASSDB_RESULT_OK) {
		auth_request_set_password_verified(auth_request);
		auth_request_set_field(auth_request, "token",
				       db_req->token, NULL);
		auth_request_lookup_credentials(auth_request, "",
						oauth2_verify_callback);
		auth_request_unref(&auth_request);
		pool_unref(&db_req->pool);
		return;
	} else if (result == PASSDB_RESULT_INTERNAL_FAILURE) {
		e_error(auth_request->event, "oauth2 failed: %s", error);
	} else {
		e_info(auth_request->event, "oauth2 failed: %s", error);
	}
	oauth2_verify_finish(result, auth_request);
	auth_request_unref(&auth_request);
	pool_unref(&db_req->pool);
}

static int
oauth2_auth_new(struct sasl_server_req_ctx *srctx, pool_t pool,
		const char *token, struct sasl_server_oauth2_request **req_r)
{
	struct auth_request *auth_request =
		container_of(srctx, struct auth_request, sasl.req);
	struct oauth2_token_lookup *lookup;

	if (db_oauth2 == NULL) {
		e_error(auth_request->event, "BUG: oauth2 database missing");
		return -1;
	}

	lookup = p_new(pool, struct oauth2_token_lookup, 1);
	sasl_server_oauth2_request_init(&lookup->request, pool, srctx);
	lookup->db_req.pool = pool;
	lookup->db = db_oauth2;

	auth_request_ref(auth_request);
	if (!db_oauth2_use_worker(lookup->db)) {
		pool_t pool = pool_alloconly_create(
			MEMPOOL_GROWING"oauth2 request", 256);
		struct db_oauth2_request *db_req =
			p_new(pool, struct db_oauth2_request, 1);
		db_req->pool = pool;
		db_req->auth_request = auth_request;
		db_oauth2_lookup(
			lookup->db, db_req, token, db_req->auth_request,
			mech_oauth2_verify_token_local_continue, lookup);
	} else {
		string_t *str = t_str_new(128);
		str_append(str, "TOKEN\tOAUTH2\t");
		str_append_tabescaped(str, token);
		str_append_c(str, '\t');
		auth_request_export(auth_request, str);
		auth_worker_call(
			lookup->db_req.pool,
			auth_request->fields.user, str_c(str),
			mech_oauth2_verify_token_input_args, lookup);
	}

	*req_r = &lookup->request;
	return 0;
}

static const struct sasl_server_oauth2_funcs mech_funcs = {
	.auth_new = oauth2_auth_new,
};

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

/*
 * Mechanisms
 */

static void
mech_oauth_init_settings(struct sasl_server_oauth2_settings *oauth2_set)
{
	i_assert(db_oauth2 != NULL);

	i_zero(oauth2_set);
	oauth2_set->openid_configuration_url =
		db_oauth2_get_openid_configuration_url(db_oauth2);
}

static bool
mech_oauthbearer_register(struct sasl_server_instance *sasl_inst,
			  const struct auth_settings *set ATTR_UNUSED)
{
	struct sasl_server_oauth2_settings oauth2_set;

	mech_oauth_init_settings(&oauth2_set);
	sasl_server_mech_register_oauthbearer(sasl_inst, &mech_funcs,
					      &oauth2_set);
	return TRUE;
}

static bool
mech_xoauth2_register(struct sasl_server_instance *sasl_inst,
		      const struct auth_settings *set ATTR_UNUSED)
{
	struct sasl_server_oauth2_settings oauth2_set;

	mech_oauth_init_settings(&oauth2_set);
	sasl_server_mech_register_xoauth2(sasl_inst, &mech_funcs,
					  &oauth2_set);
	return TRUE;
}

static const struct auth_sasl_mech_module mech_oauthbearer = {
	.mech_name = SASL_MECH_NAME_OAUTHBEARER,

	.mech_register = mech_oauthbearer_register,
};

static const struct auth_sasl_mech_module mech_xoauth2 = {
	.mech_name = SASL_MECH_NAME_XOAUTH2,

	.mech_register = mech_xoauth2_register,
};

void auth_sasl_mech_oauth2_register(void)
{
	auth_sasl_mech_register_module(&mech_oauthbearer);
	auth_sasl_mech_register_module(&mech_xoauth2);
}
