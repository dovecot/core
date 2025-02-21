/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "auth-fields.h"
#include "auth-worker-connection.h"
#include "ioloop.h"
#include "str.h"
#include "strescape.h"
#include "json-ostream.h"
#include "mech.h"
#include "passdb.h"
#include "auth-gs2.h"
#include "db-oauth2.h"
#include "oauth2.h"

struct oauth2_auth_request {
	struct auth_request auth;
	struct db_oauth2 *db;
	struct db_oauth2_request db_req;
	lookup_credentials_callback_t *callback;
	bool failed:1;
};

static struct db_oauth2 *db_oauth2 = NULL;

static void
oauth2_fail(struct oauth2_auth_request *oauth2_req, const char *status)
{
	struct auth_request *request = &oauth2_req->auth;
	const char *oidc_url = (oauth2_req->db == NULL ? "" :
		db_oauth2_get_openid_configuration_url(oauth2_req->db));
	string_t *reply = t_str_new(256);
	struct json_ostream *joutput = json_ostream_create_str(reply, 0);

	json_ostream_ndescend_object(joutput, NULL);
	if (strcmp(request->mech->mech_name, "XOAUTH2") == 0) {
		if (strcmp(status, "invalid_token") == 0)
			json_ostream_nwrite_string(joutput, "status", "401");
		else if (strcmp(status, "insufficient_scope") == 0)
			json_ostream_nwrite_string(joutput, "status", "403");
		else
			json_ostream_nwrite_string(joutput, "status", "400");
		json_ostream_nwrite_string(joutput, "schemes", "bearer");
	} else {
		i_assert(strcmp(request->mech->mech_name, "OAUTHBEARER") == 0);
		json_ostream_nwrite_string(joutput, "status", status);
	}
	json_ostream_nwrite_string(joutput, "scope", "mail");
	if (*oidc_url != '\0') {
		json_ostream_nwrite_string(
			joutput, "openid-configuration", oidc_url);
	}
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);

	oauth2_req->failed = TRUE;
	auth_request_fail_with_reply(request, str_data(reply), str_len(reply));
}

static void oauth2_fail_invalid_request(struct oauth2_auth_request *oauth2_req)
{
	oauth2_fail(oauth2_req, "invalid_request");
}

static void oauth2_fail_invalid_token(struct oauth2_auth_request *oauth2_req)
{
	oauth2_fail(oauth2_req, "invalid_token");
}

static void
oauth2_verify_callback(enum passdb_result result,
		       const unsigned char *credentials ATTR_UNUSED,
		       size_t size ATTR_UNUSED, struct auth_request *request)
{
	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, auth);

	switch (result) {
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(request);
		break;
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		/* user is explicitly disabled, don't allow it to log in */
		oauth2_fail(oauth2_req, "insufficient_scope");
		break;
	case PASSDB_RESULT_PASSWORD_MISMATCH:
		oauth2_fail(oauth2_req, "invalid_token");
		break;
	case PASSDB_RESULT_NEXT:
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_OK:
		/* sending success */
		auth_request_success(request, "", 0);
		break;
	default:
		i_unreached();
	}
}

static void
mech_oauth2_verify_token_continue(struct oauth2_auth_request *oauth2_req,
				  const char *const *args)
{
	struct auth_request *request = &oauth2_req->auth;
	int parsed;
	enum passdb_result result;

	/* OK result user fields */
	if (args[0] == NULL || args[1] == NULL) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(request->mech_event,
			"BUG: Invalid auth worker response: empty");
	} else if (str_to_int(args[1], &parsed) < 0) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(request->mech_event,
			"BUG: Invalid auth worker response: cannot parse '%s'",
			args[1]);
	} else if (args[2] == NULL) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		e_error(request->mech_event,
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

	oauth2_verify_callback(result, uchar_empty_ptr, 0, request);
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
	struct auth_request *request = &oauth2_req->auth;

	if (result == PASSDB_RESULT_OK) {
		auth_request_set_password_verified(request);
		auth_request_set_field(request, "token", db_req->token, NULL);
		auth_request_lookup_credentials(request, "",
						oauth2_verify_callback);
		auth_request_unref(&request);
		pool_unref(&db_req->pool);
		return;
	} else if (result == PASSDB_RESULT_INTERNAL_FAILURE) {
		e_error(request->mech_event, "oauth2 failed: %s", error);
	} else {
		e_info(request->mech_event, "oauth2 failed: %s", error);
	}
	oauth2_verify_callback(result, uchar_empty_ptr, 0, request);
	auth_request_unref(&request);
	pool_unref(&db_req->pool);
}

static void
mech_oauth2_verify_token(struct oauth2_auth_request *oauth2_req,
			 const char *token)
{
	struct auth_request *auth_request = &oauth2_req->auth;

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

/* Input syntax for data:
 gs2flag,a=username,^Afield=...^Afield=...^Aauth=Bearer token^A^A
*/
static void
mech_oauthbearer_auth_continue(struct auth_request *request,
			       const unsigned char *data,
			       size_t data_size)
{
	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, auth);

	if (oauth2_req->db == NULL) {
		e_error(request->event, "BUG: oauth2 database missing");
		auth_request_internal_failure(request);
		return;
	}
	if (data_size == 0) {
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}

	struct auth_gs2_header gs2_header;
	const unsigned char *gs2_header_end;
	const char *error;

	if (auth_gs2_header_decode(data, data_size, FALSE,
				   &gs2_header, &gs2_header_end, &error) < 0) {
		e_info(request->mech_event, "Invalid gs2-header in request: %s",
		       error);
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}

	if (gs2_header.authzid == NULL) {
		e_info(request->mech_event, "Missing username");
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}
	if (!auth_request_set_username(request, gs2_header.authzid, &error)) {
		e_info(request->mech_event, "%s", error);
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}
	if (gs2_header.cbind.status == AUTH_GS2_CBIND_STATUS_PROVIDED) {
		/* channel binding is not supported */
		e_info(request->mech_event,
		       "Client requested and used channel-binding");
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}

	size_t gs2_header_size = gs2_header_end - data;
	size_t payload_size = data_size - gs2_header_size;

	if (payload_size == 0) {
		e_info(request->mech_event, "Response payload is missing");
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}
	if (*gs2_header_end != '\x01') {
		e_info(request->mech_event, "Invalid gs2-header in request: "
		       "Spurious data at end of header");
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}

	/* split the data from ^A */
	const char *const *fields =
		t_strsplit(t_strndup(gs2_header_end + 1, payload_size - 1),
		  "\x01");
	const char *const *ptr;
	const char *token = NULL, *value;

	for (ptr = fields; *ptr != NULL; ptr++) {
		if (str_begins(*ptr, "auth=", &value)) {
			if (str_begins_icase(value, "bearer ", &value) &&
			    oauth2_valid_token(value)) {
				token = value;
			} else {
				e_info(request->mech_event,
				       "Invalid response payload");
				oauth2_fail_invalid_token(oauth2_req);
				return;
			}
		}
		/* do not fail on unexpected fields */
	}
	if (token == NULL) {
		e_info(request->mech_event, "Missing token");
		oauth2_fail_invalid_token(oauth2_req);
		return;
	}
	mech_oauth2_verify_token(oauth2_req, token);
}

/* Input syntax:
 user=Username^Aauth=Bearer token^A^A
*/
static void
mech_xoauth2_auth_continue(struct auth_request *request,
			   const unsigned char *data,
			   size_t data_size)
{
	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, auth);

	if (oauth2_req->db == NULL) {
		e_error(request->event, "BUG: oauth2 database missing");
		auth_request_internal_failure(request);
		return;
	}
	if (data_size == 0) {
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}

	/* split the data from ^A */
	bool user_given = FALSE;
	const char *value;
	const char *error;
	const char *token = NULL;
	const char *const *ptr;
	const char *username;
	const char *const *fields =
		t_strsplit(t_strndup(data, data_size), "\x01");

	for (ptr = fields; *ptr != NULL; ptr++) {
		if (str_begins(*ptr, "user=", &value)) {
			/* xoauth2 does not require unescaping because the data
			   format does not contain anything to escape */
			username = value;
			user_given = TRUE;
		} else if (str_begins(*ptr, "auth=", &value)) {
			if (str_begins_icase(value, "bearer ", &value) &&
			    oauth2_valid_token(value)) {
				token = value;
			} else {
				e_info(request->mech_event,
				       "Invalid response data");
				oauth2_fail_invalid_token(oauth2_req);
				return;
			}
		}
		/* do not fail on unexpected fields */
	}

	if (user_given &&
	    !auth_request_set_username(request, username, &error)) {
		e_info(request->mech_event, "%s", error);
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}
	if (user_given && token != NULL)
		mech_oauth2_verify_token(oauth2_req, token);
	else if (token == NULL) {
		e_info(request->mech_event, "Missing token");
		oauth2_fail_invalid_request(oauth2_req);
	} else {
		e_info(request->mech_event, "Missing username");
		oauth2_fail_invalid_request(oauth2_req);
	}
}

static struct auth_request *mech_oauth2_auth_new(void)
{
	struct oauth2_auth_request *request;

	pool_t pool = pool_alloconly_create_clean(MEMPOOL_GROWING
						  "oauth2_auth_request", 2048);
	request = p_new(pool, struct oauth2_auth_request, 1);
	request->auth.pool = pool;
	request->db_req.pool = pool;
	request->db = db_oauth2;
	return &request->auth;
}

const struct mech_module mech_oauthbearer = {
	"OAUTHBEARER",

	/* while this does not transfer plaintext password,
	   the token is still considered as password */
	.flags = MECH_SEC_PLAINTEXT,
	.passdb_need = 0,

	mech_oauth2_auth_new,
	mech_generic_auth_initial,
	mech_oauthbearer_auth_continue,
	mech_generic_auth_free
};

const struct mech_module mech_xoauth2 = {
	"XOAUTH2",

	.flags = MECH_SEC_PLAINTEXT,
	.passdb_need = 0,

	mech_oauth2_auth_new,
	mech_generic_auth_initial,
	mech_xoauth2_auth_continue,
	mech_generic_auth_free
};

void mech_oauth2_initialize(void)
{
	const char *mech, *error;
	array_foreach_elem(&global_auth_settings->mechanisms, mech) {
		if (strcasecmp(mech, mech_xoauth2.mech_name) == 0 ||
		    strcasecmp(mech, mech_oauthbearer.mech_name) == 0) {
			if (db_oauth2_init(auth_event, FALSE,
					   &db_oauth2, &error) < 0)
				i_fatal("Cannot initialize oauth2: %s", error);
		}
	}
}
