/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "auth-fields.h"
#include "auth-worker-connection.h"
#include "ioloop.h"
#include "str.h"
#include "strescape.h"
#include "json-ostream.h"
#include "auth-gs2.h"
#include "db-oauth2.h"
#include "oauth2.h"

#include "sasl-server-protected.h"
#include "sasl-server-oauth2.h"

struct oauth2_auth_request {
	struct sasl_server_mech_request request;
	struct db_oauth2 *db;
	struct db_oauth2_request db_req;
	lookup_credentials_callback_t *callback;

	bool failed:1;
	bool verifying_token:1;
};

const struct sasl_server_mech_def mech_oauthbearer;
const struct sasl_server_mech_def mech_xoauth2;

static struct db_oauth2 *db_oauth2 = NULL;

static void
oauth2_fail(struct oauth2_auth_request *oauth2_req,
	    const struct sasl_server_oauth2_failure *failure)
{
	struct sasl_server_mech_request *request = &oauth2_req->request;

	if (failure == NULL) {
		sasl_server_request_internal_failure(request);
		return;
	}

	string_t *reply = t_str_new(256);
	struct json_ostream *joutput = json_ostream_create_str(reply, 0);

	i_assert(failure->status != NULL);
	json_ostream_ndescend_object(joutput, NULL);
	if (request->mech == &mech_xoauth2) {
		if (strcmp(failure->status, "invalid_token") == 0)
			json_ostream_nwrite_string(joutput, "status", "401");
		else if (strcmp(failure->status, "insufficient_scope") == 0)
			json_ostream_nwrite_string(joutput, "status", "403");
		else
			json_ostream_nwrite_string(joutput, "status", "400");
		json_ostream_nwrite_string(joutput, "schemes", "bearer");
	} else {
		i_assert(request->mech == &mech_oauthbearer);
		json_ostream_nwrite_string(joutput, "status", failure->status);
	}
	if (failure->scope == NULL)
		json_ostream_nwrite_string(joutput, "scope", "mail");
	else
		json_ostream_nwrite_string(joutput, "scope", failure->scope);
	if (failure->openid_configuration != NULL &&
	    *failure->openid_configuration != '\0') {
		json_ostream_nwrite_string(
			joutput, "openid-configuration",
			failure->openid_configuration);
	}
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);

	oauth2_req->failed = TRUE;
	sasl_server_request_failure_with_reply(request,
					       str_data(reply), str_len(reply));
}

static void
oauth2_fail_status(struct oauth2_auth_request *oauth2_req, const char *status)
{
	const struct sasl_server_oauth2_failure failure = {
		.status = status,
	};

	oauth2_fail(oauth2_req, &failure);
}

static void oauth2_fail_invalid_request(struct oauth2_auth_request *oauth2_req)
{
	oauth2_fail_status(oauth2_req, "invalid_request");
}

static void oauth2_fail_invalid_token(struct oauth2_auth_request *oauth2_req)
{
	oauth2_fail_status(oauth2_req, "invalid_token");
}

void sasl_server_oauth2_request_succeed(struct auth_request *auth_request)
{
	struct sasl_server_mech_request *request = auth_request->sasl;

	i_assert(request->mech == &mech_oauthbearer ||
		 request->mech == &mech_xoauth2);

	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, request);

	i_assert(oauth2_req->verifying_token);
	sasl_server_request_success(request, "", 0);
}

void sasl_server_oauth2_request_fail(
	struct auth_request *auth_request,
	const struct sasl_server_oauth2_failure *failure)
{
	struct sasl_server_mech_request *request = auth_request->sasl;

	i_assert(request->mech == &mech_oauthbearer ||
		 request->mech == &mech_xoauth2);

	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, request);

	i_assert(oauth2_req->verifying_token);
	oauth2_fail(oauth2_req, failure);
}

#include "auth-sasl-mech-oauth2.c"

static void
mech_oauth2_verify_token(struct oauth2_auth_request *oauth2_req,
			 const char *token)
{
	i_assert(token != NULL);
	oauth2_req->verifying_token = TRUE;
	auth_sasl_oauth2_verify_token(oauth2_req, token);
}

/* Input syntax for data:
 gs2flag,a=username,^Afield=...^Afield=...^Aauth=Bearer token^A^A
*/
static void
mech_oauthbearer_auth_continue(struct sasl_server_mech_request *request,
			       const unsigned char *data,
			       size_t data_size)
{
	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, request);

	if (oauth2_req->db == NULL) {
		e_error(request->mech_event, "BUG: oauth2 database missing");
		sasl_server_request_internal_failure(request);
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
	if (!sasl_server_request_set_authid(request,
					    SASL_SERVER_AUTHID_TYPE_USERNAME,
					    gs2_header.authzid)) {
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
mech_xoauth2_auth_continue(struct sasl_server_mech_request *request,
			   const unsigned char *data,
			   size_t data_size)
{
	struct oauth2_auth_request *oauth2_req =
		container_of(request, struct oauth2_auth_request, request);

	if (oauth2_req->db == NULL) {
		e_error(request->mech_event, "BUG: oauth2 database missing");
		sasl_server_request_internal_failure(request);
		return;
	}
	if (data_size == 0) {
		oauth2_fail_invalid_request(oauth2_req);
		return;
	}

	/* split the data from ^A */
	bool user_given = FALSE;
	const char *value;
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
	    !sasl_server_request_set_authid(request,
					    SASL_SERVER_AUTHID_TYPE_USERNAME,
					    username)) {
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

static struct sasl_server_mech_request *mech_oauth2_auth_new(pool_t pool)
{
	struct oauth2_auth_request *request;

	request = p_new(pool, struct oauth2_auth_request, 1);
	request->db_req.pool = pool;
	request->db = db_oauth2;

	return &request->request;
}

const struct sasl_server_mech_def mech_oauthbearer = {
	.mech_name = "OAUTHBEARER",

	/* while this does not transfer plaintext password,
	   the token is still considered as password */
	.flags = SASL_MECH_SEC_PLAINTEXT,
	.passdb_need = 0,

	.auth_new = mech_oauth2_auth_new,
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_oauthbearer_auth_continue,
	.auth_free = sasl_server_mech_generic_auth_free,
};

const struct sasl_server_mech_def mech_xoauth2 = {
	.mech_name = "XOAUTH2",

	.flags = SASL_MECH_SEC_PLAINTEXT,
	.passdb_need = 0,

	.auth_new = mech_oauth2_auth_new,
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_xoauth2_auth_continue,
	.auth_free = sasl_server_mech_generic_auth_free,
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
