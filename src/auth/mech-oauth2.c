/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "safe-memset.h"
#include "str.h"
#include "mech.h"
#include "passdb.h"
#include "oauth2.h"
#include "json-parser.h"
#include <ctype.h>

struct oauth2_auth_request {
	struct auth_request auth;
	bool failed;
};

/* RFC5801 based unescaping */
static bool oauth2_unescape_username(const char *in, const char **username_r)
{
	string_t *out;
	out = t_str_new(64);
	for (; *in != '\0'; in++) {
		if (in[0] == ',')
			return FALSE;
		if (in[0] == '=') {
			if (in[1] == '2' && in[2] == 'C')
				str_append_c(out, ',');
			else if (in[1] == '3' && in[2] == 'D')
				str_append_c(out, '=');
			else
				return FALSE;
			in += 2;
		} else {
			str_append_c(out, *in);
		}
	}
	*username_r = str_c(out);
	return TRUE;
}

static void oauth2_verify_callback(enum passdb_result result,
				   const char *const *error_fields,
				   struct auth_request *request)
{
	struct oauth2_auth_request *oauth2_req =
			(struct oauth2_auth_request*)request;

	i_assert(result == PASSDB_RESULT_OK || error_fields != NULL);
	switch (result) {
	case PASSDB_RESULT_OK:
		auth_request_success(request, "", 0);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(request);
		break;
	default:
		/* we could get new token after this */
		if (request->mech_password != NULL)
			request->mech_password = NULL;
		string_t *error = t_str_new(64);
		str_append_c(error, '{');
		for (unsigned int i = 0; error_fields[i] != NULL; i += 2) {
			i_assert(error_fields[i+1] != NULL);
			if (i > 0)
				str_append_c(error, ',');
			str_append_c(error, '"');
			json_append_escaped(error, error_fields[i]);
			str_append(error, "\":\"");
			json_append_escaped(error, error_fields[i+1]);
			str_append_c(error, '"');
		}
		/* FIXME: HORRIBLE HACK - REMOVE ME!!!
		   It is because the mech has not been implemented properly
		   that we need to pass the config url in this strange way.

		   This **must** be removed from here and db-oauth2 once the
		   validation result et al is handled here.
		*/
		if (request->openid_config_url != NULL) {
			if (str_len(error) > 0)
				str_append_c(error, ',');
			str_printfa(error, "\"openid-configuration\":\"");
			json_append_escaped(error, request->openid_config_url);
			str_append_c(error, '"');
		}
		str_append_c(error, '}');
		auth_request_handler_reply_continue(request, str_data(error),
						    str_len(error));
		oauth2_req->failed = TRUE;
		break;
	}
}

static void
xoauth2_verify_callback(enum passdb_result result, struct auth_request *request)
{
	const char *const error_fields[] = {
		"status", "401",
		"schemes", "bearer",
		"scope", "mail",
		NULL
	};
	oauth2_verify_callback(result, error_fields, request);
}

static void
oauthbearer_verify_callback(enum passdb_result result, struct auth_request *request)
{
	const char *error_fields[] = {
		"status", "invalid_token",
		NULL
	};
	oauth2_verify_callback(result, error_fields, request);
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
			(struct oauth2_auth_request*)request;

	/* Specification says that client is sent "invalid token" challenge
	   which the client is supposed to ack with empty response */
	if (oauth2_req->failed) {
		auth_request_fail(request);
		return;
	}

	/* split the data from ^A */
	bool user_given = FALSE;
	const char *value, *error;
	const char *token = NULL;
	const char *const *ptr;
	const char *username;
	const char *const *fields =
		t_strsplit(t_strndup(data, data_size), "\x01");
	for(ptr = fields; *ptr != NULL; ptr++) {
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
				       "Invalid continued data");
				auth_request_fail(request);
				return;
			}
		}
		/* do not fail on unexpected fields */
	}

	if (user_given && !auth_request_set_username(request, username, &error)) {
		e_info(request->mech_event,
		       "%s", error);
		auth_request_fail(request);
		return;
	}

	if (user_given && token != NULL)
		auth_request_verify_plain(request, token,
					  xoauth2_verify_callback);
	else {
		e_info(request->mech_event, "Username or token missing");
		auth_request_fail(request);
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
			(struct oauth2_auth_request*)request;

	if (oauth2_req->failed) {
		auth_request_fail(request);
		return;
	}

	bool user_given = FALSE;
	const char *value, *error;
	const char *username;
	const char *const *ptr;
	/* split the data from ^A */
	const char **fields =
		t_strsplit(t_strndup(data, data_size), "\x01");
	const char *token = NULL;
	/* ensure initial field is OK */
	if (*fields == NULL || *(fields[0]) == '\0') {
		e_info(request->mech_event,
		       "Invalid continued data");
		auth_request_fail(request);
		return;
	}

	/* the first field is specified by RFC5801 as gs2-header */
	for(ptr = t_strsplit_spaces(fields[0], ","); *ptr != NULL; ptr++) {
		switch(*ptr[0]) {
		case 'f':
			e_info(request->mech_event,
			       "Client requested non-standard mechanism");
			auth_request_fail(request);
			return;
		case 'p':
			/* channel binding is not supported */
			e_info(request->mech_event,
			       "Client requested and used channel-binding");
			auth_request_fail(request);
			return;
		case 'n':
		case 'y':
			/* we don't need to use channel-binding */
			continue;
		case 'a': /* authzid */
			if ((*ptr)[1] != '=' ||
			    !oauth2_unescape_username((*ptr)+2, &username)) {
				 e_info(request->mech_event,
					"Invalid username escaping");
				 auth_request_fail(request);
				 return;
			} else {
				user_given = TRUE;
			}
			break;
		default:
			e_info(request->mech_event,
			       "Invalid gs2-header in request");
			auth_request_fail(request);
			return;
		}
	}

	for(ptr = fields; *ptr != NULL; ptr++) {
		if (str_begins(*ptr, "auth=", &value)) {
			if (str_begins_icase(value, "bearer ", &value) &&
			    oauth2_valid_token(value)) {
				token = value;
			} else {
				e_info(request->mech_event,
				       "Invalid continued data");
				auth_request_fail(request);
				return;
			}
		}
		/* do not fail on unexpected fields */
	}
	if (user_given && !auth_request_set_username(request, username, &error)) {
		e_info(request->mech_event,
		       "%s", error);
		auth_request_fail(request);
		return;
	}
	if (user_given && token != NULL)
		auth_request_verify_plain(request, token,
					  oauthbearer_verify_callback);
	else {
		e_info(request->mech_event, "Missing username or token");
		auth_request_fail(request);
	}
}

static struct auth_request *mech_oauth2_auth_new(void)
{
	struct oauth2_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"oauth2_auth_request", 2048);
	request = p_new(pool, struct oauth2_auth_request, 1);
	request->auth.pool = pool;
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


