/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "net.h"
#include "json-istream.h"
#include "istream.h"
#include "auth-gs2.h"

#include "sasl-oauth2.h"
#include "dsasl-client-protected.h"

struct oauthbearer_sasl_session {
	struct dsasl_client_mech_session session;

	const char *status;
	bool output_sent;
};

static struct dsasl_client_mech_session *mech_oauthbearer_auth_new(pool_t pool)
{
	struct oauthbearer_sasl_session *osession =
		p_new(pool, struct oauthbearer_sasl_session, 1);
	return &osession->session;
}

static int
mech_oauthbearer_auth_check(struct dsasl_client_mech_session *msession,
			    const char **error_r)
{
	if (msession->authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (msession->password == NULL) {
		*error_r = "password not set";
		return -1;
	}
	if (!sasl_oauth2_kvpair_check_value(msession->password)) {
		*error_r = "password contains unsupported characters";
		return -1;
	}
	if (msession->mech == &dsasl_client_mech_oauthbearer &&
	    msession->params.host != NULL &&
	    !sasl_oauth2_kvpair_check_value(msession->params.host)) {
		*error_r = "host contains unsupported characters";
		return -1;
	}
	return 0;
}

static enum dsasl_client_result
mech_oauthbearer_auth_input(struct dsasl_client_mech_session *msession,
			    const unsigned char *input, size_t input_len,
			    const char **error_r)
{
	struct oauthbearer_sasl_session *osession =
		container_of(msession, struct oauthbearer_sasl_session, session);

	if (!osession->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}
	} else {
		osession->status = "";
		/* if response is empty, authentication has *SUCCEEDED* */
		if (input_len == 0)
			return DSASL_CLIENT_RESULT_OK;

		/* authentication has failed, try parse status.
		   we are only interested in extracting status if possible
		   so we don't really need to much error handling. */
		struct istream *is = i_stream_create_from_data(input, input_len);
		struct json_node jnode;
		struct json_istream *jis = json_istream_create_object(
			is, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);
		const char *error;
		int ret;

		i_stream_unref(&is);

		ret = 1;
		while (ret > 0) {
			ret = json_istream_read(jis, &jnode);
			i_assert(ret != 0);
			if (ret < 0)
				break;
			i_assert(jnode.name != NULL);
			if (strcmp(jnode.name, "status") == 0) {
				if (!json_node_is_string(&jnode) &&
				    !json_node_is_number(&jnode)) {
					*error_r = "Status field in response is not a string or a number.";
					return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
				}
				osession->status = p_strdup(
					msession->pool,
					json_node_get_str(&jnode));
			}
			json_istream_skip(jis);
		}

		ret = json_istream_finish(&jis, &error);
		i_assert(ret != 0);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Error parsing JSON reply: %s", error);
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}

		if (osession->status == NULL) {
			*error_r = "Error parsing JSON reply: "
				"Status value missing";
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}

		*error_r = t_strdup_printf("Failed to authenticate: %s",
					   osession->status);
		return DSASL_CLIENT_RESULT_AUTH_FAILED;
	}
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_oauthbearer_auth_output(struct dsasl_client_mech_session *msession,
			     const unsigned char **output_r, size_t *output_len_r,
			     const char **error_r ATTR_UNUSED)
{
	struct oauthbearer_sasl_session *osession =
		container_of(msession, struct oauthbearer_sasl_session, session);
	string_t *str;

	struct auth_gs2_header gs2_header = {
		.authzid = msession->authid,
	};

	str = str_new(msession->pool, 64);
	auth_gs2_header_encode(&gs2_header, str);
	str_append_c(str, '\x01');
	if (msession->params.host != NULL)
		str_printfa(str, "host=%s\x01", msession->params.host);
	if (msession->params.port > 0)
		str_printfa(str, "port=%u\x01", msession->params.port);
	str_printfa(str, "auth=Bearer %s\x01", msession->password);
	str_append_c(str, '\x01');

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	osession->output_sent = TRUE;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_xoauth2_auth_output(struct dsasl_client_mech_session *msession,
			 const unsigned char **output_r, size_t *output_len_r,
			 const char **error_r ATTR_UNUSED)
{
	struct oauthbearer_sasl_session *osession =
		container_of(msession, struct oauthbearer_sasl_session, session);
	string_t *str;

	str = str_new(msession->pool, 64);

	str_printfa(str, "user=%s\x01", msession->authid);
	str_printfa(str, "auth=Bearer %s\x01", msession->password);
	str_append_c(str, '\x01');

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	osession->output_sent = TRUE;
	return DSASL_CLIENT_RESULT_OK;
}

static int
mech_oauthbearer_auth_get_result(struct dsasl_client_mech_session *msession,
				 const char *key, const char **value_r,
				 const char **error_r ATTR_UNUSED)
{
	struct oauthbearer_sasl_session *osession =
		container_of(msession, struct oauthbearer_sasl_session, session);

	if (strcmp(key, "status") == 0) {
		/* this is set to value after login attempt */
		i_assert(osession->status != NULL);
		*value_r = osession->status;
		return 1;
	}
	return 0;
}

const struct dsasl_client_mech dsasl_client_mech_oauthbearer = {
	.name = SASL_MECH_NAME_OAUTHBEARER,

	.auth_new = mech_oauthbearer_auth_new,
	.auth_check = mech_oauthbearer_auth_check,
	.auth_input = mech_oauthbearer_auth_input,
	.auth_output = mech_oauthbearer_auth_output,
	.auth_get_result = mech_oauthbearer_auth_get_result,
};

const struct dsasl_client_mech dsasl_client_mech_xoauth2 = {
	.name = SASL_MECH_NAME_XOAUTH2,

	.auth_new = mech_oauthbearer_auth_new,
	.auth_check = mech_oauthbearer_auth_check,
	.auth_input = mech_oauthbearer_auth_input,
	.auth_output = mech_xoauth2_auth_output,
	.auth_get_result = mech_oauthbearer_auth_get_result,
};
