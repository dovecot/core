/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "net.h"
#include "json-parser.h"
#include "istream.h"
#include "dsasl-client-private.h"

struct oauthbearer_dsasl_client {
	struct dsasl_client client;
	const char *host;
	const char *status;
	in_port_t port;
	bool output_sent;
};

static int
mech_oauthbearer_input(struct dsasl_client *_client,
		 const unsigned char *input, unsigned int input_len,
		 const char **error_r)
{
	struct oauthbearer_dsasl_client *client =
		(struct oauthbearer_dsasl_client *)_client;

	if (!client->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return -1;
		}
	} else {
		client->status = "";
		/* if response is empty, authentication has *SUCCEEDED* */
		if (input_len == 0)
			return 0;

		/* authentication has failed, try parse status.
		   we are only interested in extracting status if possible
		   so we don't really need to much error handling. */
		struct istream *is = i_stream_create_from_data(input, input_len);
		const char *status = NULL, *value;
		const char *error = NULL;
		enum json_type jtype;
		bool found_status = FALSE;
		struct json_parser *parser = json_parser_init(is);
		while (json_parse_next(parser, &jtype, &value)>0) {
			if (found_status && status == NULL) {
				if (jtype == JSON_TYPE_STRING ||
				    jtype == JSON_TYPE_NUMBER)
					status = t_strdup(value);
				break;
			} else if (jtype == JSON_TYPE_OBJECT_KEY &&
				   strcmp(value, "status") == 0) {
				found_status = TRUE;
			} else json_parse_skip_next(parser);
		}

		/* deinitialize json parser */
		int ret = json_parser_deinit(&parser, &error);

		if (status != NULL)
			client->status = p_strdup(_client->pool, status);
		else {
			ret = -1;
			if (error == NULL)
				error = "Status value missing";
		}
		if (ret < 0)
			*error_r = t_strdup_printf("Error parsing JSON reply: %s",
						   error);
		else
			*error_r = t_strdup_printf("Failed to authenticate: %s",
						   client->status);
		return -1;
	}
	return 0;
}

static int
mech_oauthbearer_output(struct dsasl_client *_client,
		  const unsigned char **output_r, unsigned int *output_len_r,
		  const char **error_r)
{
	struct oauthbearer_dsasl_client *client =
		(struct oauthbearer_dsasl_client *)_client;
	string_t *str;

	if (_client->set.authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (_client->password == NULL) {
		*error_r = "password not set";
		return -1;
	}

	str = str_new(_client->pool, 64);

	str_printfa(str, "n,a=%s,\x01", _client->set.authid);
	if (client->host != NULL && *client->host != '\0')
		str_printfa(str, "host=%s\x01", client->host);
	if (client->port > 0)
		str_printfa(str, "port=%u\x01", client->port);
	str_printfa(str, "auth=Bearer %s\x01", _client->password);
	str_append_c(str, '\x01');

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	client->output_sent = TRUE;
	return 0;
}

static int
mech_xoauth2_output(struct dsasl_client *_client,
		    const unsigned char **output_r, unsigned int *output_len_r,
		    const char **error_r)
{
	struct oauthbearer_dsasl_client *client =
		(struct oauthbearer_dsasl_client *)_client;
	string_t *str;

	if (_client->set.authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (_client->password == NULL) {
		*error_r = "password not set";
		return -1;
	}

	str = str_new(_client->pool, 64);

	str_printfa(str, "user=%s\x01", _client->set.authid);
	str_printfa(str, "auth=Bearer %s\x01", _client->password);
	str_append_c(str, '\x01');

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	client->output_sent = TRUE;
	return 0;
}

static int
mech_oauthbearer_set_parameter(struct dsasl_client *_client, const char *key,
			       const char *value, const char **error_r)
{
	struct oauthbearer_dsasl_client *client =
		(struct oauthbearer_dsasl_client *)_client;
	if (strcmp(key, "host") == 0) {
		if (value != NULL)
			client->host = p_strdup(_client->pool, value);
		else
			client->host = NULL;
		return 1;
	} else if (strcmp(key, "port") == 0) {
		if (value == NULL) {
			client->port = 0;
		} else if (net_str2port(key, &client->port) < 0) {
			*error_r = "Invalid port value";
			return -1;
		}
		return 1;
	}
	return 0;
}

static int
mech_oauthbearer_get_result(struct dsasl_client *_client, const char *key,
			    const char **value_r, const char **error_r ATTR_UNUSED)
{
	struct oauthbearer_dsasl_client *client =
		(struct oauthbearer_dsasl_client *)_client;
	if (strcmp(key, "status") == 0) {
		/* this is set to value after login attempt */
		i_assert(client->status != NULL);
		*value_r = client->status;
		return 1;
	}
	return 0;
}

const struct dsasl_client_mech dsasl_client_mech_oauthbearer = {
	.name = "OAUTHBEARER",
	.struct_size = sizeof(struct oauthbearer_dsasl_client),

	.input = mech_oauthbearer_input,
	.output = mech_oauthbearer_output,
	.set_parameter = mech_oauthbearer_set_parameter,
	.get_result = mech_oauthbearer_get_result,
};

const struct dsasl_client_mech dsasl_client_mech_xoauth2 = {
	.name = "XOAUTH2",
	.struct_size = sizeof(struct oauthbearer_dsasl_client),

	.input = mech_oauthbearer_input,
	.output = mech_xoauth2_output,
	.set_parameter = mech_oauthbearer_set_parameter,
	.get_result = mech_oauthbearer_get_result,
};
