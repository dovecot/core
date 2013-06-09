/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "sasl-client-private.h"

struct plain_sasl_client {
	struct sasl_client client;
	bool output_sent;
};

static int
mech_plain_input(struct sasl_client *_client,
		 const unsigned char *input ATTR_UNUSED, unsigned int input_len,
		 const char **error_r)
{
	struct plain_sasl_client *client = (struct plain_sasl_client *)_client;

	if (!client->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return -1;
		}
	} else {
		*error_r = "Server didn't finish authentication";
		return -1;
	}
	return 0;
}

static int
mech_plain_output(struct sasl_client *_client,
		  const unsigned char **output_r, unsigned int *output_len_r,
		  const char **error_r)
{
	struct plain_sasl_client *client = (struct plain_sasl_client *)_client;
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
	if (_client->set.authzid != NULL)
		str_append(str, _client->set.authzid);
	str_append_c(str, '\0');
	str_append(str, _client->set.authid);
	str_append_c(str, '\0');
	str_append(str, _client->password);

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	client->output_sent = TRUE;
	return 0;
}

const struct sasl_client_mech sasl_client_mech_plain = {
	.name = "PLAIN",
	.struct_size = sizeof(struct plain_sasl_client),

	.input = mech_plain_input,
	.output = mech_plain_output
};
