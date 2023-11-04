/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "sasl-server-protected.h"

static void
mech_external_auth_continue(struct sasl_server_mech_request *request,
			    const unsigned char *data, size_t data_size)
{
	const char *authzid;

	authzid = t_strndup(data, data_size);

	if (!sasl_server_request_set_authid(request,
					    SASL_SERVER_AUTHID_TYPE_EXTERNAL,
					    "")) {
		sasl_server_request_failure(request);
		return;
	}
	if (*authzid != '\0' &&
	    !sasl_server_request_set_authzid(request, authzid)) {
		sasl_server_request_failure(request);
		return;
	}
	sasl_server_request_verify_plain(
		request, "", sasl_server_mech_plain_verify_callback);
}

static const struct sasl_server_mech_funcs mech_external_funcs = {
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_external_auth_continue,
};

static const struct sasl_server_mech_def mech_external = {
	.name = SASL_MECH_NAME_EXTERNAL,

	.flags = 0,
	.passdb_need = SASL_MECH_PASSDB_NEED_VERIFY_PLAIN,

	.funcs = &mech_external_funcs,
};

void sasl_server_mech_register_external(struct sasl_server_instance *sinst)
{
	sasl_server_mech_register(sinst, &mech_external, NULL);
}
