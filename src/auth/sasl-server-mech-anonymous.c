/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "sasl-server-protected.h"

static void
mech_anonymous_auth_continue(struct sasl_server_mech_request *request,
			     const unsigned char *data, size_t data_size)
{
	if (!sasl_server_request_set_authid(request,
					    SASL_SERVER_AUTHID_TYPE_ANONYMOUS,
					    t_strndup(data, data_size))) {
		sasl_server_request_failure(request);
		return;
	}

	sasl_server_request_success(request, "", 0);
}

static const struct sasl_server_mech_funcs mech_anonymous_funcs = {
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_anonymous_auth_continue,
};

static const struct sasl_server_mech_def mech_anonymous = {
	.name = SASL_MECH_NAME_ANONYMOUS,

	.flags = SASL_MECH_SEC_ANONYMOUS | SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_NOTHING,

	.funcs = &mech_anonymous_funcs,
};

void sasl_server_mech_register_anonymous(struct sasl_server_instance *sinst)
{
	sasl_server_mech_register(sinst, &mech_anonymous, NULL);
}
