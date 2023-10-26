/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "safe-memset.h"

#include "sasl-server-protected.h"
#include "sasl-server-mech-plain-common.h"

static void
mech_plain_auth_continue(struct sasl_server_mech_request *request,
			 const unsigned char *data, size_t data_size)
{
	const char *authid, *authenid;
	char *pass;
	size_t i, len;
	int count;

	/* authorization ID \0 authentication ID \0 pass. */
	authid = (const char *) data;
	authenid = NULL; pass = NULL;

	count = 0;
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = (const char *) data + i+1;
			else if (count == 2) {
				i++;
				len = data_size - i;
				pass = p_strndup(unsafe_data_stack_pool,
						 data+i, len);
			}
			else
				break;
		}
	}

	if (count == 2 && authenid != NULL && strcmp(authid, authenid) == 0) {
		/* the login username isn't different */
		authid = "";
	}

	if (count != 2) {
		/* invalid input */
		e_info(request->mech_event, "invalid input");
		sasl_server_request_failure(request);
	} else if (!sasl_server_request_set_authid(
			request, SASL_SERVER_AUTHID_TYPE_USERNAME, authenid)) {
		/* invalid username */
		sasl_server_request_failure(request);
	} else if (*authid != '\0' &&
		   !sasl_server_request_set_authzid(request, authid)) {
		/* invalid login username */
		sasl_server_request_failure(request);
	} else {
		sasl_server_request_verify_plain(
			request, pass, sasl_server_mech_plain_verify_callback);
	}

	/* make sure it's cleared */
	if (pass != NULL)
		safe_memset(pass, 0, strlen(pass));
}

static const struct sasl_server_mech_funcs mech_plain_funcs = {
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_plain_auth_continue,
};

static const struct sasl_server_mech_def mech_plain = {
	.name = SASL_MECH_NAME_PLAIN,

	.flags = SASL_MECH_SEC_PLAINTEXT | SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_VERIFY_PLAIN,

	.funcs = &mech_plain_funcs,
};

void sasl_server_mech_register_plain(struct sasl_server_instance *sinst)
{
	sasl_server_mech_register(sinst, &mech_plain);
}
