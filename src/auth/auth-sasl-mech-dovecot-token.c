/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

/* Used internally by Dovecot processes to authenticate against each others
   (e.g. imap to imap-urlauth). See auth-token.c */

#include "auth-common.h"
#include "safe-memset.h"
#include "sasl-server-protected.h"
#include "auth-sasl.h"
#include "auth-token.h"

static void
mech_dovecot_token_auth_continue(struct sasl_server_mech_request *request,
				 const unsigned char *data, size_t data_size)
{
	const char *session_id, *username, *pid, *service;
	char *auth_token;
	size_t i, len;
	int count;

	/* service \0 pid \0 username \0 session_id \0 auth_token */
	service = (const char *) data;
	session_id = username = pid = auth_token = NULL;
	count = 0;
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\0') {
			count++; i++;
			if (count == 1)
				pid = (const char *)data + i;
			else if (count == 2)
				username = (const char *)data + i;
			else if (count == 3)
				session_id = (const char *)data + i;
			else if (count == 4) {
				len = data_size - i;
				auth_token = p_strndup(unsafe_data_stack_pool,
						       data+i, len);
			}
			else
				break;
		}
	}

	if (count != 4) {
		/* invalid input */
		e_info(request->mech_event, "invalid input");
		sasl_server_request_failure(request);
	} else if (!sasl_server_request_set_authid(
			request, SASL_SERVER_AUTHID_TYPE_USERNAME, username)) {
		/* invalid username */
		sasl_server_request_failure(request);
	} else {
		const char *valid_token =
			auth_token_get(service, pid, request->authid,
				       session_id);

		if (auth_token != NULL &&
		    str_equals_timing_almost_safe(auth_token, valid_token)) {
			request->request->passdb_success = TRUE;
			auth_request_set_field(request->request, "userdb_client_service", service, "");
			sasl_server_request_success(request, NULL, 0);
		} else {
			sasl_server_request_failure(request);
		}
	}

	/* make sure it's cleared */
	if (auth_token != NULL)
		safe_memset(auth_token, 0, strlen(auth_token));
}

static const struct sasl_server_mech_funcs mech_dovecot_token_funcs = {
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_dovecot_token_auth_continue,
};

const struct sasl_server_mech_def mech_dovecot_token = {
	.name = AUTH_SASL_MECH_NAME_DOVECOT_TOKEN,

	.flags = SASL_MECH_SEC_PRIVATE | SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_NOTHING,

	.funcs = &mech_dovecot_token_funcs,
};
