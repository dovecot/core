/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

/* Used internally by Dovecot processes to authenticate against each others
   (e.g. imap to imap-urlauth). See auth-token.c */

#include "auth-common.h"
#include "mech.h"
#include "safe-memset.h"
#include "auth-token.h"

static void
mech_dovecot_token_auth_continue(struct auth_request *request,
			     const unsigned char *data, size_t data_size)
{
	const char *session_id, *username, *pid, *service, *error;
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
			else {
				len = data_size - i;
				auth_token = p_strndup(unsafe_data_stack_pool,
						       data+i, len);
				break;
			}
		}
	}	

	if (count != 4) {
		/* invalid input */
		e_info(request->mech_event, "invalid input");
		auth_request_fail(request);
	} else if (!auth_request_set_username(request, username, &error)) {
		/* invalid username */
		e_info(request->mech_event, "%s", error);
		auth_request_fail(request);
	} else {
		const char *valid_token =
			auth_token_get(service, pid, request->user, session_id);

		if (auth_token != NULL &&
		    strcmp(auth_token, valid_token) == 0) {
			request->passdb_success = TRUE;
			auth_request_set_field(request, "userdb_client_service", service, "");
			auth_request_success(request, NULL, 0);
		} else {
			auth_request_fail(request);
		}
	}

	/* make sure it's cleared */
	if (auth_token != NULL)
		safe_memset(auth_token, 0, strlen(auth_token));
}

static struct auth_request *mech_dovecot_token_auth_new(void)
{
	struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"dovecot_token_auth_request", 512);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	return request;
}

const struct mech_module mech_dovecot_token = {
	"DOVECOT-TOKEN",

	.flags = MECH_SEC_PRIVATE,
	.passdb_need = MECH_PASSDB_NEED_NOTHING,

	mech_dovecot_token_auth_new,
	mech_generic_auth_initial,
	mech_dovecot_token_auth_continue,
	mech_generic_auth_free
};
