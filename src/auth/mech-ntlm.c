/*
 * NTLM and NTLMv2 authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "mech.h"
#include "passdb.h"
#include "str.h"
#include "buffer.h"
#include "hex-binary.h"
#include "safe-memset.h"

#include "ntlm.h"

struct ntlm_auth_request {
	struct auth_request auth_request;

	pool_t pool;

	/* requested: */
	bool ntlm2_negotiated;
	bool unicode_negotiated;
	const unsigned char *challenge;

	/* received: */
	struct ntlmssp_response *response;
};

static bool lm_verify_credentials(struct ntlm_auth_request *request,
				  const unsigned char *credentials, size_t size)
{
	const unsigned char *client_response;
	unsigned char lm_response[LM_RESPONSE_SIZE];
	unsigned int response_length;

	if (size != LM_HASH_SIZE) {
                e_error(request->auth_request.mech_event,
			"invalid LM credentials length");
		return FALSE;
	}

	response_length =
		ntlmssp_buffer_length(request->response, lm_response);
	client_response = ntlmssp_buffer_data(request->response, lm_response);

	if (response_length < LM_RESPONSE_SIZE) {
                e_error(request->auth_request.mech_event,
			"LM response length is too small");
		return FALSE;
	}

	ntlmssp_v1_response(credentials, request->challenge, lm_response);
	return mem_equals_timing_safe(lm_response, client_response, LM_RESPONSE_SIZE);
}

static void
lm_credentials_callback(enum passdb_result result,
			const unsigned char *credentials, size_t size,
			struct auth_request *auth_request)
{
	struct ntlm_auth_request *request =
		(struct ntlm_auth_request *)auth_request;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (lm_verify_credentials(request, credentials, size))
			auth_request_success(auth_request, "", 0);
		else
			auth_request_fail(auth_request);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

static int
ntlm_verify_credentials(struct ntlm_auth_request *request,
			const unsigned char *credentials, size_t size)
{
        struct auth_request *auth_request = &request->auth_request;
	const unsigned char *client_response;
	unsigned int response_length;

	response_length =
		ntlmssp_buffer_length(request->response, ntlm_response);
	client_response = ntlmssp_buffer_data(request->response, ntlm_response);

	if (response_length == 0) {
		/* try LM authentication unless NTLM2 was negotiated */
		return request->ntlm2_negotiated ? -1 : 0;
	}

	if (size != NTLMSSP_HASH_SIZE) {
                e_error(request->auth_request.mech_event,
			"invalid NTLM credentials length");
		return -1;
	}

	if (response_length > NTLMSSP_RESPONSE_SIZE) {
		unsigned char ntlm_v2_response[NTLMSSP_V2_RESPONSE_SIZE];
		const unsigned char *blob =
			client_response + NTLMSSP_V2_RESPONSE_SIZE;

		/*
		 * Authentication target == NULL because we are acting
		 * as a standalone server, not as NT domain member.
		 */
		ntlmssp_v2_response(auth_request->user, NULL,
				    credentials, request->challenge, blob,
				    response_length - NTLMSSP_V2_RESPONSE_SIZE,
				    ntlm_v2_response);

		return mem_equals_timing_safe(ntlm_v2_response, client_response,
					      NTLMSSP_V2_RESPONSE_SIZE) ? 1 : -1;
	} else {
		unsigned char ntlm_response[NTLMSSP_RESPONSE_SIZE];
		const unsigned char *client_lm_response =
			ntlmssp_buffer_data(request->response, lm_response);

		if (request->ntlm2_negotiated)
			ntlmssp2_response(credentials, request->challenge,
					  client_lm_response,
					  ntlm_response);
		else 
			ntlmssp_v1_response(credentials, request->challenge,
					    ntlm_response);

		return mem_equals_timing_safe(ntlm_response, client_response,
					      NTLMSSP_RESPONSE_SIZE) ? 1 : -1;
	}
}

static void
ntlm_credentials_callback(enum passdb_result result,
			  const unsigned char *credentials, size_t size,
			  struct auth_request *auth_request)
{
	struct ntlm_auth_request *request =
		(struct ntlm_auth_request *)auth_request;
	int ret;

	switch (result) {
	case PASSDB_RESULT_OK:
		ret = ntlm_verify_credentials(request, credentials, size);
		if (ret > 0) {
			auth_request_success(auth_request, "", 0);
			return;
		}
		if (ret < 0) {
			auth_request_fail(auth_request);
			return;
		}
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		return;
	default:
		break;
	}

	/* NTLM credentials not found or didn't want to use them,
	   try with LM credentials */
	auth_request_lookup_credentials(auth_request, "LANMAN",
					lm_credentials_callback);
}

static void
mech_ntlm_auth_continue(struct auth_request *auth_request,
			const unsigned char *data, size_t data_size)
{
	struct ntlm_auth_request *request =
		(struct ntlm_auth_request *)auth_request;
	const char *error;

	if (request->challenge == NULL) {
		const struct ntlmssp_request *ntlm_request =
			(const struct ntlmssp_request *)data;
		const struct ntlmssp_challenge *message;
		size_t message_size;
		uint32_t flags;

		if (!ntlmssp_check_request(ntlm_request, data_size, &error)) {
			e_info(auth_request->mech_event,
			       "invalid NTLM request: %s", error);
			auth_request_fail(auth_request);
			return;
		}

		message = ntlmssp_create_challenge(request->pool, ntlm_request,
						   &message_size);
		flags = read_le32(&message->flags);
		request->ntlm2_negotiated = (flags & NTLMSSP_NEGOTIATE_NTLM2) != 0;
		request->unicode_negotiated = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0;
		request->challenge = message->challenge;

		auth_request_handler_reply_continue(auth_request, message,
						    message_size);
	} else {
		const struct ntlmssp_response *response =
			(const struct ntlmssp_response *)data;
		const char *username;

		if (!ntlmssp_check_response(response, data_size, &error)) {
			e_info(auth_request->mech_event,
			       "invalid NTLM response: %s", error);
			auth_request_fail(auth_request);
			return;
		}

		request->response = p_malloc(request->pool, data_size);
		memcpy(request->response, response, data_size);

		username = ntlmssp_t_str(request->response, user, 
					 request->unicode_negotiated);

		if (!auth_request_set_username(auth_request, username, &error)) {
			e_info(auth_request->mech_event,
			       "%s", error);
			auth_request_fail(auth_request);
			return;
		}

		auth_request_lookup_credentials(auth_request, "NTLM",
						ntlm_credentials_callback);
	}
}

static struct auth_request *mech_ntlm_auth_new(void)
{
	struct ntlm_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"ntlm_auth_request", 2048);
	request = p_new(pool, struct ntlm_auth_request, 1);
	request->pool = pool;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_ntlm = {
	"NTLM",

	.flags = MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_ntlm_auth_new,
	mech_generic_auth_initial,
	mech_ntlm_auth_continue,
	mech_generic_auth_free
};
