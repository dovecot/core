/*
 * NTLM and NTLMv2 authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "common.h"
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
	int ntlm2_negotiated;
	int unicode_negotiated;
	const unsigned char *challenge;

	/* received: */
	struct ntlmssp_response *response;
};

static void
lm_credentials_callback(const char *credentials,
			struct auth_request *auth_request)
{
	struct ntlm_auth_request *request =
		(struct ntlm_auth_request *)auth_request;
	const unsigned char *client_response;
	unsigned char lm_response[LM_RESPONSE_SIZE];
	unsigned char hash[LM_HASH_SIZE];
	unsigned int response_length;
	buffer_t *hash_buffer;
	int ret;

	response_length =
		ntlmssp_buffer_length(request->response, lm_response);
	client_response = ntlmssp_buffer_data(request->response, lm_response);

	if (credentials == NULL || response_length < LM_RESPONSE_SIZE) {
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return;
	}

	hash_buffer = buffer_create_data(auth_request->pool,
					 hash, sizeof(hash));
	hex_to_binary(credentials, hash_buffer);

	ntlmssp_v1_response(hash, request->challenge, lm_response);

	ret = memcmp(lm_response, client_response, LM_RESPONSE_SIZE) == 0;

	mech_auth_finish(auth_request, NULL, 0, ret);
}

static void
ntlm_credentials_callback(const char *credentials,
			  struct auth_request *auth_request)
{
	struct ntlm_auth_request *request =
		(struct ntlm_auth_request *)auth_request;
	const unsigned char *client_response;
	unsigned char hash[NTLMSSP_HASH_SIZE];
	unsigned int response_length;
	buffer_t *hash_buffer;
	int ret;

	response_length =
		ntlmssp_buffer_length(request->response, ntlm_response);
	client_response = ntlmssp_buffer_data(request->response, ntlm_response);

	if (credentials == NULL || response_length == 0) {
		/* We can't use LM authentication if NTLM2 was negotiated */
		if (request->ntlm2_negotiated)
			mech_auth_finish(auth_request, NULL, 0, FALSE);
		else
			passdb->lookup_credentials(auth_request,
						   PASSDB_CREDENTIALS_LANMAN,
						   lm_credentials_callback);
		return;
	}

	hash_buffer = buffer_create_data(auth_request->pool,
					 hash, sizeof(hash));
	hex_to_binary(credentials, hash_buffer);


	if (response_length > NTLMSSP_RESPONSE_SIZE) {
		unsigned char ntlm_v2_response[NTLMSSP_V2_RESPONSE_SIZE];
		const unsigned char *blob =
			client_response + NTLMSSP_V2_RESPONSE_SIZE;

		/*
		 * Authentication target == NULL because we are acting
		 * as a standalone server, not as NT domain member.
		 */
		ntlmssp_v2_response(auth_request->user, NULL,
				    hash, request->challenge, blob,
				    response_length - NTLMSSP_V2_RESPONSE_SIZE,
				    ntlm_v2_response);

		ret = memcmp(ntlm_v2_response, client_response,
			     NTLMSSP_V2_RESPONSE_SIZE) == 0;
	} else {
		unsigned char ntlm_response[NTLMSSP_RESPONSE_SIZE];
		const unsigned char *client_lm_response =
			ntlmssp_buffer_data(request->response, lm_response);

		if (request->ntlm2_negotiated)
			ntlmssp2_response(hash, request->challenge,
					  client_lm_response,
					  ntlm_response);
		else 
			ntlmssp_v1_response(hash, request->challenge,
					    ntlm_response);

		ret = memcmp(ntlm_response, client_response,
			     NTLMSSP_RESPONSE_SIZE) == 0;
	}

	mech_auth_finish(auth_request, NULL, 0, ret);
}

static void
mech_ntlm_auth_continue(struct auth_request *auth_request,
			const unsigned char *data, size_t data_size,
			mech_callback_t *callback)
{
	struct ntlm_auth_request *request =
		(struct ntlm_auth_request *)auth_request;
	const char *error;

	auth_request->callback = callback;

	if (!request->challenge) {
		const struct ntlmssp_request *ntlm_request =
			(struct ntlmssp_request *)data;
		const struct ntlmssp_challenge *message;
		size_t message_size;
		uint32_t flags;

		if (!ntlmssp_check_request(ntlm_request, data_size, &error)) {
			if (verbose) {
				i_info("ntlm(%s): invalid NTLM request, %s",
				       get_log_prefix(auth_request),
				       error);
			}
			mech_auth_finish(auth_request, NULL, 0, FALSE);
			return;
		}

		message = ntlmssp_create_challenge(request->pool, ntlm_request,
						   &message_size);
		flags = read_le32(&message->flags);
		request->ntlm2_negotiated = flags & NTLMSSP_NEGOTIATE_NTLM2;
		request->unicode_negotiated = flags & NTLMSSP_NEGOTIATE_UNICODE;
		request->challenge = message->challenge;

		auth_request->callback(auth_request,
				       AUTH_CLIENT_RESULT_CONTINUE,
				       message, message_size);
	} else {
		const struct ntlmssp_response *response =
			(struct ntlmssp_response *)data;
		char *username;

		if (!ntlmssp_check_response(response, data_size, &error)) {
			if (verbose) {
				i_info("ntlm(%s): invalid NTLM response, %s",
				       get_log_prefix(auth_request),
				       error);
			}
			mech_auth_finish(auth_request, NULL, 0, FALSE);
			return;
		}

		request->response = p_malloc(request->pool, data_size);
		memcpy(request->response, response, data_size);

		username = p_strdup(auth_request->pool,
				    ntlmssp_t_str(request->response, user, 
				    request->unicode_negotiated));

		if (!mech_fix_username(username, &error)) {
			if (verbose) {
				i_info("ntlm(%s): %s",
				       get_log_prefix(auth_request), error);
			}
			mech_auth_finish(auth_request, NULL, 0, FALSE);
			return;
		}

		auth_request->user = username;
		passdb->lookup_credentials(auth_request,
					   PASSDB_CREDENTIALS_NTLM,
					   ntlm_credentials_callback);
	}
}

static void
mech_ntlm_auth_initial(struct auth_request *auth_request,
		       const unsigned char *data __attr_unused__,
		       size_t data_size __attr_unused__,
		       mech_callback_t *callback)
{
	callback(auth_request, AUTH_CLIENT_RESULT_CONTINUE, NULL, 0);
}

static void
mech_ntlm_auth_free(struct auth_request *request)
{
	pool_unref(request->pool);
}

static struct auth_request *mech_ntlm_auth_new(void)
{
	struct ntlm_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("ntlm_auth_request", 256);
	request = p_new(pool, struct ntlm_auth_request, 1);
	request->pool = pool;

	request->auth_request.refcount = 1;
	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_ntlm = {
	"NTLM",

	MEMBER(flags) MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE,

	MEMBER(passdb_need_plain) FALSE,
	MEMBER(passdb_need_credentials) TRUE,

	mech_ntlm_auth_new,
	mech_ntlm_auth_initial,
	mech_ntlm_auth_continue,
	mech_ntlm_auth_free
};
