/*
 * S/Key (RFC 1731) authentication mechanism.
 *
 * Copyright (c) 2006 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "safe-memset.h"
#include "hash.h"
#include "mech.h"
#include "passdb.h"
#include "hex-binary.h"
#include "otp.h"
#include "mech-otp-skey-common.h"

static void 
skey_send_challenge(struct auth_request *auth_request,
		    const unsigned char *credentials, size_t size)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;
	const char *answer;

	if (otp_parse_dbentry(t_strndup(credentials, size),
			      &request->state) != 0) {
		e_error(request->auth_request.mech_event,
			"invalid OTP data in passdb");
		auth_request_fail(auth_request);
		return;
	}

	if (request->state.algo != OTP_HASH_MD4) {
		e_error(request->auth_request.mech_event,
			"md4 hash is needed");
		auth_request_fail(auth_request);
		return;
	}

	if (--request->state.seq < 1) {
		e_error(request->auth_request.mech_event,
			"sequence number < 1");
		auth_request_fail(auth_request);
		return;
	}

	request->lock = otp_try_lock(auth_request);
	if (!request->lock) {
		e_error(request->auth_request.mech_event,
			"user is locked, race attack?");
		auth_request_fail(auth_request);
		return;
	}

	answer = p_strdup_printf(request->pool, "%u %s",
				 request->state.seq, request->state.seed);

	auth_request_handler_reply_continue(auth_request, answer,
					    strlen(answer));
}

static void
otp_credentials_callback(enum passdb_result result,
			 const unsigned char *credentials, size_t size,
			 struct auth_request *auth_request)
{
	switch (result) {
	case PASSDB_RESULT_OK:
		skey_send_challenge(auth_request, credentials, size);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

static void
skey_credentials_callback(enum passdb_result result,
			  const unsigned char *credentials, size_t size,
			  struct auth_request *auth_request)
{
	switch (result) {
	case PASSDB_RESULT_OK:
		skey_send_challenge(auth_request, credentials, size);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		/* S/KEY credentials not found, try OTP */
		auth_request_lookup_credentials(auth_request, "OTP",
						otp_credentials_callback);
		break;
	}
}

static void
mech_skey_auth_phase1(struct auth_request *auth_request,
		      const unsigned char *data, size_t data_size)
{
	const char *username, *error;

	username = t_strndup(data, data_size);

	if (!auth_request_set_username(auth_request, username, &error)) {
		e_info(auth_request->mech_event,
		       "%s", error);
		auth_request_fail(auth_request);
		return;
	}

	auth_request_lookup_credentials(auth_request, "SKEY",
					skey_credentials_callback);
}

static void
mech_skey_auth_phase2(struct auth_request *auth_request,
		      const unsigned char *data, size_t data_size)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;
	struct otp_state *state = &request->state;
	unsigned char hash[OTP_HASH_SIZE], cur_hash[OTP_HASH_SIZE];
	int ret;

	if (data_size == 8) {
		memcpy(hash, data, 8);
	} else {
		const char *words = t_strndup(data, data_size);

		ret = otp_parse_response(words, hash, FALSE);
		if (ret < 0) {
			e_error(request->auth_request.mech_event,
				"invalid response");
			auth_request_fail(auth_request);
			otp_unlock(auth_request);
			return;
		}
	}

	otp_next_hash(state->algo, hash, cur_hash);

	ret = memcmp(cur_hash, state->hash, OTP_HASH_SIZE);
	if (ret != 0) {
		auth_request_fail(auth_request);
		otp_unlock(auth_request);
		return;
	}

	memcpy(state->hash, hash, sizeof(state->hash));

	auth_request_set_credentials(auth_request, "OTP",
				     otp_print_dbentry(state),
				     otp_set_credentials_callback);
}

static void
mech_skey_auth_continue(struct auth_request *auth_request,
		       const unsigned char *data, size_t data_size)
{
	if (auth_request->user == NULL) {
		mech_skey_auth_phase1(auth_request, data, data_size);
	} else {
		mech_skey_auth_phase2(auth_request, data, data_size);
	}
}

static struct auth_request *mech_skey_auth_new(void)
{
	struct otp_auth_request *request;
	pool_t pool;

	otp_lock_init();

	pool = pool_alloconly_create(MEMPOOL_GROWING"skey_auth_request", 2048);
	request = p_new(pool, struct otp_auth_request, 1);
	request->pool = pool;
	request->lock = FALSE;

	request->auth_request.refcount = 1;
	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_skey = {
	"SKEY",

	.flags = MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE,
	.passdb_need = MECH_PASSDB_NEED_SET_CREDENTIALS,

	mech_skey_auth_new,
	mech_generic_auth_initial,
	mech_skey_auth_continue,
	mech_otp_skey_auth_free
};
