/*
 * One-Time-Password (RFC 2444) authentication mechanism.
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
otp_send_challenge(struct auth_request *auth_request,
		   const unsigned char *credentials, size_t size)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;
	const char *answer;

	if (auth_request_fail_on_nuls(auth_request, credentials, size))
		return;

	if (otp_parse_dbentry(t_strndup(credentials, size),
			      &request->state) != 0) {
		e_error(request->auth_request.mech_event,
			"invalid OTP data in passdb");
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

	answer = p_strdup_printf(request->pool, "otp-%s %u %s ext",
				 digest_name(request->state.algo),
				 request->state.seq, request->state.seed);

	auth_request_handler_reply_continue(auth_request, answer,
					    strlen(answer));
}

static void
skey_credentials_callback(enum passdb_result result,
			  const unsigned char *credentials, size_t size,
			  struct auth_request *auth_request)
{
	switch (result) {
	case PASSDB_RESULT_OK:
		otp_send_challenge(auth_request, credentials, size);
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
otp_credentials_callback(enum passdb_result result,
			 const unsigned char *credentials, size_t size,
			 struct auth_request *auth_request)
{
	switch (result) {
	case PASSDB_RESULT_OK:
		otp_send_challenge(auth_request, credentials, size);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		/* OTP credentials not found, try S/KEY */
		auth_request_lookup_credentials(auth_request, "OTP",
						skey_credentials_callback);
		break;
	}
}

static void
mech_otp_auth_phase1(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;
	const char *authenid, *error;
	size_t i, count;

	/* authorization ID \0 authentication ID
	   FIXME: we'll ignore authorization ID for now. */
	authenid = NULL;

	count = 0;
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = (const char *) data + i + 1;
		}
	}

	if (count != 1) {
		e_error(request->auth_request.mech_event,
			"invalid input");
		auth_request_fail(auth_request);
		return;
	}

	if (!auth_request_set_username(auth_request, authenid, &error)) {
		e_info(auth_request->mech_event, "%s", error);
		auth_request_fail(auth_request);
		return;
	}

	auth_request_lookup_credentials(auth_request, "OTP",
					otp_credentials_callback);
}

static void mech_otp_verify(struct auth_request *auth_request,
			    const char *data, bool hex)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;
	struct otp_state *state = &request->state;
	unsigned char hash[OTP_HASH_SIZE], cur_hash[OTP_HASH_SIZE];
	int ret;

	ret = otp_parse_response(data, hash, hex);
	if (ret < 0) {
		e_error(request->auth_request.mech_event,
			"invalid response");
		auth_request_fail(auth_request);
		otp_unlock(auth_request);
		return;
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

static void mech_otp_verify_init(struct auth_request *auth_request,
				 const char *data, bool hex)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;
	struct otp_state new_state;
	unsigned char hash[OTP_HASH_SIZE], cur_hash[OTP_HASH_SIZE];
	const char *error;
	int ret;

	ret = otp_parse_init_response(data, &new_state, cur_hash, hex, &error);
	if (ret < 0) {
		e_error(request->auth_request.mech_event,
			"invalid init response, %s", error);
		auth_request_fail(auth_request);
		otp_unlock(auth_request);
		return;
	}

	otp_next_hash(request->state.algo, cur_hash, hash);

	ret = memcmp(hash, request->state.hash, OTP_HASH_SIZE);
	if (ret != 0) {
		auth_request_fail(auth_request);
		otp_unlock(auth_request);
		return;
	}

	auth_request_set_credentials(auth_request, "OTP",
				     otp_print_dbentry(&new_state),
				     otp_set_credentials_callback);
}

static void
mech_otp_auth_phase2(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size)
{
	if (auth_request_fail_on_nuls(auth_request, data, data_size))
		return;

	const char *str = t_strndup(data, data_size);

	if (str_begins(str, "hex:")) {
		mech_otp_verify(auth_request, str + 4, TRUE);
	} else if (str_begins(str, "word:")) {
		mech_otp_verify(auth_request, str + 5, FALSE);
	} else if (str_begins(str, "init-hex:")) {
		mech_otp_verify_init(auth_request, str + 9, TRUE);
	} else if (str_begins(str, "init-word:")) {
		mech_otp_verify_init(auth_request, str + 10, FALSE);
	} else {
		e_error(auth_request->mech_event,
			"unsupported response type");
		auth_request_fail(auth_request);
		otp_unlock(auth_request);
	}
}

static void
mech_otp_auth_continue(struct auth_request *auth_request,
		       const unsigned char *data, size_t data_size)
{
	if (auth_request->user == NULL) {
		mech_otp_auth_phase1(auth_request, data, data_size);
	} else {
		mech_otp_auth_phase2(auth_request, data, data_size);
	}
}

static struct auth_request *mech_otp_auth_new(void)
{
	struct otp_auth_request *request;
	pool_t pool;

	otp_lock_init();

	pool = pool_alloconly_create(MEMPOOL_GROWING"otp_auth_request", 2048);
	request = p_new(pool, struct otp_auth_request, 1);
	request->pool = pool;
	request->lock = FALSE;

	request->auth_request.refcount = 1;
	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_otp = {
	"OTP",

	.flags = MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE | MECH_SEC_ALLOW_NULS,
	.passdb_need = MECH_PASSDB_NEED_SET_CREDENTIALS,

	mech_otp_auth_new,
	mech_generic_auth_initial,
	mech_otp_auth_continue,
	mech_otp_skey_auth_free
};
