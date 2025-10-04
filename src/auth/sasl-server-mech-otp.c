/*
 * One-Time-Password (RFC 2444) authentication mechanism.
 *
 * Copyright (c) 2006 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "safe-memset.h"
#include "hash.h"
#include "hex-binary.h"
#include "otp.h"

#include "sasl-server-protected.h"

struct otp_auth_request {
	struct sasl_server_mech_request auth_request;

	bool lock;

	struct otp_state state;
};

struct otp_auth_mech_data {
	struct sasl_server_mech_data data;

	HASH_TABLE(const char *, struct otp_auth_request *) lock_table;
};

/*
 * Locking
 */

static bool otp_try_lock(struct otp_auth_request *request)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	struct otp_auth_mech_data *otp_mdata =
		container_of(auth_request->mech->data,
			     struct otp_auth_mech_data, data);

	i_assert(auth_request->authid != NULL);
	if (hash_table_lookup(otp_mdata->lock_table,
			      auth_request->authid) != NULL)
		return FALSE;

	hash_table_insert(otp_mdata->lock_table, auth_request->authid, request);
	request->lock = TRUE;
	return TRUE;
}

static void otp_unlock(struct otp_auth_request *request)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	struct otp_auth_mech_data *otp_mdata =
		container_of(auth_request->mech->data,
			     struct otp_auth_mech_data, data);

	if (!request->lock)
		return;

	i_assert(auth_request->authid != NULL);
	hash_table_remove(otp_mdata->lock_table, auth_request->authid);
	request->lock = FALSE;
}

/*
 * Authentication
 */

static void
otp_send_challenge(struct otp_auth_request *request,
		   const unsigned char *credentials, size_t size)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	const char *answer;

	if (otp_parse_dbentry(t_strndup(credentials, size),
			      &request->state) != 0) {
		e_error(auth_request->event, "invalid OTP data in passdb");
		sasl_server_request_failure(auth_request);
		return;
	}

	if (--request->state.seq < 1) {
		e_error(auth_request->event, "sequence number < 1");
		sasl_server_request_failure(auth_request);
		return;
	}

	if (!otp_try_lock(request)) {
		e_error(auth_request->event, "user is locked, race attack?");
		sasl_server_request_failure(auth_request);
		return;
	}

	answer = p_strdup_printf(auth_request->pool, "otp-%s %u %s ext",
				 digest_name(request->state.algo),
				 request->state.seq, request->state.seed);

	sasl_server_request_output(auth_request, answer, strlen(answer));
}

static void
otp_credentials_callback(struct sasl_server_mech_request *auth_request,
			 const struct sasl_passdb_result *result)
{
	struct otp_auth_request *request =
		container_of(auth_request, struct otp_auth_request,
			     auth_request);

	switch (result->status) {
	case SASL_PASSDB_RESULT_OK:
		otp_send_challenge(request, result->credentials.data,
				   result->credentials.size);
		break;
	case SASL_PASSDB_RESULT_INTERNAL_FAILURE:
		sasl_server_request_internal_failure(auth_request);
		break;
	default:
		sasl_server_request_failure(auth_request);
		break;
	}
}

static void
mech_otp_auth_phase1(struct otp_auth_request *request,
		     const unsigned char *data, size_t data_size)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	const char *authenid;
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
		e_info(auth_request->event, "invalid input");
		sasl_server_request_failure(auth_request);
		return;
	}

	if (!sasl_server_request_set_authid(
			auth_request, SASL_SERVER_AUTHID_TYPE_USERNAME,
			authenid)) {
		sasl_server_request_failure(auth_request);
		return;
	}

	sasl_server_request_lookup_credentials(auth_request, "OTP",
					       otp_credentials_callback);
}

static void
otp_set_credentials_callback(struct sasl_server_mech_request *auth_request,
			     const struct sasl_passdb_result *result)
{
	struct otp_auth_request *request =
		container_of(auth_request, struct otp_auth_request,
			     auth_request);

	if (result->status == SASL_PASSDB_RESULT_OK)
		sasl_server_request_success(auth_request, "", 0);
	else
		sasl_server_request_internal_failure(auth_request);

	otp_unlock(request);
}

static void
mech_otp_verify(struct otp_auth_request *request, const char *data, bool hex)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	struct otp_state *state = &request->state;
	unsigned char hash[OTP_HASH_SIZE], cur_hash[OTP_HASH_SIZE];
	int ret;

	ret = otp_parse_response(data, hash, hex);
	if (ret < 0) {
		e_info(auth_request->event, "invalid response");
		sasl_server_request_failure(auth_request);
		otp_unlock(request);
		return;
	}

	otp_next_hash(state->algo, hash, cur_hash);

	ret = memcmp(cur_hash, state->hash, OTP_HASH_SIZE);
	if (ret != 0) {
		sasl_server_request_password_mismatch(auth_request);
		otp_unlock(request);
		return;
	}

	memcpy(state->hash, hash, sizeof(state->hash));

	sasl_server_request_set_credentials(auth_request, "OTP",
					    otp_print_dbentry(state),
					    otp_set_credentials_callback);
}

static void
mech_otp_verify_init(struct otp_auth_request *request, const char *data,
		     bool hex)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	struct otp_state new_state;
	unsigned char hash[OTP_HASH_SIZE], cur_hash[OTP_HASH_SIZE];
	const char *error;
	int ret;

	ret = otp_parse_init_response(data, &new_state, cur_hash, hex, &error);
	if (ret < 0) {
		e_info(auth_request->event, "invalid init response, %s", error);
		sasl_server_request_failure(auth_request);
		otp_unlock(request);
		return;
	}

	otp_next_hash(request->state.algo, cur_hash, hash);

	ret = memcmp(hash, request->state.hash, OTP_HASH_SIZE);
	if (ret != 0) {
		sasl_server_request_password_mismatch(auth_request);
		otp_unlock(request);
		return;
	}

	sasl_server_request_set_credentials(auth_request, "OTP",
					    otp_print_dbentry(&new_state),
					    otp_set_credentials_callback);
}

static void
mech_otp_auth_phase2(struct otp_auth_request *request,
		     const unsigned char *data, size_t data_size)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	const char *value, *str = t_strndup(data, data_size);

	if (str_begins(str, "hex:", &value))
		mech_otp_verify(request, value, TRUE);
	else if (str_begins(str, "word:", &value))
		mech_otp_verify(request, value, FALSE);
	else if (str_begins(str, "init-hex:", &value))
		mech_otp_verify_init(request, value, TRUE);
	else if (str_begins(str, "init-word:", &value))
		mech_otp_verify_init(request, value, FALSE);
	else {
		e_info(auth_request->event, "unsupported response type");
		sasl_server_request_failure(auth_request);
		otp_unlock(request);
	}
}

static void
mech_otp_auth_continue(struct sasl_server_mech_request *auth_request,
		       const unsigned char *data, size_t data_size)
{
	struct otp_auth_request *request =
		container_of(auth_request, struct otp_auth_request,
			     auth_request);

	if (auth_request->authid == NULL)
		mech_otp_auth_phase1(request, data, data_size);
	else
		mech_otp_auth_phase2(request, data, data_size);
}

static struct sasl_server_mech_request *
mech_otp_auth_new(const struct sasl_server_mech *mech ATTR_UNUSED, pool_t pool)
{
	struct otp_auth_request *request;

	request = p_new(pool, struct otp_auth_request, 1);
	request->lock = FALSE;

	return &request->auth_request;
}

static void mech_otp_auth_free(struct sasl_server_mech_request *auth_request)
{
	struct otp_auth_request *request =
		container_of(auth_request, struct otp_auth_request,
			     auth_request);

	otp_unlock(request);
}

/*
 * Mechanism
 */

static struct sasl_server_mech_data *mech_otp_data_new(pool_t pool)
{
	struct otp_auth_mech_data *otp_mdata;

	otp_mdata = p_new(pool, struct otp_auth_mech_data, 1);
	hash_table_create(&otp_mdata->lock_table, default_pool, 128,
			  strcase_hash, strcasecmp);

	return &otp_mdata->data;
}

static void mech_otp_data_free(struct sasl_server_mech_data *mdata)
{
	struct otp_auth_mech_data *otp_mdata =
		container_of(mdata, struct otp_auth_mech_data, data);

	hash_table_destroy(&otp_mdata->lock_table);
}

static const struct sasl_server_mech_funcs mech_otp_funcs = {
	.auth_new = mech_otp_auth_new,
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_otp_auth_continue,
	.auth_free = mech_otp_auth_free,

	.data_new = mech_otp_data_new,
	.data_free = mech_otp_data_free,
};

static const struct sasl_server_mech_def mech_otp = {
	.name = SASL_MECH_NAME_OTP,

	.flags = SASL_MECH_SEC_DICTIONARY | SASL_MECH_SEC_ACTIVE |
		 SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_SET_CREDENTIALS,

	.funcs = &mech_otp_funcs,
};

void sasl_server_mech_register_otp(struct sasl_server_instance *sinst)
{
	sasl_server_mech_register(sinst, &mech_otp, NULL);
}
