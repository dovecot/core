/*
 * Compuserve RPA authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "mech.h"
#include "passdb.h"
#include "str.h"
#include "strfuncs.h"
#include "safe-memset.h"
#include "randgen.h"
#include "buffer.h"
#include "hostpid.h"
#include "hex-binary.h"
#include "md5.h"

struct rpa_auth_request {
	struct auth_request auth_request;

	pool_t pool;

	int phase;

	/* cached: */
	unsigned char pwd_md5[MD5_RESULTLEN];
	size_t service_len;
	const unsigned char *service_ucs2be;
	size_t username_len;
	const unsigned char *username_ucs2be;
	size_t realm_len;
	const unsigned char *realm_ucs2be;

	/* requested: */
	unsigned char *service_challenge;
	unsigned char *service_timestamp;

	/* received: */
	unsigned int user_challenge_len;
	unsigned char *user_challenge;
	unsigned char *user_response;
	unsigned char session_key[16];
};

#define RPA_SCHALLENGE_LEN	32
#define RPA_UCHALLENGE_LEN	16
#define RPA_TIMESTAMP_LEN	14

#define ASN1_APPLICATION	0x60

/* Object id encoded using ASN.1 DER */
static const unsigned char rpa_oid[] = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x73, 0x01, 0x01
};

void *ucs2be_str(pool_t pool, const char *str, size_t *size);

/*
 * Compute client -> server authentication response.
 */
static void rpa_user_response(struct rpa_auth_request *request,
			      unsigned char digest[STATIC_ARRAY MD5_RESULTLEN])
{
	struct md5_context ctx;
	unsigned char z[48];

	memset(z, 0, sizeof(z));

	md5_init(&ctx);
	md5_update(&ctx, request->pwd_md5, sizeof(request->pwd_md5));
	md5_update(&ctx, z, sizeof(z));
	md5_update(&ctx, request->username_ucs2be, request->username_len);
	md5_update(&ctx, request->service_ucs2be, request->service_len);
	md5_update(&ctx, request->realm_ucs2be, request->realm_len);
	md5_update(&ctx, request->user_challenge, request->user_challenge_len);
	md5_update(&ctx, request->service_challenge, RPA_SCHALLENGE_LEN);
	md5_update(&ctx, request->service_timestamp, RPA_TIMESTAMP_LEN);
	md5_update(&ctx, request->pwd_md5, sizeof(request->pwd_md5));
	md5_final(&ctx, digest);
}

/*
 * Compute server -> client authentication response.
 */
static void rpa_server_response(struct rpa_auth_request *request,
				unsigned char digest[STATIC_ARRAY MD5_RESULTLEN])
{
	struct md5_context ctx;
	unsigned char tmp[MD5_RESULTLEN];
	unsigned char z[48];
	unsigned int i;

	memset(z, 0, sizeof(z));

	md5_init(&ctx);
	md5_update(&ctx, request->pwd_md5, sizeof(request->pwd_md5));
	md5_update(&ctx, z, sizeof(z));
	md5_update(&ctx, request->service_ucs2be, request->service_len);
	md5_update(&ctx, request->username_ucs2be, request->username_len);
	md5_update(&ctx, request->realm_ucs2be, request->realm_len);
	md5_update(&ctx, request->service_challenge, RPA_SCHALLENGE_LEN);
	md5_update(&ctx, request->user_challenge, request->user_challenge_len);
	md5_update(&ctx, request->service_timestamp, RPA_TIMESTAMP_LEN);
	md5_update(&ctx, request->pwd_md5, sizeof(request->pwd_md5));
	md5_final(&ctx, tmp);

	for (i = 0; i < sizeof(tmp); i++)
		tmp[i] = request->session_key[i] ^ tmp[i];

	md5_init(&ctx);
	md5_update(&ctx, request->pwd_md5, sizeof(request->pwd_md5));
	md5_update(&ctx, z, sizeof(z));
	md5_update(&ctx, request->service_ucs2be, request->service_len);
	md5_update(&ctx, request->username_ucs2be, request->username_len);
	md5_update(&ctx, request->realm_ucs2be, request->realm_len);
	md5_update(&ctx, request->session_key, sizeof(request->session_key));
	md5_update(&ctx, request->service_challenge, RPA_SCHALLENGE_LEN);
	md5_update(&ctx, request->user_challenge, request->user_challenge_len);
	md5_update(&ctx, request->service_timestamp, RPA_TIMESTAMP_LEN);
	md5_update(&ctx, tmp, sizeof(tmp));
	md5_update(&ctx, request->pwd_md5, sizeof(request->pwd_md5));
	md5_final(&ctx, digest);
}

static const unsigned char *
rpa_check_message(const unsigned char *data, const unsigned char *end,
		  const char **error)
{
	const unsigned char *p = data;
	unsigned int len = 0;

	if (p + 2 > end) {
		*error = "message too short";
		return NULL;
	}

	if (*p++ != ASN1_APPLICATION) {
		*error = "invalid data type";
		return NULL;
	}

	if ((*p & 0x80) != 0) {
		unsigned int nbytes = *p++ & 0x7f;

		while (nbytes-- > 0) {
			if (p >= end) {
				*error = "invalid structure length";
				return NULL;
			}

			len = (len << 8) | *p++;
		}
	} else
		len = *p++;

	if ((size_t)(end - p) != len) {
		*error = "structure length disagrees with data size";
		return NULL;
	}

	if (p + sizeof(rpa_oid) > end) {
		*error = "not enough space for object id";
		return NULL;
	}

	if (memcmp(p, rpa_oid, sizeof(rpa_oid)) != 0) {
		*error = "invalid object id";
		return NULL;
	}

	return p + sizeof(rpa_oid);
}

static bool
rpa_parse_token1(const void *data, size_t data_size, const char **error)
{
	const unsigned char *end = ((const unsigned char *) data) + data_size;
	const unsigned char *p;
	unsigned int version_lo, version_hi;

	p = rpa_check_message(data, end, error);
	if (p == NULL)
		return FALSE;

	if (p + 6 > end) {
		*error = "message too short";
		return FALSE;
	}

	version_lo = p[0] + (p[1] << 8);
	version_hi = p[2] + (p[3] << 8);

	if ((version_lo > 3) || (version_hi < 3)) {
		*error = "protocol version mismatch";
		return FALSE;
	}
	p += 4;

	if ((p[0] != 0) || (p[1] != 1)) {
		*error = "invalid message flags";
		return FALSE;
	}
	p += 2;

	if (p != end) {
		*error = "unneeded data found";
		return FALSE;
	}

	return TRUE;
}

static unsigned int
rpa_read_buffer(pool_t pool, const unsigned char **data,
		const unsigned char *end, unsigned char **buffer)
{
	const unsigned char *p = *data;
	unsigned int len;

	if (p > end)
		return 0;

	len = *p++;
	if (p + len > end)
		return 0;

	*buffer = p_malloc(pool, len);
	memcpy(*buffer, p, len);

	*data += 1 + len;

	return len;
}

static bool
rpa_parse_token3(struct rpa_auth_request *request, const void *data,
		 size_t data_size, const char **error)
{
	struct auth_request *auth_request = &request->auth_request;
	const unsigned char *end = ((const unsigned char *)data) + data_size;
	const unsigned char *p;
	unsigned int len;
	const char *user, *realm;

	p = rpa_check_message(data, end, error);
	if (p == NULL)
		return FALSE;

	/* Read username@realm */
	if (p + 2 > end) {
		*error = "message too short";
		return FALSE;
	}

	len = (p[0] << 8) + p[1];
	if (p + 2 + len > end) {
		*error = "message too short";
		return FALSE;
	}
	p += 2;

	user = t_strndup(p, len);
	realm = strrchr(user, '@');
	if (realm == NULL) {
		*error = "missing realm";
		return FALSE;
	}
	user = t_strdup_until(user, realm++);
	p += len;

	if (!auth_request_set_username(auth_request, user, error))
		return FALSE;

	request->username_ucs2be = ucs2be_str(request->pool, auth_request->user,
					      &request->username_len);
	request->realm_ucs2be = ucs2be_str(request->pool, realm,
					   &request->realm_len);

	/* Read user challenge */
	request->user_challenge_len = rpa_read_buffer(request->pool, &p, end,
						      &request->user_challenge);
	if (request->user_challenge_len == 0) {
		*error = "invalid user challenge";
		return FALSE;
	}

	/* Read user response */
	len = rpa_read_buffer(request->pool, &p, end, &request->user_response);
	if (len != RPA_UCHALLENGE_LEN) {
		*error = "invalid user response";
		return FALSE;
	}

	if (p != end) {
		*error = "unneeded data found";
		return FALSE;
	}

	return TRUE;
}

static void
buffer_append_asn1_length(buffer_t *buf, unsigned int length)
{
	if (length < 0x80) {
		buffer_append_c(buf, length);
	} else if (length < 0x100) {
		buffer_append_c(buf, 0x81);
		buffer_append_c(buf, length);
	} else {
		buffer_append_c(buf, 0x82);
		buffer_append_c(buf, length >> 8);
		buffer_append_c(buf, length & 0xff);
	}
}

static void
rpa_add_realm(string_t *realms, const char *realm, const char *service)
{
	str_append(realms, service);	
	str_append_c(realms, '@');
	str_append(realms, realm);
	str_append_c(realms, ' ');
}

static const unsigned char *
mech_rpa_build_token2(struct rpa_auth_request *request, size_t *size)
{
	const struct auth_settings *set = request->auth_request.set;
	unsigned int realms_len, length;
	string_t *realms;
	buffer_t *buf;
	unsigned char timestamp[RPA_TIMESTAMP_LEN / 2];
	const char *const *tmp;

	realms = t_str_new(64);
	for (tmp = set->realms_arr; *tmp != NULL; tmp++) {
		rpa_add_realm(realms, *tmp, request->auth_request.service);
	}

	if (str_len(realms) == 0) {
		rpa_add_realm(realms, *set->default_realm != '\0' ?
			      set->default_realm : my_hostname,
			      request->auth_request.service);
	}

	realms_len = str_len(realms) - 1;
        length = sizeof(rpa_oid) + 3 + RPA_SCHALLENGE_LEN +
		RPA_TIMESTAMP_LEN + 2 + realms_len;

	buf = buffer_create_dynamic(request->pool, length + 4);

	buffer_append_c(buf, ASN1_APPLICATION);
	buffer_append_asn1_length(buf, length);
	buffer_append(buf, rpa_oid, sizeof(rpa_oid));

	/* Protocol version */
	buffer_append_c(buf, 3);
	buffer_append_c(buf, 0);

	/* Service challenge */
	request->service_challenge =
		p_malloc(request->pool, RPA_SCHALLENGE_LEN);
	random_fill(request->service_challenge, RPA_SCHALLENGE_LEN);
	buffer_append_c(buf, RPA_SCHALLENGE_LEN);
	buffer_append(buf, request->service_challenge, RPA_SCHALLENGE_LEN);

	/* Timestamp, looks like clients accept anything we send */
	random_fill(timestamp, sizeof(timestamp));
	request->service_timestamp = p_malloc(request->pool, RPA_TIMESTAMP_LEN);
	memcpy(request->service_timestamp,
	       binary_to_hex(timestamp, sizeof(timestamp)),
	       RPA_TIMESTAMP_LEN);
	buffer_append(buf, request->service_timestamp, RPA_TIMESTAMP_LEN);

	/* Realm list */
	buffer_append_c(buf, realms_len >> 8);
	buffer_append_c(buf, realms_len & 0xff);
	buffer_append(buf, str_c(realms), realms_len);

	*size = buf->used;
	return buffer_free_without_data(&buf);
}

static const unsigned char *
mech_rpa_build_token4(struct rpa_auth_request *request, size_t *size)
{
	buffer_t *buf;
	unsigned char server_response[MD5_RESULTLEN];
	unsigned int length = sizeof(rpa_oid) +
		sizeof(server_response) + 1 +
		sizeof(request->session_key) + 1 + 1;

	buf = buffer_create_dynamic(request->pool, length + 4);

	buffer_append_c(buf, ASN1_APPLICATION);
	buffer_append_asn1_length(buf, length);
	buffer_append(buf, rpa_oid, sizeof(rpa_oid));

	/* Generate random session key */
	random_fill(request->session_key, sizeof(request->session_key));

	/* Server authentication response */
	rpa_server_response(request, server_response);
	buffer_append_c(buf, sizeof(server_response));
	buffer_append(buf, server_response, sizeof(server_response));

	buffer_append_c(buf, sizeof(request->session_key));
	buffer_append(buf, request->session_key, sizeof(request->session_key));

	/* Status, 0 - success */
	buffer_append_c(buf, 0);

	*size = buf->used;
	return buffer_free_without_data(&buf);
}

static bool verify_credentials(struct rpa_auth_request *request,
			       const unsigned char *credentials, size_t size)
{
	unsigned char response[MD5_RESULTLEN];

	if (size != sizeof(request->pwd_md5)) {
                e_error(request->auth_request.mech_event,
			"invalid credentials length");
		return FALSE;
	}

	memcpy(request->pwd_md5, credentials, sizeof(request->pwd_md5));
	rpa_user_response(request, response);
	return mem_equals_timing_safe(response, request->user_response, sizeof(response));
}

static void
rpa_credentials_callback(enum passdb_result result,
			 const unsigned char *credentials, size_t size,
			 struct auth_request *auth_request)
{
	struct rpa_auth_request *request =
		(struct rpa_auth_request *)auth_request;
	const unsigned char *token4;
	size_t token4_size;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (!verify_credentials(request, credentials, size))
			auth_request_fail(auth_request);
		else {
			token4 = mech_rpa_build_token4(request, &token4_size);
			auth_request_handler_reply_continue(auth_request,
							    token4,
							    token4_size);
			request->phase = 2;
		}
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
mech_rpa_auth_phase1(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size)
{
	struct rpa_auth_request *request =
		(struct rpa_auth_request *)auth_request;
	const unsigned char *token2;
	size_t token2_size;
	const char *service, *error;

	if (!rpa_parse_token1(data, data_size, &error)) {
		e_info(auth_request->mech_event,
		       "invalid token 1: %s", error);
		auth_request_fail(auth_request);
		return;
	}

	service = t_str_lcase(auth_request->service);

	token2 = mech_rpa_build_token2(request, &token2_size);

	request->service_ucs2be = ucs2be_str(request->pool, service,
					     &request->service_len);

	auth_request_handler_reply_continue(auth_request, token2, token2_size);
	request->phase = 1;
}

static void
mech_rpa_auth_phase2(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size)
{
	struct rpa_auth_request *request =
		(struct rpa_auth_request *)auth_request;
	const char *error;

	if (!rpa_parse_token3(request, data, data_size, &error)) {
		e_info(auth_request->mech_event,
		       "invalid token 3: %s", error);
		auth_request_fail(auth_request);
		return;
	}

	auth_request_lookup_credentials(auth_request, "RPA",
					rpa_credentials_callback);
}

static void
mech_rpa_auth_phase3(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size)
{
	static const unsigned char client_ack[3] = { 0x60, 0x01, 0x00 };

	if ((data_size != sizeof(client_ack)) ||
	    (memcmp(data, client_ack, sizeof(client_ack)) != 0)) {
		e_info(auth_request->mech_event,
		       "invalid token 5 or client rejects us");
		auth_request_fail(auth_request);
	} else {
		auth_request_success(auth_request, "", 0);
	}
}

static void
mech_rpa_auth_continue(struct auth_request *auth_request,
		       const unsigned char *data, size_t data_size)
{
	struct rpa_auth_request *request =
		(struct rpa_auth_request *)auth_request;

	switch (request->phase) {
	case 0:
		mech_rpa_auth_phase1(auth_request, data, data_size);
		break;
	case 1:
		mech_rpa_auth_phase2(auth_request, data, data_size);
		break;
	case 2:
		mech_rpa_auth_phase3(auth_request, data, data_size);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

static void
mech_rpa_auth_free(struct auth_request *auth_request)
{
	struct rpa_auth_request *request =
		(struct rpa_auth_request *)auth_request;

	safe_memset(request->pwd_md5, 0, sizeof(request->pwd_md5));

	pool_unref(&auth_request->pool);
}

static struct auth_request *mech_rpa_auth_new(void)
{
	struct rpa_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"rpa_auth_request", 2048);
	request = p_new(pool, struct rpa_auth_request, 1);
	request->pool = pool;
	request->phase = 0;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_rpa = {
	"RPA",

	.flags = MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE |
		MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_rpa_auth_new,
	mech_generic_auth_initial,
	mech_rpa_auth_continue,
	mech_rpa_auth_free
};
