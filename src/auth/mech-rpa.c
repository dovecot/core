/*
 * Compuserve RPA authentication mechanism.
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
	unsigned char *pwd_md5;
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
	unsigned char *session_key;
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
static void rpa_user_response(struct rpa_auth_request *auth,
			      unsigned char *digest)
{
	struct md5_context ctx;
	unsigned char z[48];

	memset(z, 0, sizeof(z));

	md5_init(&ctx);
	md5_update(&ctx, auth->pwd_md5, 16);
	md5_update(&ctx, z, sizeof(z));
	md5_update(&ctx, auth->username_ucs2be, auth->username_len);
	md5_update(&ctx, auth->service_ucs2be, auth->service_len);
	md5_update(&ctx, auth->realm_ucs2be, auth->realm_len);
	md5_update(&ctx, auth->user_challenge, auth->user_challenge_len);
	md5_update(&ctx, auth->service_challenge, RPA_SCHALLENGE_LEN);
	md5_update(&ctx, auth->service_timestamp, RPA_TIMESTAMP_LEN);
	md5_update(&ctx, auth->pwd_md5, 16);
	md5_final(&ctx, digest);
}

/*
 * Compute server -> client authentication response.
 */
static void rpa_server_response(struct rpa_auth_request *auth,
				unsigned char *digest)
{
	struct md5_context ctx;
	unsigned char tmp[16];
	unsigned char z[48];
	int i;

	memset(z, 0, sizeof(z));

	md5_init(&ctx);
	md5_update(&ctx, auth->pwd_md5, 16);
	md5_update(&ctx, z, sizeof(z));
	md5_update(&ctx, auth->service_ucs2be, auth->service_len);
	md5_update(&ctx, auth->username_ucs2be, auth->username_len);
	md5_update(&ctx, auth->realm_ucs2be, auth->realm_len);
	md5_update(&ctx, auth->service_challenge, RPA_SCHALLENGE_LEN);
	md5_update(&ctx, auth->user_challenge, auth->user_challenge_len);
	md5_update(&ctx, auth->service_timestamp, RPA_TIMESTAMP_LEN);
	md5_update(&ctx, auth->pwd_md5, 16);
	md5_final(&ctx, tmp);

	for (i = 0; i < 16; i++)
		tmp[i] = auth->session_key[i] ^ tmp[i];

	md5_init(&ctx);
	md5_update(&ctx, auth->pwd_md5, 16);
	md5_update(&ctx, z, sizeof(z));
	md5_update(&ctx, auth->service_ucs2be, auth->service_len);
	md5_update(&ctx, auth->username_ucs2be, auth->username_len);
	md5_update(&ctx, auth->realm_ucs2be, auth->realm_len);
	md5_update(&ctx, auth->session_key, 16);
	md5_update(&ctx, auth->service_challenge, RPA_SCHALLENGE_LEN);
	md5_update(&ctx, auth->user_challenge, auth->user_challenge_len);
	md5_update(&ctx, auth->service_timestamp, RPA_TIMESTAMP_LEN);
	md5_update(&ctx, tmp, 16);
	md5_update(&ctx, auth->pwd_md5, 16);
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

static int
rpa_parse_token1(const void *data, size_t data_size, const char **error)
{
	const unsigned char *end = ((unsigned char *) data) + data_size;
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

static char *
rpa_parse_username(pool_t pool, const char *username)
{
	const char *p = strrchr(username, '@');

	return p == NULL ? p_strdup(pool, username) :
		p_strdup_until(pool, username, p);
}

static int
rpa_parse_token3(struct rpa_auth_request *auth, const void *data,
		 size_t data_size, const char **error)
{
	struct auth_request *auth_request = (struct auth_request *)auth;
	const unsigned char *end = ((unsigned char *)data) + data_size;
	const unsigned char *p;
	unsigned int len;
	const char *user;

	p = rpa_check_message(data, end, error);
	if (p == NULL)
		return FALSE;

	/* Read username@realm */
	if (p + 2 > end) {
		*error = "message too short";
		return FALSE;
	}

	len = (p[0] >> 8) + p[1];
	if (p + 2 + len > end) {
		*error = "message too short";
		return FALSE;
	}
	p += 2;

	user = t_strndup(p, len);
	p += len;

	auth_request->user = rpa_parse_username(auth->pool, user);

	auth->username_ucs2be = ucs2be_str(auth->pool, auth_request->user,
					   &auth->username_len);

	/* Read user challenge */
	auth->user_challenge_len = rpa_read_buffer(auth->pool, &p, end,
						   &auth->user_challenge);
	if (auth->user_challenge_len == 0) {
		*error = "invalid user challenge";
		return FALSE;
	}

	/* Read user response */
	len = rpa_read_buffer(auth->pool, &p, end, &auth->user_response);
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

static const char *
mech_rpa_build_token2(struct rpa_auth_request *auth,
		      const char *realms, size_t *size)
{
	unsigned int realms_len;
	unsigned int length;
	buffer_t *buf;
	unsigned char timestamp[RPA_TIMESTAMP_LEN / 2];

	realms_len = strlen(realms);
        length = sizeof(rpa_oid) + 3 + RPA_SCHALLENGE_LEN +
		RPA_TIMESTAMP_LEN + 2 + realms_len;

	buf = buffer_create_dynamic(auth->pool, length + 4, (size_t)-1);

	buffer_append_c(buf, ASN1_APPLICATION);
	buffer_append_asn1_length(buf, length);
	buffer_append(buf, rpa_oid, sizeof(rpa_oid));

	/* Protocol version */
	buffer_append_c(buf, 3);
	buffer_append_c(buf, 0);

	/* Service challenge */
	auth->service_challenge = p_malloc(auth->pool, RPA_SCHALLENGE_LEN);
	random_fill(auth->service_challenge, RPA_SCHALLENGE_LEN);
	buffer_append_c(buf, RPA_SCHALLENGE_LEN);
	buffer_append(buf, auth->service_challenge, RPA_SCHALLENGE_LEN);

	/* Timestamp, looks like clients accept anything we send */
	random_fill(timestamp, sizeof(timestamp));
	auth->service_timestamp = p_malloc(auth->pool, RPA_TIMESTAMP_LEN);
	memcpy(auth->service_timestamp,
	       binary_to_hex(timestamp, sizeof(timestamp)),
	       RPA_TIMESTAMP_LEN);
	buffer_append(buf, auth->service_timestamp, RPA_TIMESTAMP_LEN);

	/* Realm list */
	buffer_append_c(buf, realms_len >> 8);
	buffer_append_c(buf, realms_len & 0xff);
	buffer_append(buf, realms, realms_len);

	*size = buffer_get_used_size(buf);
	return buffer_free_without_data(buf);
}

static const char *
mech_rpa_build_token4(struct rpa_auth_request *auth, size_t *size)
{
	unsigned int length = sizeof(rpa_oid) + 17 + 17 + 1;
	buffer_t *buf;
	unsigned char server_response[16];

	buf = buffer_create_dynamic(auth->pool, length + 4, (size_t)-1);

	buffer_append_c(buf, ASN1_APPLICATION);
	buffer_append_asn1_length(buf, length);
	buffer_append(buf, rpa_oid, sizeof(rpa_oid));

	/* Generate random session key */
	auth->session_key = p_malloc(auth->pool, 16);
	random_fill(auth->session_key, 16);

	/* Server authentication response */
	rpa_server_response(auth, server_response);
	buffer_append_c(buf, 16);
	buffer_append(buf, server_response, 16);

	buffer_append_c(buf, 16);
	buffer_append(buf, auth->session_key, 16);

	/* Status, 0 - success */
	buffer_append_c(buf, 0);

	*size = buffer_get_used_size(buf);
	return buffer_free_without_data(buf);
}

static void
rpa_credentials_callback(const char *credentials,
			 struct auth_request *auth_request)
{
	struct rpa_auth_request *auth =
		(struct rpa_auth_request *)auth_request;
	buffer_t *hash_buffer;

	if (credentials == NULL)
		return;

	auth->pwd_md5 = p_malloc(auth->pool, 16);

	hash_buffer = buffer_create_data(auth->pool, auth->pwd_md5, 16);

	hex_to_binary(credentials, hash_buffer);
}

static int
mech_rpa_auth_phase1(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size,
		     mech_callback_t *callback)
{
	struct rpa_auth_request *auth =
		(struct rpa_auth_request *)auth_request;
	struct auth_client_request_reply reply;
	const unsigned char *token2;
	size_t token2_size;
	const char *service, *error;

	if (!rpa_parse_token1(data, data_size, &error)) {
		if (verbose) {
			i_info("rpa(%s): invalid token 1, %s",
			       get_log_prefix(auth_request), error);
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	service = t_str_lcase(auth_request->protocol);

	token2 = mech_rpa_build_token2(auth, t_strconcat(service, "@",
				       my_hostname, NULL), &token2_size);

	auth->service_ucs2be = ucs2be_str(auth->pool, service,
					  &auth->service_len);
	auth->realm_ucs2be = ucs2be_str(auth->pool, my_hostname,
					&auth->realm_len);

	mech_init_auth_client_reply(&reply);
	reply.id = auth_request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	reply.reply_idx = 0;
	reply.data_size = token2_size;
	callback(&reply, token2, auth_request->conn);

	auth->phase = 1;

	return TRUE;
}

static int
mech_rpa_auth_phase2(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size,
		     mech_callback_t *callback)
{
	struct rpa_auth_request *auth =
		(struct rpa_auth_request *)auth_request;
	struct auth_client_request_reply reply;
	unsigned char response[16];
	const unsigned char *token4;
	const char *error;
	size_t token4_size;

	if (!rpa_parse_token3(auth, data, data_size, &error)) {
		if (verbose) {
			i_info("rpa(%s): invalid token 3, %s",
			       get_log_prefix(auth_request), error);
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	if (!mech_fix_username(auth_request->user, &error)) {
		if (verbose) {
			i_info("rpa(%s): %s",
			       get_log_prefix(auth_request), error);
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	passdb->lookup_credentials(auth_request, PASSDB_CREDENTIALS_RPA,
				   rpa_credentials_callback);
	if (auth->pwd_md5 == NULL) {
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	rpa_user_response(auth, response);
	if (memcmp(response, auth->user_response, 16) != 0) {
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	token4 = mech_rpa_build_token4(auth, &token4_size);

	mech_init_auth_client_reply(&reply);
	reply.id = auth_request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	reply.reply_idx = 0;
	reply.data_size = token4_size;
	callback(&reply, token4, auth_request->conn);

	auth->phase = 2;

	return TRUE;
}

static int
mech_rpa_auth_phase3(struct auth_request *auth_request,
		     const unsigned char *data, size_t data_size,
		     mech_callback_t *callback __attr_unused__)
{
	static const unsigned char client_ack[3] = { 0x60, 0x01, 0x00 };
	int ret = TRUE;

	if ((data_size != sizeof(client_ack)) ||
	    (memcmp(data, client_ack, sizeof(client_ack)) != 0)) {
		if (verbose) {
			i_info("rpa(%s): invalid token 5 or client rejects us",
			       get_log_prefix(auth_request));
		}
		ret = FALSE;
	}

	mech_auth_finish(auth_request, NULL, 0, ret);
	return TRUE;
}

static int
mech_rpa_auth_continue(struct auth_request *auth_request,
			const unsigned char *data, size_t data_size,
			mech_callback_t *callback)
{
	struct rpa_auth_request *auth =
		(struct rpa_auth_request *)auth_request;

	auth_request->callback = callback;

	switch (auth->phase) {
		case 0:	return mech_rpa_auth_phase1(auth_request, data,
						    data_size, callback);
		case 1:	return mech_rpa_auth_phase2(auth_request, data,
						    data_size, callback);
		case 2:	return mech_rpa_auth_phase3(auth_request, data,
						    data_size, callback);
	}

	mech_auth_finish(auth_request, NULL, 0, FALSE);
	return TRUE;
}

static int
mech_rpa_auth_initial(struct auth_request *auth_request,
		      struct auth_client_request_new *request,
		      const unsigned char *data __attr_unused__,
		      mech_callback_t *callback)
{
	struct auth_client_request_reply reply;

	mech_init_auth_client_reply(&reply);
	reply.id = request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	reply.reply_idx = 0;
	reply.data_size = 0;
	callback(&reply, "", auth_request->conn);

	return TRUE;
}

static void
mech_rpa_auth_free(struct auth_request *auth_request)
{
	struct rpa_auth_request *auth =
		(struct rpa_auth_request *)auth_request;

	if (auth->pwd_md5 != NULL)
		safe_memset(auth->pwd_md5, 0, 16);

	pool_unref(auth_request->pool);
}

static struct auth_request *mech_rpa_auth_new(void)
{
	struct rpa_auth_request *auth;
	pool_t pool;

	pool = pool_alloconly_create("rpa_auth_request", 256);
	auth = p_new(pool, struct rpa_auth_request, 1);
	auth->pool = pool;
	auth->phase = 0;

	auth->auth_request.refcount = 1;
	auth->auth_request.pool = pool;
	auth->auth_request.auth_initial = mech_rpa_auth_initial;
	auth->auth_request.auth_continue = mech_rpa_auth_continue;
	auth->auth_request.auth_free = mech_rpa_auth_free;

	return &auth->auth_request;
}

const struct mech_module mech_rpa = {
	"RPA",

	MEMBER(plaintext) FALSE,
	MEMBER(advertise) TRUE,

	MEMBER(passdb_need_plain) FALSE,
	MEMBER(passdb_need_credentials) TRUE,

	mech_rpa_auth_new,
};
