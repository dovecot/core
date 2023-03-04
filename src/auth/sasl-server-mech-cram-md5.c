/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* CRAM-MD5 SASL authentication, see RFC-2195
   Joshua Goodall <joshua@roughtrade.net> */

#include "auth-common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hex-binary.h"
#include "hmac-cram-md5.h"
#include "hmac.h"
#include "md5.h"
#include "randgen.h"
#include "hostpid.h"

#include "sasl-server-protected.h"

#include <time.h>

struct cram_auth_request {
	struct auth_request auth_request;

	/* requested: */
	char *challenge;

	/* received: */
	char *username;
	char *response;
	unsigned long maxbuf;
};

static const char *get_cram_challenge(void)
{
	unsigned char buf[17];
	size_t i;

	random_fill(buf, sizeof(buf)-1);

	for (i = 0; i < sizeof(buf)-1; i++)
		buf[i] = (buf[i] % 10) + '0';
	buf[sizeof(buf)-1] = '\0';

	return t_strdup_printf("<%s.%s@%s>", (const char *)buf,
			       dec2str(ioloop_time), my_hostname);
}

static void
verify_credentials(struct auth_request *auth_request,
		   const unsigned char *credentials, size_t size)
{
	struct cram_auth_request *request =
		container_of(auth_request, struct cram_auth_request,
			     auth_request);
	unsigned char digest[MD5_RESULTLEN];
        struct hmac_context ctx;
	const char *response_hex;

	if (size != CRAM_MD5_CONTEXTLEN) {
		e_error(auth_request->mech_event, "invalid credentials length");
		sasl_server_request_failure(auth_request);
		return;
	}

	hmac_init(&ctx, NULL, 0, &hash_method_md5);
	hmac_md5_set_cram_context(&ctx, credentials);
	hmac_update(&ctx, request->challenge, strlen(request->challenge));
	hmac_final(&ctx, digest);

	response_hex = binary_to_hex(digest, sizeof(digest));

	if (!mem_equals_timing_safe(response_hex, request->response,
				    sizeof(digest) * 2)) {
		e_info(auth_request->mech_event,
		       AUTH_LOG_MSG_PASSWORD_MISMATCH);
		sasl_server_request_failure(auth_request);
		return;
	}

	sasl_server_request_success(auth_request, "", 0);
}

static bool
parse_cram_response(struct cram_auth_request *request,
		    const unsigned char *data, size_t size)
{
	struct auth_request *auth_request = &request->auth_request;
	size_t i, space;

	/* <username> SPACE <response>. Username may contain spaces, so assume
	   the rightmost space is the response separator. */
	for (i = space = 0; i < size; i++) {
		if (data[i] == '\0') {
			e_info(auth_request->mech_event, "NULs in response");
			return FALSE;
		}
		if (data[i] == ' ')
			space = i;
	}

	if (space == 0) {
		e_info(auth_request->mech_event, "missing digest");
		return FALSE;
	}

	request->username = p_strndup(auth_request->pool, data, space);
	space++;
	request->response =
		p_strndup(auth_request->pool, data + space, size - space);
	return TRUE;
}

static void
credentials_callback(enum passdb_result result,
		     const unsigned char *credentials, size_t size,
		     struct auth_request *auth_request)
{
	switch (result) {
	case SASL_PASSDB_RESULT_OK:
		verify_credentials(auth_request, credentials, size);
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
mech_cram_md5_auth_continue(struct auth_request *auth_request,
			    const unsigned char *data, size_t data_size)
{
	struct cram_auth_request *request =
		container_of(auth_request, struct cram_auth_request,
			     auth_request);
	const char *error;

	if (!parse_cram_response(request, data, data_size)) {
		sasl_server_request_failure(auth_request);
		return;
	}
	if (!auth_request_set_username(auth_request, request->username,
				       &error)) {
		e_info(auth_request->mech_event, "%s", error);
		sasl_server_request_failure(auth_request);
		return;
	}

	sasl_server_request_lookup_credentials(auth_request, "CRAM-MD5",
					       credentials_callback);
}

static void
mech_cram_md5_auth_initial(struct auth_request *auth_request,
			   const unsigned char *data ATTR_UNUSED,
			   size_t data_size ATTR_UNUSED)
{
	struct cram_auth_request *request =
		container_of(auth_request, struct cram_auth_request,
			     auth_request);

	request->challenge = p_strdup(auth_request->pool, get_cram_challenge());
	sasl_server_request_output(auth_request, request->challenge,
				   strlen(request->challenge));
}

static struct auth_request *mech_cram_md5_auth_new(void)
{
	struct cram_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"cram_md5_auth_request", 2048);
	request = p_new(pool, struct cram_auth_request, 1);

	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_cram_md5 = {
	.mech_name = "CRAM-MD5",

	.flags = SASL_MECH_SEC_DICTIONARY | SASL_MECH_SEC_ACTIVE,
	.passdb_need = MECH_PASSDB_NEED_VERIFY_RESPONSE,

	.auth_new = mech_cram_md5_auth_new,
	.auth_initial = mech_cram_md5_auth_initial,
	.auth_continue = mech_cram_md5_auth_continue,
        .auth_free = sasl_server_mech_generic_auth_free,
};
