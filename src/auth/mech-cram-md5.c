/* Copyright (C) 2002,2003 Timo Sirainen / Joshua Goodall */

/* CRAM-MD5 SASL authentication, see RFC-2195
   Joshua Goodall <joshua@roughtrade.net> */

#include "common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hex-binary.h"
#include "hmac-md5.h"
#include "randgen.h"
#include "mech.h"
#include "passdb.h"
#include "hostpid.h"

#include <stdlib.h>
#include <time.h>

struct cram_auth_request {
	struct auth_request auth_request;

	pool_t pool;

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

	hostpid_init();
	random_fill(buf, sizeof(buf)-1);

	for (i = 0; i < sizeof(buf)-1; i++)
		buf[i] = (buf[i] % 10) + '0';
	buf[sizeof(buf)-1] = '\0';

	return t_strdup_printf("<%s.%s@%s>", (const char *)buf,
			       dec2str(ioloop_time), my_hostname);
}

static int verify_credentials(struct cram_auth_request *request,
			      const char *credentials)
{
	
	unsigned char digest[16], context_digest[32];
        struct hmac_md5_context ctx;
	buffer_t *context_digest_buf;
	const char *response_hex;

	if (credentials == NULL)
		return FALSE;

	context_digest_buf =
		buffer_create_data(pool_datastack_create(),
				   context_digest, sizeof(context_digest));

	if (hex_to_binary(credentials, context_digest_buf) < 0)
		return FALSE;

	hmac_md5_set_cram_context(&ctx, context_digest);
	hmac_md5_update(&ctx, request->challenge, strlen(request->challenge));
	hmac_md5_final(&ctx, digest);

	response_hex = binary_to_hex(digest, 16);

	if (memcmp(response_hex, request->response, 32) != 0) {
		if (verbose) {
			i_info("cram-md5(%s): password mismatch",
			       get_log_prefix(&request->auth_request));
		}
		return FALSE;
	}

	return TRUE;
}

static int parse_cram_response(struct cram_auth_request *request,
			       const unsigned char *data, size_t size,
			       const char **error_r)
{
	size_t i, space;

	*error_r = NULL;

	/* <username> SPACE <response>. Username may contain spaces, so assume
	   the rightmost space is the response separator. */
	for (i = space = 0; i < size; i++) {
		if (data[i] == ' ')
			space = i;
	}

	if (space == 0) {
		*error_r = "missing digest";
		return FALSE;
	}

	request->username = p_strndup(request->pool, data, space);
	space++;
	request->response =
		p_strndup(request->pool, data + space, size - space);
	return TRUE;
}

static void credentials_callback(const char *result,
				 struct auth_request *auth_request)
{
	struct cram_auth_request *request =
		(struct cram_auth_request *)auth_request;

	if (verify_credentials(request, result))
		mech_auth_finish(auth_request, NULL, 0, TRUE);
	else {
		if (verbose) {
			i_info("cram-md5(%s): authentication failed",
			       get_log_prefix(auth_request));
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
	}
}

static void
mech_cram_md5_auth_continue(struct auth_request *auth_request,
			    const unsigned char *data, size_t data_size,
			    mech_callback_t *callback)
{
	struct cram_auth_request *request =
		(struct cram_auth_request *)auth_request;
	const char *error;

	if (parse_cram_response(request, data, data_size, &error)) {
		auth_request->callback = callback;

		auth_request->user =
			p_strdup(auth_request->pool, request->username);

		if (mech_fix_username(auth_request->user, &error)) {
			passdb->lookup_credentials(auth_request,
						   PASSDB_CREDENTIALS_CRAM_MD5,
						   credentials_callback);
			return;
		}
	}

	if (error == NULL)
		error = "authentication failed";

	if (verbose)
		i_info("cram-md5(%s): %s", get_log_prefix(auth_request), error);

	/* failed */
	mech_auth_finish(auth_request, NULL, 0, FALSE);
}

static void
mech_cram_md5_auth_initial(struct auth_request *auth_request,
			   const unsigned char *data __attr_unused__,
			   size_t data_size __attr_unused__,
			   mech_callback_t *callback)
{
	struct cram_auth_request *request =
		(struct cram_auth_request *)auth_request;

	request->challenge = p_strdup(request->pool, get_cram_challenge());
	callback(auth_request, AUTH_CLIENT_RESULT_CONTINUE,
		 request->challenge, strlen(request->challenge));
}

static void mech_cram_md5_auth_free(struct auth_request *request)
{
	pool_unref(request->pool);
}

static struct auth_request *mech_cram_md5_auth_new(void)
{
	struct cram_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("cram_md5_auth_request", 2048);
	request = p_new(pool, struct cram_auth_request, 1);
	request->pool = pool;

	request->auth_request.refcount = 1;
	request->auth_request.pool = pool;
	return &request->auth_request;
}

struct mech_module mech_cram_md5 = {
	"CRAM-MD5",

	MEMBER(flags) MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE,

	MEMBER(passdb_need_plain) FALSE,
	MEMBER(passdb_need_credentials) TRUE,

	mech_cram_md5_auth_new,
	mech_cram_md5_auth_initial,
	mech_cram_md5_auth_continue,
        mech_cram_md5_auth_free
};
