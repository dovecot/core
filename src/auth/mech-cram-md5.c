/* Copyright (C) 2002,2003 Timo Sirainen / Joshua Goodall */

/* CRAM-MD5 SASL authentication, see RFC-2195
   Joshua Goodall <joshua@roughtrade.net> */

#include "common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hex-binary.h"
#include "md5.h"
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

	return t_strdup_printf("<%s.%s@%s>", (const char *) buf,
			       dec2str(ioloop_time), my_hostname);
}

static int verify_credentials(struct cram_auth_request *auth,
			      const char *credentials)
{
	
	unsigned char digest[16], context_digest[32], *cdp;
	struct md5_context ctxo, ctxi;
	buffer_t *context_digest_buf;
	const char *response_hex;

	if (credentials == NULL)
		return FALSE;

	context_digest_buf =
		buffer_create_data(pool_datastack_create(),
				   context_digest, sizeof(context_digest));

	if (hex_to_binary(credentials, context_digest_buf) <= 0)
		return FALSE;

#define CDGET(p, c) STMT_START { \
	(c)  = (*p++);           \
	(c) += (*p++ << 8);      \
	(c) += (*p++ << 16);     \
	(c) += (*p++ << 24);     \
} STMT_END

	cdp = context_digest;
	CDGET(cdp, ctxo.a);
	CDGET(cdp, ctxo.b);
	CDGET(cdp, ctxo.c);
	CDGET(cdp, ctxo.d);
	CDGET(cdp, ctxi.a);
	CDGET(cdp, ctxi.b);
	CDGET(cdp, ctxi.c);
	CDGET(cdp, ctxi.d);

	ctxo.lo = ctxi.lo = 64;
	ctxo.hi = ctxi.hi = 0;

	md5_update(&ctxi, auth->challenge, strlen(auth->challenge));
	md5_final(&ctxi, digest);
	md5_update(&ctxo, digest, 16);
	md5_final(&ctxo, digest);
	response_hex = binary_to_hex(digest, 16);

	if (memcmp(response_hex, auth->response, 32) != 0) {
		if (verbose) {
			i_info("cram-md5(%s): password mismatch",
			       auth->username);
		}
		return FALSE;
	}

	return TRUE;
}

static int parse_cram_response(struct cram_auth_request *auth,
			       const unsigned char *data, size_t size,
			       const char **error_r)
{
	size_t i;

	*error_r = NULL;

	for (i = 0; i < size; i++) {
		if (data[i] == ' ')
			break;
	}

	if (i == size) {
		*error_r = "missing digest";
		return FALSE;
	}

	auth->username = p_strndup(auth->pool, data, i);
	i++;
	auth->response = p_strndup(auth->pool, data + i, size - i);
	return TRUE;
}

static void credentials_callback(const char *result,
				 struct auth_request *request)
{
	struct cram_auth_request *auth =
		(struct cram_auth_request *) request;

	if (verify_credentials(auth, result)) {
		if (verbose) {
			i_info("cram-md5(%s): authenticated",
			       auth->username == NULL ? "" : auth->username);
		}
		mech_auth_finish(request, NULL, 0, TRUE);
	} else {
		if (verbose) {
			i_info("cram-md5(%s): authentication failed",
			       auth->username == NULL ? "" : auth->username);
		}
		mech_auth_finish(request, NULL, 0, FALSE);
	}
}

static int
mech_cram_md5_auth_continue(struct auth_request *auth_request,
			    const unsigned char *data, size_t data_size,
			    mech_callback_t *callback)
{
	struct cram_auth_request *auth =
		(struct cram_auth_request *)auth_request;
	const char *error;

	if (parse_cram_response(auth, data, data_size, &error)) {
		auth_request->callback = callback;

		auth_request->user =
			p_strdup(auth_request->pool, auth->username);

		if (mech_is_valid_username(auth_request->user)) {
			passdb->lookup_credentials(&auth->auth_request,
						   PASSDB_CREDENTIALS_CRAM_MD5,
						   credentials_callback);
			return TRUE;
		}

		error = "invalid username";
	}

	if (error == NULL)
		error = "authentication failed";

	if (verbose) {
		i_info("cram-md5(%s): %s",
		       auth->username == NULL ? "" : auth->username, error);
	}

	/* failed */
	mech_auth_finish(auth_request, NULL, 0, FALSE);
	return FALSE;
}

static int
mech_cram_md5_auth_initial(struct auth_request *auth_request,
			   struct auth_client_request_new *request,
			   const unsigned char *data __attr_unused__,
			   mech_callback_t *callback)
{
	struct cram_auth_request *auth =
		(struct cram_auth_request *)auth_request;

	struct auth_client_request_reply reply;

	if (AUTH_CLIENT_REQUEST_HAVE_INITIAL_RESPONSE(request)) {
		/* No initial response in CRAM-MD5 */
		return FALSE;
	}

	auth->challenge = p_strdup(auth->pool, get_cram_challenge());

	/* initialize reply */
	mech_init_auth_client_reply(&reply);
	reply.id = request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	/* send the initial challenge */
	reply.reply_idx = 0;
	reply.data_size = strlen(auth->challenge);
	callback(&reply, auth->challenge, auth_request->conn);
	return TRUE;
}

static void mech_cram_md5_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *mech_cram_md5_auth_new(void)
{
	struct cram_auth_request *auth;
	pool_t pool;

	pool = pool_alloconly_create("cram_md5_auth_request", 2048);
	auth = p_new(pool, struct cram_auth_request, 1);
	auth->pool = pool;

	auth->auth_request.refcount = 1;
	auth->auth_request.pool = pool;
	auth->auth_request.auth_initial = mech_cram_md5_auth_initial;
	auth->auth_request.auth_continue = mech_cram_md5_auth_continue;
	auth->auth_request.auth_free = mech_cram_md5_auth_free;

	return &auth->auth_request;
}

struct mech_module mech_cram_md5 = {
	"CRAM-MD5",

	MEMBER(plaintext) FALSE,
	MEMBER(advertise) TRUE,

	MEMBER(passdb_need_plain) FALSE,
	MEMBER(passdb_need_credentials) TRUE,

	mech_cram_md5_auth_new
};
