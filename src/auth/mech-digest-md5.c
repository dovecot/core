/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* Digest-MD5 SASL authentication, see RFC-2831 */

#include "auth-common.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "md5.h"
#include "randgen.h"
#include "str.h"
#include "str-sanitize.h"
#include "mech.h"
#include "passdb.h"

#include <stdlib.h>

#define MAX_REALM_LEN 64

/* Linear whitespace */
#define IS_LWS(c) ((c) == ' ' || (c) == '\t')

enum qop_option {
	QOP_AUTH	= 0x01,	/* authenticate */
	QOP_AUTH_INT	= 0x02, /* + integrity protection, not supported yet */
	QOP_AUTH_CONF	= 0x04, /* + encryption, not supported yet */

	QOP_COUNT	= 3
};

static const char *qop_names[] = { "auth", "auth-int", "auth-conf" };

struct digest_auth_request {
	struct auth_request auth_request;

	pool_t pool;
	unsigned int authenticated:1;

	/* requested: */
	char *nonce;
	enum qop_option qop;

	/* received: */
	char *username;
	char *cnonce;
	char *nonce_count;
	char *qop_value;
	char *digest_uri; /* may be NULL */
	unsigned char response[32];
	unsigned long maxbuf;
	unsigned int nonce_found:1;

	/* final reply: */
	char *rspauth;
};

static string_t *get_digest_challenge(struct digest_auth_request *request)
{
	const struct auth_settings *set = request->auth_request.set;
	buffer_t buf;
	string_t *str;
	const char *const *tmp;
	unsigned char nonce[16];
	unsigned char nonce_base64[MAX_BASE64_ENCODED_SIZE(sizeof(nonce))+1];
	int i;
	bool first_qop;

	/*
	   realm="hostname" (multiple allowed)
	   nonce="randomized data, at least 64bit"
	   qop="auth,auth-int,auth-conf"
	   maxbuf=number (with auth-int, auth-conf, defaults to 64k)
	   charset="utf-8" (iso-8859-1 if it doesn't exist)
	   algorithm="md5-sess"
	   cipher="3des,des,rc4-40,rc4,rc4-56" (with auth-conf)
	*/

	/* get 128bit of random data as nonce */
	random_fill(nonce, sizeof(nonce));

	buffer_create_data(&buf, nonce_base64, sizeof(nonce_base64));
	base64_encode(nonce, sizeof(nonce), &buf);
	buffer_append_c(&buf, '\0');
	request->nonce = p_strdup(request->pool, buf.data);

	str = t_str_new(256);
	if (*set->realms_arr == NULL) {
		/* If no realms are given, at least Cyrus SASL client defaults
		   to destination host name */
		str_append(str, "realm=\"\",");
	} else {
		for (tmp = set->realms_arr; *tmp != NULL; tmp++)
			str_printfa(str, "realm=\"%s\",", *tmp);
	}

	str_printfa(str, "nonce=\"%s\",", request->nonce);

	str_append(str, "qop=\""); first_qop = TRUE;
	for (i = 0; i < QOP_COUNT; i++) {
		if (request->qop & (1 << i)) {
			if (first_qop)
				first_qop = FALSE;
			else
				str_append_c(str, ',');
			str_append(str, qop_names[i]);
		}
	}
	str_append(str, "\",");

	str_append(str, "charset=\"utf-8\","
		   "algorithm=\"md5-sess\"");
	return str;
}

static bool verify_credentials(struct digest_auth_request *request,
			       const unsigned char *credentials, size_t size)
{
	struct md5_context ctx;
	unsigned char digest[MD5_RESULTLEN];
	const char *a1_hex, *a2_hex, *response_hex;
	int i;

	/* get the MD5 password */
	if (size != MD5_RESULTLEN) {
                auth_request_log_error(&request->auth_request, "digest-md5",
				       "invalid credentials length");
		return FALSE;
	}

	/*
	   response =
	     HEX( KD ( HEX(H(A1)),
		     { nonce-value, ":" nc-value, ":",
		       cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))

	   and since we don't support authzid yet:

	   A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
		":", nonce-value, ":", cnonce-value }

	   If the "qop" directive's value is "auth", then A2 is:
	
	      A2       = { "AUTHENTICATE:", digest-uri-value }
	
	   If the "qop" value is "auth-int" or "auth-conf" then A2 is:
	
	      A2       = { "AUTHENTICATE:", digest-uri-value,
		       ":00000000000000000000000000000000" }
	*/

	/* A1 */
	md5_init(&ctx);
	md5_update(&ctx, credentials, size);
	md5_update(&ctx, ":", 1);
	md5_update(&ctx, request->nonce, strlen(request->nonce));
	md5_update(&ctx, ":", 1);
	md5_update(&ctx, request->cnonce, strlen(request->cnonce));
	md5_final(&ctx, digest);
	a1_hex = binary_to_hex(digest, 16);

	/* do it twice, first verify the user's response, the second is
	   sent for client as a reply */
	for (i = 0; i < 2; i++) {
		/* A2 */
		md5_init(&ctx);
		if (i == 0)
			md5_update(&ctx, "AUTHENTICATE:", 13);
		else
			md5_update(&ctx, ":", 1);

		if (request->digest_uri != NULL) {
			md5_update(&ctx, request->digest_uri,
				   strlen(request->digest_uri));
		}
		if (request->qop == QOP_AUTH_INT ||
		    request->qop == QOP_AUTH_CONF) {
			md5_update(&ctx, ":00000000000000000000000000000000",
				   33);
		}
		md5_final(&ctx, digest);
		a2_hex = binary_to_hex(digest, 16);

		/* response */
		md5_init(&ctx);
		md5_update(&ctx, a1_hex, 32);
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, request->nonce, strlen(request->nonce));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, request->nonce_count,
			   strlen(request->nonce_count));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, request->cnonce, strlen(request->cnonce));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, request->qop_value,
			   strlen(request->qop_value));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, a2_hex, 32);
		md5_final(&ctx, digest);
		response_hex = binary_to_hex(digest, 16);

		if (i == 0) {
			/* verify response */
			if (memcmp(response_hex, request->response, 32) != 0) {
				auth_request_log_info(&request->auth_request,
						      "digest-md5",
						      "password mismatch");
				return FALSE;
			}
		} else {
			request->rspauth =
				p_strconcat(request->pool, "rspauth=",
					    response_hex, NULL);
		}
	}

	return TRUE;
}

static bool parse_next(char **data, char **key, char **value)
{
	/* @UNSAFE */
	char *p, *dest;

	p = *data;
	while (IS_LWS(*p)) p++;

	/* get key */
	*key = p;
	while (*p != '\0' && *p != '=' && *p != ',')
		p++;

	if (*p != '=') {
		*data = p;
		return FALSE;
	}

	*value = p+1;

	/* skip trailing whitespace in key */
	while (IS_LWS(p[-1]))
		p--;
	*p = '\0';

	/* get value */
	p = *value;
	while (IS_LWS(*p)) p++;

	if (*p != '"') {
		while (*p != '\0' && *p != ',')
			p++;

		*data = p+1;
		while (IS_LWS(p[-1]))
			p--;
		*p = '\0';
	} else {
		/* quoted string */
		*value = dest = ++p;
		while (*p != '\0' && *p != '"') {
			if (*p == '\\' && p[1] != '\0')
				p++;
			*dest++ = *p++;
		}

		*data = *p == '"' ? p+1 : p;
		*dest = '\0';
	}

	return TRUE;
}

static bool auth_handle_response(struct digest_auth_request *request,
				 char *key, char *value, const char **error)
{
	unsigned int i;

	str_lcase(key);

	if (strcmp(key, "realm") == 0) {
		if (request->auth_request.realm == NULL && *value != '\0')
			request->auth_request.realm =
				p_strdup(request->pool, value);
		return TRUE;
	}

	if (strcmp(key, "username") == 0) {
		if (request->username != NULL) {
			*error = "username must not exist more than once";
			return FALSE;
		}

		if (*value == '\0') {
			*error = "empty username";
			return FALSE;
		}

		request->username = p_strdup(request->pool, value);
		return TRUE;
	}

	if (strcmp(key, "nonce") == 0) {
		/* nonce must be same */
		if (strcmp(value, request->nonce) != 0) {
			*error = "Invalid nonce";
			return FALSE;
		}

		request->nonce_found = TRUE;
		return TRUE;
	}

	if (strcmp(key, "cnonce") == 0) {
		if (request->cnonce != NULL) {
			*error = "cnonce must not exist more than once";
			return FALSE;
		}

		if (*value == '\0') {
			*error = "cnonce can't contain empty value";
			return FALSE;
		}

		request->cnonce = p_strdup(request->pool, value);
		return TRUE;
	}

	if (strcmp(key, "nonce-count") == 0) {
		if (request->nonce_count != NULL) {
			*error = "nonce-count must not exist more than once";
			return FALSE;
		}

		if (atoi(value) != 1) {
			*error = "re-auth not supported currently";
			return FALSE;
		}

		request->nonce_count = p_strdup(request->pool, value);
		return TRUE;
	}

	if (strcmp(key, "qop") == 0) {
		for (i = 0; i < QOP_COUNT; i++) {
			if (strcasecmp(qop_names[i], value) == 0)
				break;
		}

		if (i == QOP_COUNT) {
			*error = t_strdup_printf("Unknown QoP value: %s",
					str_sanitize(value, 32));
			return FALSE;
		}

		request->qop &= (1 << i);
		if (request->qop == 0) {
			*error = "Nonallowed QoP requested";
			return FALSE;
		} 

		request->qop_value = p_strdup(request->pool, value);
		return TRUE;
	}

	if (strcmp(key, "digest-uri") == 0) {
		/* type / host / serv-name */
		const char *const *uri = t_strsplit(value, "/");

		if (uri[0] == NULL || uri[1] == NULL) {
			*error = "Invalid digest-uri";
			return FALSE;
		}

		/* FIXME: RFC recommends that we verify the host/serv-type.
		   But isn't the realm enough already? That'd be just extra
		   configuration.. Maybe optionally list valid hosts in
		   config file? */
		request->digest_uri = p_strdup(request->pool, value);
		return TRUE;
	}

	if (strcmp(key, "maxbuf") == 0) {
		if (request->maxbuf != 0) {
			*error = "maxbuf must not exist more than once";
			return FALSE;
		}

		if (str_to_ulong(value, &request->maxbuf) < 0 ||
		    request->maxbuf == 0) {
			*error = "Invalid maxbuf value";
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(key, "charset") == 0) {
		if (strcasecmp(value, "utf-8") != 0) {
			*error = "Only utf-8 charset is allowed";
			return FALSE;
		}

		return TRUE;
	}

	if (strcmp(key, "response") == 0) {
		if (strlen(value) != 32) {
			*error = "Invalid response value";
			return FALSE;
		}

		memcpy(request->response, value, 32);
		return TRUE;
	}

	if (strcmp(key, "cipher") == 0) {
		/* not supported, ignore */
		return TRUE;
	}

	if (strcmp(key, "authzid") == 0) {
		/* not supported, abort */
		return FALSE;
	}

	/* unknown key, ignore */
	return TRUE;
}

static bool parse_digest_response(struct digest_auth_request *request,
				  const unsigned char *data, size_t size,
				  const char **error)
{
	char *copy, *key, *value;
	bool failed;

	/*
	   realm="realm"
	   username="username"
	   nonce="randomized data"
	   cnonce="??"
	   nc=00000001
	   qop="auth|auth-int|auth-conf"
	   digest-uri="serv-type/host[/serv-name]"
	   response=32 HEX digits
	   maxbuf=number (with auth-int, auth-conf, defaults to 64k)
	   charset="utf-8" (iso-8859-1 if it doesn't exist)
	   cipher="cipher-value"
	   authzid="authzid-value"
	*/

	*error = NULL;
	failed = FALSE;

	if (size == 0) {
		*error = "Client sent no input";
		return FALSE;
	}

	/* treating response as NUL-terminated string also gets rid of all
	   potential problems with NUL characters in strings. */
	copy = t_strdup_noconst(t_strndup(data, size));
	while (*copy != '\0') {
		if (parse_next(&copy, &key, &value)) {
			if (!auth_handle_response(request, key, value, error)) {
				failed = TRUE;
				break;
			}
		}

		if (*copy == ',')
			copy++;
	}

	if (!failed) {
		if (!request->nonce_found) {
			*error = "Missing nonce parameter";
			failed = TRUE;
		} else if (request->cnonce == NULL) {
			*error = "Missing cnonce parameter";
			failed = TRUE;
		} else if (request->username == NULL) {
			*error = "Missing username parameter";
			failed = TRUE;
		}
	}

	if (request->nonce_count == NULL)
		request->nonce_count = p_strdup(request->pool, "00000001");
	if (request->qop_value == NULL)
		request->qop_value = p_strdup(request->pool, "auth");

	return !failed;
}

static void credentials_callback(enum passdb_result result,
				 const unsigned char *credentials, size_t size,
				 struct auth_request *auth_request)
{
	struct digest_auth_request *request =
		(struct digest_auth_request *)auth_request;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (!verify_credentials(request, credentials, size)) {
			auth_request_fail(auth_request);
			return;
		}

		request->authenticated = TRUE;
		auth_request_handler_reply_continue(auth_request,
						    request->rspauth,
						    strlen(request->rspauth));
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
mech_digest_md5_auth_continue(struct auth_request *auth_request,
			      const unsigned char *data, size_t data_size)
{
	struct digest_auth_request *request =
		(struct digest_auth_request *)auth_request;
	const char *username, *error;

	if (request->authenticated) {
		/* authentication is done, we were just waiting the last
		   word from client */
		auth_request_success(auth_request, NULL, 0);
		return;
	}

	if (parse_digest_response(request, data, data_size, &error)) {
		if (auth_request->realm != NULL &&
		    strchr(request->username, '@') == NULL) {
			username = t_strconcat(request->username, "@",
					       auth_request->realm, NULL);
			auth_request->domain_is_realm = TRUE;
		} else {
			username = request->username;
		}

		if (auth_request_set_username(auth_request, username, &error)) {
			auth_request_lookup_credentials(auth_request,
					"DIGEST-MD5", credentials_callback);
			return;
		}
	}

	if (error != NULL)
                auth_request_log_info(auth_request, "digest-md5", "%s", error);

	auth_request_fail(auth_request);
}

static void
mech_digest_md5_auth_initial(struct auth_request *auth_request,
			     const unsigned char *data ATTR_UNUSED,
			     size_t data_size ATTR_UNUSED)
{
	struct digest_auth_request *request =
		(struct digest_auth_request *)auth_request;
	string_t *challenge;

	/* FIXME: there's no support for subsequent authentication */

	challenge = get_digest_challenge(request);
	auth_request_handler_reply_continue(auth_request, str_data(challenge),
					    str_len(challenge));
}

static struct auth_request *mech_digest_md5_auth_new(void)
{
	struct digest_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("digest_md5_auth_request", 2048);
	request = p_new(pool, struct digest_auth_request, 1);
	request->pool = pool;
	request->qop = QOP_AUTH;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_digest_md5 = {
	"DIGEST-MD5",

	.flags = MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE |
		MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_digest_md5_auth_new,
	mech_digest_md5_auth_initial,
	mech_digest_md5_auth_continue,
	mech_generic_auth_free
};
