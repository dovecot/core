/* Copyright (C) 2002 Timo Sirainen */

/* Digest-MD5 SASL authentication, see rfc-2831 */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "md5.h"
#include "randgen.h"
#include "str.h"

#include "auth.h"
#include "cookie.h"
#include "userinfo.h"

#include <stdlib.h>

#define SERVICE_TYPE "imap"

/* Linear whitespace */
#define IS_LWS(c) ((c) == ' ' || (c) == '\t')

enum qop_option {
	QOP_AUTH	= 0x01,	/* authenticate */
	QOP_AUTH_INT	= 0x02, /* + integrity protection, not supported yet */
	QOP_AUTH_CONF	= 0x04, /* + encryption, not supported yet */

	QOP_COUNT	= 3
};

static char *qop_names[] = { "auth", "auth-int", "auth-conf" };

struct auth_data {
	pool_t pool;
	unsigned int authenticated:1;

	/* requested: */
	char *nonce;
	enum qop_option qop;

	/* received: */
	char *realm; /* may be NULL */
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
        struct auth_cookie_reply_data cookie_reply;
};

static const char *get_digest_challenge(struct auth_data *auth)
{
	string_t *qoplist, *realms;
	buffer_t *buf;
	const char *const *tmp;
	unsigned char nonce[16];
	int i;

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

	t_push();
	buf = buffer_create_static(data_stack_pool,
				   MAX_BASE64_ENCODED_SIZE(sizeof(nonce))+1);

	base64_encode(nonce, sizeof(nonce), buf);
	buffer_append_c(buf, '\0');
	auth->nonce = p_strdup(auth->pool, buffer_get_data(buf, NULL));
	t_pop();

	/* get list of allowed QoPs */
	qoplist = t_str_new(32);
	for (i = 0; i < QOP_COUNT; i++) {
		if (auth->qop & (1 << i)) {
			if (str_len(qoplist) > 0)
				str_append_c(qoplist, ',');
			str_append(qoplist, qop_names[i]);
		}
	}

	realms = t_str_new(128);
	for (tmp = auth_realms; *tmp != NULL; tmp++) {
		str_printfa(realms, "realm=\"%s\"", *tmp);
		str_append_c(realms, ',');
	}

	return t_strconcat(str_c(realms),
			   "nonce=\"", auth->nonce, "\",",
			   "qop=\"", str_c(qoplist), "\",",
			   "charset=\"utf-8\",",
			   "algorithm=\"md5-sess\"",
			   NULL);
}

static int verify_auth(struct auth_data *auth)
{
	struct md5_context ctx;
	unsigned char digest[16];
	const char *a1_hex, *a2_hex, *response_hex;
	int i;

	/* we should have taken care of this at startup */
	i_assert(userinfo->lookup_digest_md5 != NULL);

	/* get the MD5 password */
	if (!userinfo->lookup_digest_md5(auth->username, auth->realm != NULL ?
					 auth->realm : "", digest,
					 &auth->cookie_reply))
		return FALSE;

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
	md5_update(&ctx, digest, 16);
	md5_update(&ctx, ":", 1);
	md5_update(&ctx, auth->nonce, strlen(auth->nonce));
	md5_update(&ctx, ":", 1);
	md5_update(&ctx, auth->cnonce, strlen(auth->cnonce));
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

		if (auth->digest_uri != NULL) {
			md5_update(&ctx, auth->digest_uri,
				   strlen(auth->digest_uri));
		}
		if (auth->qop == QOP_AUTH_INT || auth->qop == QOP_AUTH_CONF) {
			md5_update(&ctx, ":00000000000000000000000000000000",
				   33);
		}
		md5_final(&ctx, digest);
		a2_hex = binary_to_hex(digest, 16);

		/* response */
		md5_init(&ctx);
		md5_update(&ctx, a1_hex, 32);
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, auth->nonce, strlen(auth->nonce));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, auth->nonce_count, strlen(auth->nonce_count));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, auth->cnonce, strlen(auth->cnonce));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, auth->qop_value, strlen(auth->qop_value));
		md5_update(&ctx, ":", 1);
		md5_update(&ctx, a2_hex, 32);
		md5_final(&ctx, digest);
		response_hex = binary_to_hex(digest, 16);

		if (i == 0) {
			/* verify response */
			if (memcmp(response_hex, auth->response, 32) != 0)
				return FALSE;
		} else {
			auth->rspauth = p_strconcat(auth->pool, "rspauth=",
						    response_hex, NULL);
		}
	}

	return TRUE;
}

static int verify_realm(const char *realm)
{
	const char *const *tmp;

	for (tmp = auth_realms; *tmp != NULL; tmp++) {
		if (strcasecmp(realm, *tmp) == 0)
			return TRUE;
	}

	return FALSE;
}

static int parse_next(char **data, char **key, char **value)
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

/* remove leading and trailing whitespace */
static const char *trim(const char *str)
{
	const char *ret;

	while (IS_LWS(*str)) str++;
	ret = str;

	while (*str != '\0') str++;
	if (str > ret) {
		while (IS_LWS(str[-1])) str--;
		ret = t_strdup_until(ret, str);
	}

	return ret;
}

static int auth_handle_response(struct auth_data *auth, char *key, char *value,
				const char **error)
{
	int i;

	str_lcase(key);

	if (strcmp(key, "realm") == 0) {
		if (!verify_realm(value)) {
			*error = "Invalid realm";
			return FALSE;
		}
		if (auth->realm == NULL)
			auth->realm = p_strdup(auth->pool, value);
		return TRUE;
	}

	if (strcmp(key, "username") == 0) {
		if (auth->username != NULL) {
			*error = "username must not exist more than once";
			return FALSE;
		}

		if (*value == '\0') {
			*error = "empty username";
			return FALSE;
		}

		auth->username = p_strdup(auth->pool, value);
		return TRUE;
	}

	if (strcmp(key, "nonce") == 0) {
		/* nonce must be same */
		if (strcmp(value, auth->nonce) != 0) {
			*error = "Invalid nonce";
			return FALSE;
		}

		auth->nonce_found = TRUE;
		return TRUE;
	}

	if (strcmp(key, "cnonce") == 0) {
		if (auth->cnonce != NULL) {
			*error = "cnonce must not exist more than once";
			return FALSE;
		}

		if (*value == '\0') {
			*error = "cnonce can't contain empty value";
			return FALSE;
		}

		auth->cnonce = p_strdup(auth->pool, value);
		return TRUE;
	}

	if (strcmp(key, "nonce-count") == 0) {
		if (auth->nonce_count != NULL) {
			*error = "nonce-count must not exist more than once";
			return FALSE;
		}

		if (atoi(value) != 1) {
			*error = "re-auth not supported currently";
			return FALSE;
		}

		auth->nonce_count = p_strdup(auth->pool, value);
		return TRUE;
	}

	if (strcmp(key, "qop") == 0) {
		for (i = 0; i < QOP_COUNT; i++) {
			if (strcasecmp(qop_names[i], value) == 0)
				break;
		}

		if (i == QOP_COUNT) {
			*error = "Unknown QoP value";
			return FALSE;
		}

		auth->qop &= (1 << i);
		if (auth->qop == 0) {
			*error = "Nonallowed QoP requested";
			return FALSE;
		} 

		auth->qop_value = p_strdup(auth->pool, value);
		return TRUE;
	}

	if (strcmp(key, "digest-uri") == 0) {
		/* type / host / serv-name */
		const char *const *uri = t_strsplit(value, "/");

		if (uri[0] == NULL || uri[1] == NULL) {
			*error = "Invalid digest-uri";
			return FALSE;
		}

		if (strcasecmp(trim(uri[0]), SERVICE_TYPE) != 0) {
			*error = "Unexpected service type in digest-uri";
			return FALSE;
		}

		/* FIXME: RFC recommends that we verify the host/serv-type.
		   But isn't the realm enough already? That'd be just extra
		   configuration.. Maybe optionally list valid hosts in
		   config file? */
		auth->digest_uri = p_strdup(auth->pool, value);
		return TRUE;
	}

	if (strcmp(key, "maxbuf") == 0) {
		if (auth->maxbuf != 0) {
			*error = "maxbuf must not exist more than once";
			return FALSE;
		}

		auth->maxbuf = strtoul(value, NULL, 10);
		if (auth->maxbuf == 0) {
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

		memcpy(auth->response, value, 32);
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

static int parse_digest_response(struct auth_data *auth, const char *data,
				 size_t size, const char **error)
{
	char *copy, *key, *value;
	int failed;

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

	t_push();

	failed = FALSE;

	copy = t_strdup_noconst(t_strndup(data, size));
	while (*copy != '\0') {
		if (parse_next(&copy, &key, &value)) {
			if (!auth_handle_response(auth, key, value, error)) {
				failed = TRUE;
				break;
			}
		}

		if (*copy == ',')
			copy++;
	}

	if (!auth->nonce_found) {
		*error = "Missing nonce parameter";
		failed = TRUE;
	} else if (auth->cnonce == NULL) {
		*error = "Missing cnonce parameter";
		failed = TRUE;
	} else if (auth->username == NULL) {
		*error = "Missing username parameter";
		failed = TRUE;
	}

	if (auth->nonce_count == NULL)
		auth->nonce_count = p_strdup(auth->pool, "00000001");
	if (auth->qop_value == NULL)
		auth->qop_value = p_strdup(auth->pool, "auth");

	if (!failed && !verify_auth(auth)) {
		*error = "Authentication failed";
		failed = TRUE;
	}

	t_pop();

	/* error message is actually ignored here, we could send it to
	   syslog or maybe to client, but it's not specified if that's
	   allowed and how. */
	return !failed;
}

static void
auth_digest_md5_continue(struct cookie_data *cookie,
			 struct auth_continued_request_data *request,
			 const unsigned char *data,
			 AuthCallback callback, void *context)
{
	struct auth_data *auth = cookie->context;
	struct auth_reply_data reply;
	const char *error;

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);

	if (auth->authenticated) {
		/* authentication is done, we were just waiting the last
		   word from client */
		auth->cookie_reply.success = TRUE;
		reply.result = AUTH_RESULT_SUCCESS;
		callback(&reply, NULL, context);
		return;
	}

	if (parse_digest_response(auth, (const char *) data,
					 request->data_size, &error)) {
		/* authentication ok */
		reply.result = AUTH_RESULT_CONTINUE;

		reply.data_size = strlen(auth->rspauth);
		callback(&reply, (const unsigned char *) auth->rspauth,
			 context);
		auth->authenticated = TRUE;
		return;
	}

	/* failed */
	reply.result = AUTH_RESULT_FAILURE;
	callback(&reply, (const unsigned char *) error, context);
	cookie_remove(cookie->cookie);
}

static int auth_digest_md5_fill_reply(struct cookie_data *cookie,
				      struct auth_cookie_reply_data *reply)
{
	struct auth_data *auth = cookie->context;

	if (!auth->authenticated)
		return FALSE;

	memcpy(reply, &auth->cookie_reply,
	       sizeof(struct auth_cookie_reply_data));
	return TRUE;
}

static void auth_digest_md5_free(struct cookie_data *cookie)
{
	pool_unref(((struct auth_data *) cookie->context)->pool);
}

static void auth_digest_md5_init(unsigned int login_pid,
				 struct auth_init_request_data *request,
				 AuthCallback callback, void *context)
{
	struct cookie_data *cookie;
	struct auth_reply_data reply;
	struct auth_data *auth;
	pool_t pool;
	const char *challenge;

	pool = pool_alloconly_create("Digest-MD5", 2048);
	auth = p_new(pool, struct auth_data, 1);
	auth->pool = pool;

	auth->qop = QOP_AUTH;

	cookie = p_new(pool, struct cookie_data, 1);
	cookie->login_pid = login_pid;
	cookie->auth_fill_reply = auth_digest_md5_fill_reply;
	cookie->auth_continue = auth_digest_md5_continue;
	cookie->free = auth_digest_md5_free;
	cookie->context = auth;

	cookie_add(cookie);

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	reply.result = AUTH_RESULT_CONTINUE;
	memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);

	/* send the initial challenge */
	t_push();

	challenge = get_digest_challenge(auth);
	reply.data_size = strlen(challenge);
	callback(&reply, (const unsigned char *) challenge, context);

	t_pop();
}

struct auth_module auth_digest_md5 = {
	AUTH_METHOD_DIGEST_MD5,
	auth_digest_md5_init
};
