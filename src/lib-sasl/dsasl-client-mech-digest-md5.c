/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "base64.h"
#include "randgen.h"
#include "hex-binary.h"
#include "md5.h"
#include "hash-method.h"
#include "auth-digest.h"

#include "dsasl-client-private.h"

enum digest_md5_state {
	DIGEST_MD5_STATE_INIT = 0,
	DIGEST_MD5_STATE_SERVER_FIRST,
	DIGEST_MD5_STATE_CLIENT_FIRST,
	DIGEST_MD5_STATE_SERVER_FINAL,
	DIGEST_MD5_STATE_CLIENT_FINAL,
	DIGEST_MD5_STATE_END,
};

struct digest_md5_dsasl_client {
	struct dsasl_client client;

	enum digest_md5_state state;

	const char *username;
	const char *realm;
	const char *nonce;
	const char *nc;
	const char *cnonce;
	const char *qop;
	const char *req_uri;
	unsigned long maxbuf;

	const char *a1_hex;

	bool challenge_has_realm;
	bool challenge_has_our_realm;
};

static const struct hash_method *const hmethod = &hash_method_md5;

static void
value_append_escaped(string_t *dest, const void *src)
{
	size_t src_size = strlen(src);
	const unsigned char *pstart = src, *p = src, *pend = pstart + src_size;

	/* see if we need to quote it */
	for (; p < pend; p++) {
		if (*p == '"' || *p == '\\')
			break;
	}

	/* quote */
	str_append_data(dest, pstart, (size_t)(p - pstart));

	for (; p < pend; p++) {
		if (*p == '"' || *p == '\\')
			str_append_c(dest, '\\');
		str_append_data(dest, p, 1);
	}
}

static bool parse_list_element(const char **in_p, const char **element_r)
{
	const char *p = *in_p, *pend = p + strlen(*in_p);
	const char *poffset = NULL, *plchar;

	while (p < pend) {
		if (*p == ' ' || *p == '\t') {
			p++;
			continue;
		}
		if (*p == ',') {
			p++;
			if (poffset == NULL)
				continue;
			*in_p = p;
			*element_r = t_strdup_until(poffset, plchar);
			return TRUE;
		}
		if (poffset == NULL)
			poffset = p;
		plchar = p;
		p++;
	}
	*in_p = pend;
	*element_r = NULL;
	return FALSE;
}

static bool
handle_challenge_field(struct digest_md5_dsasl_client *dclient,
		       const char *key, const char *value, const char **error_r)
{
	struct dsasl_client *client = &dclient->client;

	if (strcmp(key, "realm") == 0) {
		dclient->challenge_has_realm = TRUE;
		if (dclient->realm != NULL &&
		    strcmp(value, dclient->realm) == 0)
			dclient->challenge_has_our_realm = TRUE;
		return TRUE;
	}

	if (strcmp(key, "nonce") == 0) {
		if (dclient->nonce != NULL) {
			*error_r = "nonce must not exist more than once";
			return FALSE;
		}

		if (*value == '\0') {
			*error_r = "nonce can't contain empty value";
			return FALSE;
		}

		dclient->nonce = p_strdup(client->pool, value);
		return TRUE;
	}

	if (strcmp(key, "qop-options") == 0) {
		const char *opt;

		while (parse_list_element(&value, &opt)) {
			if (strcasecmp(opt, dclient->qop) == 0)
				return TRUE;
		}
		*error_r = "'auth' qop not supported by server";
		return FALSE;
	}

	if (strcmp(key, "stale") == 0) {
		/* ignore */
		return TRUE;
	}

	if (strcmp(key, "maxbuf") == 0) {
		if (dclient->maxbuf != 0) {
			*error_r = "maxbuf must not exist more than once";
			return FALSE;
		}

		if (str_to_ulong(value, &dclient->maxbuf) < 0 ||
		    dclient->maxbuf == 0) {
			*error_r = "Invalid maxbuf value";
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(key, "algorithm") == 0) {
		if (strcasecmp(value, "md5-sess") != 0) {
			*error_r = "Unsupported algorithm";
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(key, "cipher-opts") == 0) {
		/* not supported, ignore */
		return TRUE;
	}

	/* unknown key, ignore */
	return TRUE;
}

static bool
handle_confirmation_field(struct digest_md5_dsasl_client *dclient ATTR_UNUSED,
			  const char *key, const char *value,
			  const char **rspauth_r, const char **error_r)
{
	if (strcmp(key, "rspauth") == 0) {
		if (*rspauth_r != NULL)  {
			*error_r = "rspauth must not exist more than once";
			return FALSE;
		}

		*rspauth_r = value;
		return TRUE;
	}

	/* unknown key, ignore */
	return TRUE;
}

static int
mech_digest_md5_init(struct digest_md5_dsasl_client *dclient,
		     const char **error_r)
{
	struct dsasl_client *client = &dclient->client;
	const char *realm;

	if (client->set.authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (client->password == NULL) {
		*error_r = "password not set";
		return -1;
	}
	if (client->set.protocol == NULL) {
		*error_r = "protocol not set";
		return -1;
	}
	if (client->set.host == NULL) {
		*error_r = "host not set";
		return -1;
	}

	/* Assume user@realm format for username. If user@domain is wanted
	   in the username, allow also user@domain@realm. */
	realm = strrchr(client->set.authid, '@');
	if (realm != NULL) {
		dclient->username = p_strdup_until(client->pool,
						   client->set.authid, realm);
		realm++;
		dclient->realm = p_strdup(client->pool, realm);
	} else {
		dclient->username = client->set.authid;
		dclient->realm = "";
	}
	dclient->nc = "00000001";
	dclient->qop = "auth";
	dclient->req_uri = p_strdup_printf(client->pool, "%s/%s",
					   client->set.protocol,
					   client->set.host);
	return 0;
}

static int
mech_digest_md5_input_first(struct digest_md5_dsasl_client *dclient,
			    const unsigned char *input, size_t input_len,
			    const char **error_r)
{
	char *copy;
	bool failed = FALSE;

	/*
	   realm="hostname" (multiple allowed)
	   nonce="randomized data, at least 64bit"
	   qop="auth,auth-int,auth-conf"
	   maxbuf=number (with auth-int, auth-conf, defaults to 64k)
	   charset="utf-8" (iso-8859-1 if it doesn't exist)
	   algorithm="md5-sess"
	   cipher="3des,des,rc4-40,rc4,rc4-56" (with auth-conf)
	*/

	if (input_len == 0) {
		*error_r = "Empty server challenge";
		return -1;
	}

	/* RFC 2831, Section 2.1.1:
	   The size of a digest-challenge MUST be less than 2048 bytes.
	 */
	if (input_len >= 2048) {
		*error_r = "Server challenge too large (>= 2048)";
		return -1;
	}

	/* Treating challenge as NUL-terminated string also gets rid of all
	   potential problems with NUL characters in strings. */
	copy = t_strdup_noconst(t_strndup(input, input_len));
	while (*copy != '\0') {
		const char *key, *value;

		if (auth_digest_parse_keyvalue(&copy, &key, &value)) {
			const char *error;

			if (!handle_challenge_field(dclient, key, value,
						    &error)) {
				*error_r = t_strdup_printf(
					"Server sent invalid challenge field '%s': "
					"%s", key, error);
				failed = TRUE;
				break;
			}
		}

		if (*copy == ',')
			copy++;
	}

	if (!failed) {
		if (dclient->realm != NULL && dclient->challenge_has_realm &&
		    !dclient->challenge_has_our_realm) {
			*error_r = "Server offers no matching realm";
			failed = TRUE;
		} else if (dclient->nonce == NULL) {
			*error_r = "Missing nonce parameter";
			failed = TRUE;
		}
	}

	return (failed ? -1 : 0);
}

static string_t *
mech_digest_md5_output_first(struct digest_md5_dsasl_client *dclient)
{
	struct dsasl_client *client = &dclient->client;

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

	unsigned char cnonce[16];
	unsigned char cnonce_base64[MAX_BASE64_ENCODED_SIZE(sizeof(cnonce))+1];
	buffer_t buf;

	/* Get 128bit of random data as cnonce */
	random_fill(cnonce, sizeof(cnonce));

	buffer_create_from_data(&buf, cnonce_base64, sizeof(cnonce_base64));
	base64_encode(cnonce, sizeof(cnonce), &buf);
	buffer_append_c(&buf, '\0');
	dclient->cnonce = p_strdup(client->pool, buf.data);

	string_t *str = t_str_new(256);

	str_append(str, "realm=\"");
	value_append_escaped(str, dclient->realm);

	str_append(str, "\",username=\"");
	value_append_escaped(str, dclient->username);

	str_printfa(str, "\",nonce=\"%s\",cnonce=\"%s\",nc=%s,qop=%s,"
			 "digest-uri=\"%s\",charset=\"utf-8\"",
		    dclient->nonce, dclient->cnonce, dclient->nc, dclient->qop,
		    dclient->req_uri);

	unsigned char a1_secret[hmethod->digest_size];

	auth_digest_get_hash_a1_secret(hmethod, dclient->username,
				       dclient->realm, client->password,
				       a1_secret);

	const char *a1_hex =
		auth_digest_get_hash_a1(hmethod, a1_secret, dclient->nonce,
					dclient->cnonce, client->set.authzid);
	dclient->a1_hex = p_strdup(client->pool, a1_hex);

	const char *response_hex =
		auth_digest_get_client_response(
			hmethod, a1_hex, "AUTHENTICATE", dclient->req_uri,
			dclient->qop, dclient->nonce, dclient->nc,
			dclient->cnonce, NULL);
	str_append(str, ",response=\"");
	str_append(str, response_hex);
	str_append(str, "\"");
	if (client->set.authzid != NULL) {
		str_append(str, ",authzid=\"");
		str_append(str, client->set.authzid);
		str_append(str, "\"");
	}

	return str;
}

static int
mech_digest_md5_input_final(struct digest_md5_dsasl_client *dclient,
			    const unsigned char *input, size_t input_len,
			    const char **error_r)
{
	char *copy;
	const char *rspauth = NULL;
	bool failed = FALSE;

	/*
	   realm="hostname" (multiple allowed)
	   nonce="randomized data, at least 64bit"
	   qop="auth,auth-int,auth-conf"
	   maxbuf=number (with auth-int, auth-conf, defaults to 64k)
	   charset="utf-8" (iso-8859-1 if it doesn't exist)
	   algorithm="md5-sess"
	   cipher="3des,des,rc4-40,rc4,rc4-56" (with auth-conf)
	*/

	if (input_len == 0) {
		*error_r = "Empty server confirmation";
		return -1;
	}

	/* Treating challenge as NUL-terminated string also gets rid of all
	   potential problems with NUL characters in strings. */
	copy = t_strdup_noconst(t_strndup(input, input_len));
	rspauth = NULL;
	while (*copy != '\0') {
		const char *key, *value;

		if (auth_digest_parse_keyvalue(&copy, &key, &value)) {
			const char *error;

			if (!handle_confirmation_field(dclient, key, value,
						       &rspauth, &error)) {
				*error_r = t_strdup_printf(
					"Server sent invalid confirmation field '%s': "
					"%s", key, error);
				failed = TRUE;
				break;
			}
		}

		if (*copy == ',')
			copy++;
	}

	if (!failed) {
		if (rspauth == NULL) {
			*error_r = "Missing rspauth parameter";
			failed = TRUE;
		} else if (strlen(rspauth) != hmethod->digest_size * 2) {
			*error_r = "Invalid length for rspauth";
			failed = TRUE;
		}
	}

	if (failed)
		return -1;

	/* Calculate server response locally */
	const char *response_hex = auth_digest_get_server_response(
		hmethod, dclient->a1_hex, dclient->req_uri, dclient->qop,
		dclient->nonce, dclient->nc, dclient->cnonce, NULL);

	/* Verify response */
	if (!mem_equals_timing_safe(response_hex, rspauth,
				    hmethod->digest_size * 2)) {
		*error_r = "Incorrect rspauth field";
		return 0;
	}
	return 1;
}

static enum dsasl_client_result
mech_digest_md5_input(struct dsasl_client *client,
		      const unsigned char *input, size_t input_len,
		      const char **error_r)
{
	struct digest_md5_dsasl_client *dclient =
		container_of(client, struct digest_md5_dsasl_client, client);
	int ret;

	*error_r = NULL;

	switch (dclient->state) {
	case DIGEST_MD5_STATE_INIT:
		if (mech_digest_md5_init(dclient, error_r) < 0) {
			dclient->state = DIGEST_MD5_STATE_END;
			return DSASL_CLIENT_RESULT_ERR_INTERNAL;
		}
		dclient->state = DIGEST_MD5_STATE_SERVER_FIRST;
		/* Fall through */
	case DIGEST_MD5_STATE_SERVER_FIRST:
		if (mech_digest_md5_input_first(dclient, input, input_len,
						error_r) < 0) {
			dclient->state = DIGEST_MD5_STATE_END;
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}
		dclient->state = DIGEST_MD5_STATE_CLIENT_FIRST;
		return DSASL_CLIENT_RESULT_OK;
	case DIGEST_MD5_STATE_CLIENT_FIRST:
		i_unreached();
	case DIGEST_MD5_STATE_SERVER_FINAL:
		break;
	case DIGEST_MD5_STATE_CLIENT_FINAL:
	case DIGEST_MD5_STATE_END:
		i_unreached();
	}

	ret = mech_digest_md5_input_final(dclient, input, input_len, error_r);
	if (ret < 0) {
		dclient->state = DIGEST_MD5_STATE_END;
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (ret == 0) {
		dclient->state = DIGEST_MD5_STATE_END;
		return DSASL_CLIENT_RESULT_AUTH_FAILED;
	}
	dclient->state = DIGEST_MD5_STATE_CLIENT_FINAL;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_digest_md5_output(struct dsasl_client *client,
		       const unsigned char **output_r, size_t *output_len_r,
		       const char **error_r)
{
	struct digest_md5_dsasl_client *dclient =
		container_of(client, struct digest_md5_dsasl_client, client);
	string_t *str;

	switch (dclient->state) {
	case DIGEST_MD5_STATE_INIT:
		if (mech_digest_md5_init(dclient, error_r) < 0) {
			dclient->state = DIGEST_MD5_STATE_END;
			return DSASL_CLIENT_RESULT_ERR_INTERNAL;
		}
		dclient->state = DIGEST_MD5_STATE_SERVER_FIRST;
		/* Fall through */
	case DIGEST_MD5_STATE_SERVER_FIRST:
		*output_r = uchar_empty_ptr;
		*output_len_r = 0;
		return DSASL_CLIENT_RESULT_OK;
	case DIGEST_MD5_STATE_CLIENT_FIRST:
		str = mech_digest_md5_output_first(dclient);
		*output_r = str_data(str);
		*output_len_r = str_len(str);
		dclient->state = DIGEST_MD5_STATE_SERVER_FINAL;
		return DSASL_CLIENT_RESULT_OK;
	case DIGEST_MD5_STATE_SERVER_FINAL:
		i_unreached();
	case DIGEST_MD5_STATE_CLIENT_FINAL:
		break;
	case DIGEST_MD5_STATE_END:
		i_unreached();
	}

	*output_r = uchar_empty_ptr;
	*output_len_r = 0;
	dclient->state = DIGEST_MD5_STATE_END;
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_digest_md5 = {
	.name = SASL_MECH_NAME_DIGEST_MD5,
	.struct_size = sizeof(struct digest_md5_dsasl_client),

	.input = mech_digest_md5_input,
	.output = mech_digest_md5_output,
};
