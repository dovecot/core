/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-binary.h"
#include "hash-method.h"

#include "auth-digest.h"

/*
 * Parsing
 */

/* Linear whitespace */
#define IS_LWS(c) ((c) == ' ' || (c) == '\t')

bool auth_digest_parse_keyvalue(char **data, char **key_r, char **value_r)
{
	/* @UNSAFE */
	char *p, *dest;

	p = *data;
	while (IS_LWS(*p)) p++;

	/* get key */
	*key_r = p;
	while (*p != '\0' && *p != '=' && *p != ',')
		p++;

	if (*p != '=') {
		*data = p;
		return FALSE;
	}

	*value_r = p+1;

	/* skip trailing whitespace in key */
	while (p > *data && IS_LWS(p[-1]))
		p--;
	*p = '\0';

	/* get value */
	p = *value_r;
	while (IS_LWS(*p)) p++;

	if (*p != '"') {
		while (*p != '\0' && *p != ',')
			p++;

		*data = p;
		/* If there is more to parse, ensure it won't get skipped
		   because *p is set to NUL below */
		if (**data != '\0') (*data)++;
		while (IS_LWS(p[-1]))
			p--;
		*p = '\0';
	} else {
		/* quoted string */
		*value_r = dest = ++p;
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

/*
 * Processing
 */

void auth_digest_get_hash_a1_secret(const struct hash_method *hmethod,
				    const char *username, const char *realm,
				    const char *password,
				    unsigned char *digest_r)
{
	struct hash_method_context ctx;

	/* A1 = unq(username) ":" unq(realm) ":" passwd */

	hash_method_init(&ctx, hmethod);
	hash_method_loop(&ctx, username, strlen(username));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, realm, strlen(realm));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, password, strlen(password));
	hash_method_result(&ctx, digest_r);
}

const char *
auth_digest_get_hash_a1(const struct hash_method *hmethod,
			const unsigned char *hash_a1_secret,
			const char *nonce, const char *cnonce,
			const char *authzid)
{
	struct hash_method_context ctx;

	if (nonce == NULL)
		return binary_to_hex(hash_a1_secret, hmethod->digest_size);
	i_assert(cnonce != NULL);

	unsigned char digest[hmethod->digest_size];

	/* A1       = H( unq(username) ":" unq(realm) ":" passwd )
			  ":" unq(nonce-prime) ":" unq(cnonce-prime)

	   If authzid is not NULL it is added in an additional ":" authzid as
	   per RFC 2831.
	 */

	hash_method_init(&ctx, hmethod);
	hash_method_loop(&ctx, hash_a1_secret, hmethod->digest_size);
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, nonce, strlen(nonce));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, cnonce, strlen(cnonce));
	if (authzid != NULL) {
		hash_method_loop(&ctx, ":", 1);
		hash_method_loop(&ctx, authzid, strlen(authzid));
	}
	hash_method_result(&ctx, digest);

	return binary_to_hex(digest, sizeof(digest));
}

const char *
auth_digest_get_hash_a2(const struct hash_method *hmethod,
			const char *req_method, const char *req_uri,
			const char *entity_body_hash)
{
	struct hash_method_context ctx;
	unsigned char digest[hmethod->digest_size];

	/* If the qop parameter's value is "auth" or is unspecified, then A2 is:
	         A2       = Method ":" request-uri

	   If the qop value is "auth-int", then A2 is:

	         A2       = Method ":" request-uri ":" H(entity-body)
	 */

	hash_method_init(&ctx, hmethod);
	if (req_method != NULL)
		hash_method_loop(&ctx, req_method, strlen(req_method));
	hash_method_loop(&ctx, ":", 1);
	if (req_uri != NULL)
		hash_method_loop(&ctx, req_uri, strlen(req_uri));
	if (entity_body_hash != NULL) {
		hash_method_loop(&ctx, ":", 1);
		hash_method_loop(&ctx, entity_body_hash,
				 strlen(entity_body_hash));
	}
	hash_method_result(&ctx, digest);

	return binary_to_hex(digest, sizeof(digest));
}

static const char *
auth_digest_get_response(const struct hash_method *hmethod,
			 const char *hash_a1, const char *hash_a2,
			 const char *qop, const char *nonce, const char *nc,
			 const char *cnonce)
{
	/* response = <"> < KD ( H(A1), unq(nonce)
                                  ":" nc
                                  ":" unq(cnonce)
                                  ":" unq(qop)
                                  ":" H(A2)
                         ) <">
	 */

	struct hash_method_context ctx;
	unsigned char digest[hmethod->digest_size];

	hash_method_init(&ctx, hmethod);
	hash_method_loop(&ctx, hash_a1, strlen(hash_a1));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, nonce, strlen(nonce));
	hash_method_loop(&ctx, ":", 1);
	if (qop != NULL) {
		hash_method_loop(&ctx, nc, strlen(nc));
		hash_method_loop(&ctx, ":", 1);
		hash_method_loop(&ctx, cnonce, strlen(cnonce));
		hash_method_loop(&ctx, ":", 1);
		hash_method_loop(&ctx, qop, strlen(qop));
		hash_method_loop(&ctx, ":", 1);
	}
	hash_method_loop(&ctx, hash_a2, strlen(hash_a2));
	hash_method_result(&ctx, digest);

	return binary_to_hex(digest, sizeof(digest));
}

const char *
auth_digest_get_client_response(const struct hash_method *hmethod,
				const char *hash_a1, const char *req_method,
				const char *req_uri, const char *qop,
				const char *nonce, const char *nc,
				const char *cnonce,
				const char *entity_body_hash)
{
	const char *hash_a2;

	hash_a2 = auth_digest_get_hash_a2(hmethod, req_method, req_uri,
					  entity_body_hash);

	return auth_digest_get_response(hmethod, hash_a1, hash_a2,
					qop, nonce, nc, cnonce);
}

const char *
auth_digest_get_server_response(const struct hash_method *hmethod,
				const char *hash_a1, const char *req_uri,
				const char *qop, const char *nonce,
				const char *nc,	const char *cnonce,
				const char *entity_body_hash)
{
	const char *hash_a2;

	hash_a2 = auth_digest_get_hash_a2(hmethod, NULL, req_uri,
					  entity_body_hash);

	return auth_digest_get_response(hmethod, hash_a1, hash_a2,
					qop, nonce, nc, cnonce);
}
