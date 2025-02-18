#ifndef AUTH_DIGEST_H
#define AUTH_DIGEST_H

/*
 * Parsing
 */

bool auth_digest_parse_keyvalue(char **data, char **key_r, char **value_r);

/*
 * Processing
 */

void auth_digest_get_hash_a1_secret(const struct hash_method *hmethod,
				    const char *username, const char *realm,
				    const char *password,
				    unsigned char *digest_r);
const char *
auth_digest_get_hash_a1(const struct hash_method *hmethod,
			const unsigned char *hash_a1_secret,
			const char *nonce, const char *cnonce,
			const char *authzid);
const char *
auth_digest_get_hash_a2(const struct hash_method *hmethod,
			const char *req_method, const char *req_uri,
			const char *entity_body_hash);

const char *
auth_digest_get_client_response(const struct hash_method *hmethod,
				const char *hash_a1, const char *req_method,
				const char *req_uri, const char *qop,
				const char *nonce, const char *nc,
				const char *cnonce,
				const char *entity_body_hash);
const char *
auth_digest_get_server_response(const struct hash_method *hmethod,
				const char *hash_a1, const char *req_uri,
				const char *qop, const char *nonce,
				const char *nc,	const char *cnonce,
				const char *entity_body_hash);
#endif
