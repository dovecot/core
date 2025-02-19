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

#endif
