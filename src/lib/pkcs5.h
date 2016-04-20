#ifndef PKCS5_H
#define PKCS5_H 1

enum pkcs5_pbkdf_mode {
	PKCS5_PBKDF1,
	PKCS5_PBKDF2
};

/*

 mode         - v1.0 or v2.0
 hash         - hash_method_lookup return value
 password     - private password for generation
 password_len - length of password in octets
 salt         - salt for generation
 salt_len     - length of salt in octets
 iterations   - number of iterations to hash (use at least 1000, a very large number => very very slow)
 dk_len       - number of bytes to return from derived key
 result       - buffer_t to hold the result, either use dynamic or make sure it fits dk_len

 non-zero return value indicates that either iterations was less than 1 or dk_len was too large

 Sample code:

 buffer_t *result = buffer_create_dynamic(pool_datastack_create(), 256);
 if (pkcs5_pbkdf(PKCS5_PBKDF2, hash_method_lookup("sha256"), "password", 8, "salt", 4, 4096, 256, result) != 0) { // error }

*/

int pkcs5_pbkdf(enum pkcs5_pbkdf_mode mode, const struct hash_method *hash,
	const unsigned char *password, size_t password_len,
	const unsigned char *salt, size_t salt_len,
	unsigned int iterations, uint32_t dk_len,
	buffer_t *result);
#endif
