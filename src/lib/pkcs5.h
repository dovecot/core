#ifndef PKCS5_H
#define PKCS5_H 1

/*

 hash         - hash_method_lookup return value
 password     - private password for generation
 password_len - length of password in octets
 salt         - salt for generation
 salt_len     - length of salt in octets
 iterations   - number of iterations to hash (use at least 1000, a very large number => very very slow)
 dk_len       - number of bytes to return from derived key
 result       - buffer_t to hold the result, either use dynamic or make sure it fits dk_len

 non-zero return value indicates that either iterations or dk_len was less than 1

 Sample code:

 buffer_t *result = t_buffer_create(256);
 if (pkcs5_pbkdf(hash_method_lookup("sha256"), "password", 8, "salt", 4, 4096, 256, result) != 0) { // error }

*/

int pkcs5_pbkdf(const struct hash_method *hash,
	const unsigned char *password, size_t password_len,
	const unsigned char *salt, size_t salt_len,
	unsigned int iterations, uint32_t dk_len,
	buffer_t *result);
#endif
