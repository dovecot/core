#ifndef AUTH_SCRAM_H
#define AUTH_SCRAM_H

struct auth_scram_key_data {
	pool_t pool;
	const struct hash_method *hmethod;

	unsigned int iter_count;
	const char *salt;
	unsigned char *stored_key;
	unsigned char *server_key;
};

void auth_scram_hi(const struct hash_method *hmethod,
		   const unsigned char *str, size_t str_size,
		   const unsigned char *salt, size_t salt_size, unsigned int i,
		   unsigned char *result);

#endif
