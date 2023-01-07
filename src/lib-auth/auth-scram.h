#ifndef AUTH_SCRAM_H
#define AUTH_SCRAM_H

/* SCRAM allowed iteration count range. RFC says it SHOULD be at least 4096 */
#define AUTH_SCRAM_MIN_ITERATE_COUNT 4096
#define AUTH_SCRAM_MAX_ITERATE_COUNT INT_MAX

#define AUTH_SCRAM_DEFAULT_ITERATE_COUNT 4096

struct auth_scram_key_data {
	pool_t pool;
	const struct hash_method *hmethod;

	unsigned int iter_count;
	const char *salt;
	unsigned char *stored_key;
	unsigned char *server_key;
};

void auth_scram_key_data_clear(struct auth_scram_key_data *data);

void auth_scram_hi(const struct hash_method *hmethod,
		   const unsigned char *str, size_t str_size,
		   const unsigned char *salt, size_t salt_size, unsigned int i,
		   unsigned char *result);

void auth_scram_generate_key_data(const struct hash_method *hmethod,
				  const char *plaintext, unsigned int rounds,
				  unsigned int *iter_count_r,
				  const char **salt_r,
				  unsigned char stored_key_r[],
				  unsigned char server_key_r[]);
#endif
