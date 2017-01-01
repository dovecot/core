/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "password-scheme.h"
#include "hex-binary.h"
#include "hash-method.h"
#include "pkcs5.h"

#define PBKDF2_KEY_SIZE_SHA1 20

#define PBKDF2_GENERATE_SALT_LEN      16
#define PBKDF2_ROUNDS_DEFAULT          5000

static void
pbkdf_run(const char *plaintext, const char *salt,
	  unsigned int rounds, unsigned char key_r[PBKDF2_KEY_SIZE_SHA1])
{
	memset(key_r, 0, PBKDF2_KEY_SIZE_SHA1);
	buffer_t buf;
	buffer_create_from_data(&buf, key_r, PBKDF2_KEY_SIZE_SHA1);

	pkcs5_pbkdf(PKCS5_PBKDF2, hash_method_lookup("sha1"),
		(const unsigned char *)plaintext, strlen(plaintext),
		(const unsigned char *)salt, strlen(salt),
		rounds, PBKDF2_KEY_SIZE_SHA1, &buf);
}

void pbkdf2_generate(const char *plaintext, const char *user ATTR_UNUSED,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char key[PBKDF2_KEY_SIZE_SHA1];
	const char *salt;
	string_t *str = t_str_new(64);
	unsigned int rounds = password_scheme_encryption_rounds;

	if (rounds == 0)
		rounds = PBKDF2_ROUNDS_DEFAULT;
	salt = password_generate_salt(PBKDF2_GENERATE_SALT_LEN);
	pbkdf_run(plaintext, salt, rounds, key);

	str_printfa(str, "$1$%s$%u$", salt, rounds);
	binary_to_hex_append(str, key, sizeof(key));

	*raw_password_r = str_data(str);
	*size_r = str_len(str);
}

int pbkdf2_verify(const char *plaintext, const char *user ATTR_UNUSED,
	      const unsigned char *raw_password, size_t size,
	      const char **error_r)
{
	const char *const *fields;
	const char *salt;
	unsigned int rounds;
	unsigned char key1[PBKDF2_KEY_SIZE_SHA1], key2[PBKDF2_KEY_SIZE_SHA1];
	buffer_t buf;

	/* $1$salt$rounds$hash */
	if (size < 3 || memcmp(raw_password, "$1$", 3) != 0) {
		*error_r = "Invalid PBKDF2 passdb entry prefix";
		return -1;
	}

	fields = t_strsplit(t_strndup(raw_password + 3, size - 3), "$");
	salt = fields[0];
	if (str_array_length(fields) != 3 ||
	    str_to_uint(fields[1], &rounds) < 0) {
		*error_r = "Invalid PBKDF2 passdb entry format";
		return -1;
	}
	buffer_create_from_data(&buf, key1, sizeof(key1));
	if (strlen(fields[2]) != sizeof(key1)*2 ||
	    hex_to_binary(fields[2], &buf) < 0) {
		*error_r = "PBKDF2 hash not 160bit hex-encoded";
		return -1;
	}

	pbkdf_run(plaintext, salt, rounds, key2);
	return memcmp(key1, key2, sizeof(key1)) == 0 ? 1 : 0;
}
