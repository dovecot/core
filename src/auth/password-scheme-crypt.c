/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mycrypt.h"
#include "password-scheme.h"

/* Lengths and limits for some crypt() algorithms. */
#define CRYPT_BLF_ROUNDS_DEFAULT 5
#define CRYPT_BLF_ROUNDS_MIN 4
#define CRYPT_BLF_ROUNDS_MAX 31
#define CRYPT_BLF_SALT_LEN 22
#define CRYPT_SHA2_ROUNDS_DEFAULT 5000
#define CRYPT_SHA2_ROUNDS_MIN 1000
#define CRYPT_SHA2_ROUNDS_MAX 999999999
#define CRYPT_SHA2_SALT_LEN 16

static unsigned int encryption_rounds = 0;

void password_set_encryption_rounds(unsigned int rounds)
{
	/* just take the new value. crypt_generate_*() will enforce their
	   limits. */
	encryption_rounds = rounds;
}

static void
crypt_generate_blowfisch(const char *plaintext, const char *user ATTR_UNUSED,
			 const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password, *salt, *magic_salt;
	unsigned int rounds = encryption_rounds;

	if (rounds == 0)
		rounds = CRYPT_BLF_ROUNDS_DEFAULT;
	else if (rounds < CRYPT_BLF_ROUNDS_MIN)
		rounds = CRYPT_BLF_ROUNDS_MIN;
	else if (rounds > CRYPT_BLF_ROUNDS_MAX)
		rounds = CRYPT_BLF_ROUNDS_MAX;

	salt = password_generate_salt(CRYPT_BLF_SALT_LEN);
	magic_salt = t_strdup_printf("$2a$%02u$%s", rounds, salt);
	password = t_strdup(mycrypt(plaintext, magic_salt));
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
crypt_generate_sha256(const char *plaintext, const char *user ATTR_UNUSED,
		      const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password, *salt, *magic_salt;
	unsigned int rounds = encryption_rounds;

	if (rounds == 0)
		rounds = CRYPT_SHA2_ROUNDS_DEFAULT;
	else if (rounds < CRYPT_SHA2_ROUNDS_MIN)
		rounds = CRYPT_SHA2_ROUNDS_MIN;
	else if (rounds > CRYPT_SHA2_ROUNDS_MAX)
		rounds = CRYPT_SHA2_ROUNDS_MAX;

	salt = password_generate_salt(CRYPT_SHA2_SALT_LEN);
	if (rounds == CRYPT_SHA2_ROUNDS_DEFAULT)
		magic_salt = t_strdup_printf("$5$%s", salt);
	else
		magic_salt = t_strdup_printf("$5$rounds=%u$%s", rounds, salt);
	password = t_strdup(mycrypt(plaintext, magic_salt));
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
crypt_generate_sha512(const char *plaintext, const char *user ATTR_UNUSED,
		      const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password, *salt, *magic_salt;
	unsigned int rounds = encryption_rounds;

	if (rounds == 0)
		rounds = CRYPT_SHA2_ROUNDS_DEFAULT;
	else if (rounds < CRYPT_SHA2_ROUNDS_MIN)
		rounds = CRYPT_SHA2_ROUNDS_MIN;
	else if (rounds > CRYPT_SHA2_ROUNDS_MAX)
		rounds = CRYPT_SHA2_ROUNDS_MAX;

	salt = password_generate_salt(CRYPT_SHA2_SALT_LEN);
	if (rounds == CRYPT_SHA2_ROUNDS_DEFAULT)
		magic_salt = t_strdup_printf("$6$%s", salt);
	else
		magic_salt = t_strdup_printf("$6$rounds=%u$%s", rounds, salt);
	password = t_strdup(mycrypt(plaintext, magic_salt));
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

/* keep in sync with the crypt_schemes struct below */
static const struct {
	const char *key;
	const char *salt;
	const char *expected;
} sample[] = {
	{ "08/15!test~4711", "$2a$04$0123456789abcdefABCDEF",
	  "$2a$04$0123456789abcdefABCDE.N.drYX5yIAL1LkTaaZotW3yI0hQhZru" },
	{ "08/15!test~4711", "$5$rounds=1000$0123456789abcdef",
	  "$5$rounds=1000$0123456789abcdef$K/DksR0DT01hGc8g/kt"
	  "9McEgrbFMKi9qrb1jehe7hn4" },
	{ "08/15!test~4711", "$6$rounds=1000$0123456789abcdef",
	  "$6$rounds=1000$0123456789abcdef$ZIAd5WqfyLkpvsVCVUU1GrvqaZTq"
	  "vhJoouxdSqJO71l9Ld3tVrfOatEjarhghvEYADkq//LpDnTeO90tcbtHR1" }
};

/* keep in sync with the sample struct above */
static const struct password_scheme crypt_schemes[] = {
	{ "BLF-CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
	  crypt_generate_blowfisch },
	{ "SHA256-CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
	  crypt_generate_sha256 },
	{ "SHA512-CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
	  crypt_generate_sha512 }
};

void password_scheme_register_crypt(void)
{
	unsigned int i;
	const char *crypted;

	for (i = 0; i < N_ELEMENTS(crypt_schemes); i++) {
		crypted = mycrypt(sample[i].key, sample[i].salt);
		if (crypted != NULL &&
		   (strcmp(crypted, sample[i].expected) == 0))
			password_scheme_register(&crypt_schemes[i]);
	}
}
