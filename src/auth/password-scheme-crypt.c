/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mycrypt.h"
#include "password-scheme.h"
#include "crypt-blowfish.h"
#include "randgen.h"

/* Lengths and limits for some crypt() algorithms. */
#define CRYPT_BLF_ROUNDS_DEFAULT 5
#define CRYPT_BLF_ROUNDS_MIN 4
#define CRYPT_BLF_ROUNDS_MAX 31
#define CRYPT_BLF_SALT_LEN 16 /* raw salt */
#define CRYPT_BLF_PREFIX_LEN (7+22+1) /* $2.$nn$ + salt */
#define CRYPT_BLF_BUFFER_LEN 128
#define CRYPT_BLF_PREFIX "$2y"
#define CRYPT_SHA2_ROUNDS_DEFAULT 5000
#define CRYPT_SHA2_ROUNDS_MIN 1000
#define CRYPT_SHA2_ROUNDS_MAX 999999999
#define CRYPT_SHA2_SALT_LEN 16

static void
crypt_generate_des(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
#define CRYPT_SALT_LEN 2
	const char *password, *salt;

	salt = password_generate_salt(CRYPT_SALT_LEN);
	password = t_strdup(mycrypt(plaintext, salt));
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
crypt_generate_blowfish(const char *plaintext, const struct password_generate_params *params,
			 const unsigned char **raw_password_r, size_t *size_r)
{
	char salt[CRYPT_BLF_SALT_LEN];
	char password[CRYPT_BLF_BUFFER_LEN];
	char magic_salt[CRYPT_BLF_PREFIX_LEN];
	unsigned int rounds = params->rounds;

	if (rounds == 0)
		rounds = CRYPT_BLF_ROUNDS_DEFAULT;
	else if (rounds < CRYPT_BLF_ROUNDS_MIN)
		rounds = CRYPT_BLF_ROUNDS_MIN;
	else if (rounds > CRYPT_BLF_ROUNDS_MAX)
		rounds = CRYPT_BLF_ROUNDS_MAX;

	random_fill(salt, CRYPT_BLF_SALT_LEN);
	if (crypt_gensalt_blowfish_rn(CRYPT_BLF_PREFIX, rounds,
				      salt, CRYPT_BLF_SALT_LEN,
				      magic_salt, CRYPT_BLF_PREFIX_LEN) == NULL)
		i_fatal("crypt_gensalt_blowfish_rn failed: %m");

	if (crypt_blowfish_rn(plaintext, magic_salt, password,
			       CRYPT_BLF_BUFFER_LEN) == NULL)
		i_fatal("crypt_blowfish_rn failed: %m");

	*raw_password_r = (const unsigned char *)t_strdup(password);
	*size_r = strlen(password);
}

static int
crypt_verify_blowfish(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		      const unsigned char *raw_password, size_t size,
		      const char **error_r)
{
	const char *password;
	const char *salt;
	char crypted[CRYPT_BLF_BUFFER_LEN];

	if (size == 0) {
		/* the default mycrypt() handler would return match */
		return 0;
	}
	password = t_strndup(raw_password, size);

	if (size < CRYPT_BLF_PREFIX_LEN ||
	    !str_begins(password, "$2") ||
	    password[2] < 'a' || password[2] > 'z' ||
	    password[3] != '$') {
		*error_r = "Password is not blowfish password";
		return -1;
	}

	salt = t_strndup(password, CRYPT_BLF_PREFIX_LEN);
	if (crypt_blowfish_rn(plaintext, salt, crypted, CRYPT_BLF_BUFFER_LEN) == NULL) {
		/* really shouldn't happen unless the system is broken */
		*error_r = t_strdup_printf("crypt_blowfish_rn failed: %m");
		return -1;
	}

	return strcmp(crypted, password) == 0 ? 1 : 0;
}

static void
crypt_generate_sha256(const char *plaintext, const struct password_generate_params *params,
		      const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password, *salt, *magic_salt;
	unsigned int rounds = params->rounds;

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
crypt_generate_sha512(const char *plaintext, const struct password_generate_params *params,
		      const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password, *salt, *magic_salt;
	unsigned int rounds = params->rounds;

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
	{ "08/15!test~4711", "JB", "JBOZ0DgmtucwE" },
	{ "08/15!test~4711", "$5$rounds=1000$0123456789abcdef",
	  "$5$rounds=1000$0123456789abcdef$K/DksR0DT01hGc8g/kt"
	  "9McEgrbFMKi9qrb1jehe7hn4" },
	{ "08/15!test~4711", "$6$rounds=1000$0123456789abcdef",
	  "$6$rounds=1000$0123456789abcdef$ZIAd5WqfyLkpvsVCVUU1GrvqaZTq"
	  "vhJoouxdSqJO71l9Ld3tVrfOatEjarhghvEYADkq//LpDnTeO90tcbtHR1" }
};

/* keep in sync with the sample struct above */
static const struct password_scheme crypt_schemes[] = {
	{ "DES-CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
	  crypt_generate_des },
	{ "SHA256-CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
	  crypt_generate_sha256 },
	{ "SHA512-CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
	  crypt_generate_sha512 }
};

static const struct password_scheme blf_crypt_scheme = {
	"BLF-CRYPT", PW_ENCODING_NONE, 0, crypt_verify_blowfish,
		crypt_generate_blowfish
};

static const struct password_scheme default_crypt_scheme = {
	"CRYPT", PW_ENCODING_NONE, 0, crypt_verify,
		crypt_generate_blowfish
};

void password_scheme_register_crypt(void)
{
	unsigned int i;
	const char *crypted;

	i_assert(N_ELEMENTS(crypt_schemes) == N_ELEMENTS(sample));

	for (i = 0; i < N_ELEMENTS(crypt_schemes); i++) {
		crypted = mycrypt(sample[i].key, sample[i].salt);
		if (crypted != NULL &&
		   (strcmp(crypted, sample[i].expected) == 0))
			password_scheme_register(&crypt_schemes[i]);
	}
	password_scheme_register(&blf_crypt_scheme);
	password_scheme_register(&default_crypt_scheme);
}
