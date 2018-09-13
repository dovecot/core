/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "password-scheme.h"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>

static void
generate_argon2i(const char *plaintext, const struct password_generate_params *params,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned long long rounds = params->rounds;
	size_t memlimit;
	char result[crypto_pwhash_STRBYTES];

	if (rounds == 0)
		rounds = crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE;

	if (rounds >= crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE)
		memlimit = crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE;
	else if (rounds >= crypto_pwhash_argon2i_OPSLIMIT_MODERATE)
		memlimit = crypto_pwhash_argon2i_MEMLIMIT_MODERATE;
	else
		memlimit = crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE;

	if (crypto_pwhash_argon2i_str(result, plaintext, strlen(plaintext), rounds, memlimit) < 0)
		i_fatal("crypto_pwhash_argon2i_str failed: %m");
	*raw_password_r = (const unsigned char*)t_strdup(result);
	*size_r = strlen(result);
}

#ifdef crypto_pwhash_ALG_ARGON2ID13
static void
generate_argon2id(const char *plaintext, const struct password_generate_params *params,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned long long rounds = params->rounds;
	size_t memlimit;
	char result[crypto_pwhash_argon2id_STRBYTES];
	i_zero(&result);

	if (rounds == 0)
		rounds = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;

	if (rounds >= crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE)
		memlimit = crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE;
	else if (rounds >= crypto_pwhash_argon2id_OPSLIMIT_MODERATE)
		memlimit = crypto_pwhash_argon2id_MEMLIMIT_MODERATE;
	else
		memlimit = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE;

	/* XXX: Bug in sodium-1.0.13, it expects rounds to be 3 */
	if (rounds < 3)
		rounds = 3;

	if (crypto_pwhash_argon2id_str(result, plaintext, strlen(plaintext), rounds, memlimit) < 0)
		i_fatal("crypto_pwhash_argon2id_str failed: %m");
	*raw_password_r = (const unsigned char*)t_strdup(result);
	*size_r = strlen(result);
}
#endif

static int
verify_argon2(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	      const unsigned char *raw_password, size_t size,
	      const char **error_r ATTR_UNUSED)
{
	const char *passwd = t_strndup(raw_password, size);
	if (crypto_pwhash_str_verify(passwd, plaintext, strlen(plaintext)) < 0)
		return 0;
	return 1;
}


static const struct password_scheme sodium_schemes[] = {
	{ "ARGON2I", PW_ENCODING_NONE, 0, verify_argon2,
	  generate_argon2i },
#ifdef crypto_pwhash_ALG_ARGON2ID13
	{ "ARGON2ID", PW_ENCODING_NONE, 0, verify_argon2,
	  generate_argon2id },
#endif
};

void password_scheme_register_sodium(void)
{
	if (sodium_init() != 0)
		i_fatal("sodium_init() failed");
	for(size_t i = 0; i < N_ELEMENTS(sodium_schemes); i++)
		password_scheme_register(&sodium_schemes[i]);
}
#endif
