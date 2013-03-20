/* Copyright (c) 2004-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "password-scheme.h"
#include "randgen.h"
#include "doveadm.h"
#include "askpass.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEFAULT_SCHEME "CRAM-MD5"

static void cmd_pw(int argc, char *argv[])
{
	const char *hash = NULL;
	const char *user = NULL;
	const char *scheme = NULL;
	const char *plaintext = NULL;
	const char *test_hash = NULL;
	bool list_schemes = FALSE, reverse_verify = FALSE;
	unsigned int rounds = 0;
	int c;

	random_init();
	password_schemes_init();
	
	while ((c = getopt(argc, argv, "lp:r:s:t:u:V")) > 0) {
		switch (c) {
		case 'l':
			list_schemes = 1;
			break;
		case 'p':
			plaintext = optarg;
			break;
		case 'r':
			if (str_to_uint(optarg, &rounds) < 0)
				i_fatal("Invalid number of rounds: %s", optarg);
			break;
		case 's':
			scheme = optarg;
			break;
		case 't':
			test_hash = optarg;
			reverse_verify = TRUE;
			break;
		case 'u':
			user = optarg;
			break;
		case 'V':
			reverse_verify = TRUE;
			break;
		case '?':
		default:
			help(&doveadm_cmd_pw);
		}
	}

	if (list_schemes) {
		const struct password_scheme *const *schemes;
		unsigned int i, count;

		schemes = array_get(&password_schemes, &count);
		for (i = 0; i < count; i++)
			printf("%s ", schemes[i]->name);
		printf("\n");
		exit(0);
	}

	if (argc != optind)
		help(&doveadm_cmd_pw);

	scheme = scheme == NULL ? DEFAULT_SCHEME : t_str_ucase(scheme);
	if (rounds > 0)
		password_set_encryption_rounds(rounds);

	if (test_hash != NULL && plaintext == NULL)
		plaintext = t_askpass("Enter password to verify: ");
	while (plaintext == NULL) {
		const char *check;
		static int lives = 3;

		plaintext = t_askpass("Enter new password: ");
		check = t_askpass("Retype new password: ");
		if (strcmp(plaintext, check) != 0) {
			i_error("Passwords don't match!");
			if (--lives == 0)
				exit(1);
			plaintext = NULL;
		}
	}

	if (!password_generate_encoded(plaintext, user, scheme, &hash))
		i_fatal("Unknown scheme: %s", scheme);
	if (reverse_verify) {
		const unsigned char *raw_password;
		size_t size;
		const char *error;

		if (test_hash != NULL) {
			scheme = password_get_scheme(&test_hash);
			if (scheme == NULL)
				i_fatal("Missing {scheme} prefix from hash");
			hash = test_hash;
		}

		if (password_decode(hash, scheme, &raw_password, &size,
				    &error) <= 0)
			i_fatal("reverse decode check failed: %s", error);

		if (password_verify(plaintext, user, scheme,
				    raw_password, size, &error) <= 0) {
			i_fatal("reverse password verification check failed: %s",
				error);
		}

		printf("{%s}%s (verified)\n", scheme, hash);
	} else {
		printf("{%s}%s\n", scheme, hash);
	}

	password_schemes_deinit();
	random_deinit();
}

struct doveadm_cmd doveadm_cmd_pw = {
	cmd_pw, "pw",
	"[-l] [-p plaintext] [-r rounds] [-s scheme] [-t hash] [-u user] [-V]"
};
