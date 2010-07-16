/* Copyright (C) 2004 Joshua Goodall */

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
	int ch, lflag = 0, Vflag = 0;
	unsigned int rounds = 0;

	random_init();
	password_schemes_init();
	
	while ((ch = getopt(argc, argv, "lp:r:s:u:V")) != -1) {
		switch (ch) {
		case 'l':
			lflag = 1;
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
		case 'u':
			user = optarg;
			break;
		case 'V':
			Vflag = 1;
			break;
		case '?':
		default:
			help(&doveadm_cmd_pw);
		}
	}

	if (lflag) {
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

	while (plaintext == NULL) {
		const char *check;
		static int lives = 3;

		plaintext = t_askpass("Enter new password: ");
		check = t_askpass("Retype new password: ");
		if (strcmp(plaintext, check) != 0) {
			fprintf(stderr, "Passwords don't match!\n");
			if (--lives == 0)
				exit(1);
			plaintext = NULL;
		}
	}

	if (!password_generate_encoded(plaintext, user, scheme, &hash)) {
		fprintf(stderr, "Unknown scheme: %s\n", scheme);
		exit(1);
	}
	if (Vflag == 1) {
		const unsigned char *raw_password;
		size_t size;

		if (password_decode(hash, scheme, &raw_password, &size) <= 0) {
			fprintf(stderr, "reverse decode check failed\n");
			exit(2);
		}

		if (password_verify(plaintext, user, scheme,
				    raw_password, size) != 1) {
			fprintf(stderr,
				"reverse password verification check failed\n");
			exit(2);
		}

		printf("{%s}%s (verified)\n", scheme, hash);
	} else
		printf("{%s}%s\n", scheme, hash);

	password_schemes_deinit();
	random_deinit();
}

struct doveadm_cmd doveadm_cmd_pw = {
	cmd_pw, "pw",
	"[-l] [-p plaintext] [-r rounds] [-s scheme] [-u user] [-V]"
};
