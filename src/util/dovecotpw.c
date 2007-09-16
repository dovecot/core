/* Copyright (C) 2004 Joshua Goodall */

#include "lib.h"
#include "array.h"
#include "password-scheme.h"
#include "randgen.h"
#include "safe-memset.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_LIBGEN_H
#  include <libgen.h>
#endif

#define DEFAULT_SCHEME "HMAC-MD5"

static void ATTR_NORETURN
usage(const char *s)
{
	fprintf(stderr,
	    "usage: %s [-l] [-p plaintext] [-s scheme] [-u user] [-V]\n", s);
	fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n",
	    "    -l            List known password schemes",
	    "    -p plaintext  New password",
	    "    -s scheme     Password scheme",
	    "    -u user       Username (if scheme uses it)",
	    "    -V            Internally verify the hash");

	exit(1);
}

int main(int argc, char *argv[])
{
	const char *hash = NULL;
	const char *user = NULL;
	char *scheme = NULL;
	char *plaintext = NULL;
	int ch, lflag = 0, Vflag = 0;

	lib_init();
	random_init();
	password_schemes_init();
	
	while ((ch = getopt(argc, argv, "lp:s:u:V")) != -1) {
		switch (ch) {
		case 'l':
			lflag = 1;
			break;
		case 'p':
			plaintext = i_strdup(optarg);
			safe_memset(optarg, 0, strlen(optarg));
			break;
		case 's':
			scheme = i_strdup(optarg);
			break;
		case 'u':
			user = i_strdup(optarg);
			break;
		case 'V':
			Vflag = 1;
			break;
		case '?':
		default:
			usage(basename(*argv));
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
		usage(basename(*argv));

	if (scheme == NULL)
		scheme = i_strdup(DEFAULT_SCHEME);
	else {
		char *c;
		for (c = scheme; *c != '\0'; c++)
			*c = i_toupper(*c);
	}


	while (plaintext == NULL) {
		char *check;
		static int lives = 3;

		plaintext = i_strdup(getpass("Enter new password: "));
		check = i_strdup(getpass("Retype new password: "));
		if (strcmp(plaintext, check) != 0) {
			fprintf(stderr, "Passwords don't match!\n");
			if (--lives == 0)
				exit(1);
			safe_memset(plaintext, 0, strlen(plaintext));
			safe_memset(check, 0, strlen(check));
			i_free(plaintext);
			i_free(check);
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

        return 0;
}
