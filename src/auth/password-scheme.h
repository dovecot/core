#ifndef __PASSWORD_SCHEME_H
#define __PASSWORD_SCHEME_H

/* Returns 1 = matched, 0 = didn't match, -1 = unknown scheme */
int password_verify(const char *plaintext, const char *password,
		    const char *scheme, const char *user);

/* Extracts scheme from password, or returns NULL if it isn't found. */
const char *password_get_scheme(const char **password);

/* Create wanted password scheme out of plaintext password and username. */
const char *password_generate(const char *plaintext, const char *user,
			      const char *scheme);

#endif
