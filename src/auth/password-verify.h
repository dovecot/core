#ifndef __PASSWORD_VERIFY_H
#define __PASSWORD_VERIFY_H

/* Returns 1 = matched, 0 = didn't match, -1 = unknown scheme */
int password_verify(const char *plaintext, const char *password,
		    const char *scheme, const char *user);

/* Extracts scheme from password, or returns NULL if it isn't found. */
const char *password_get_scheme(const char **password);

#endif
