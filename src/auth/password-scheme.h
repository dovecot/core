#ifndef __PASSWORD_SCHEME_H
#define __PASSWORD_SCHEME_H

struct password_scheme {
	const char *name;

	int (*password_verify)(const char *plaintext, const char *password,
			       const char *user);
	const char *(*password_generate)(const char *plaintext,
					 const char *user);
};

/* Returns 1 = matched, 0 = didn't match, -1 = unknown scheme */
int password_verify(const char *plaintext, const char *password,
		    const char *scheme, const char *user);

/* Extracts scheme from password, or returns NULL if it isn't found. */
const char *password_get_scheme(const char **password);

/* Create wanted password scheme out of plaintext password and username. */
const char *password_generate(const char *plaintext, const char *user,
			      const char *scheme);

/* Iterate through the list of password schemes, returning names */
const char *password_list_schemes(const struct password_scheme **listptr);

void password_schemes_init(void);
void password_schemes_deinit(void);

/* INTERNAL: */
const char *password_generate_md5_crypt(const char *pw, const char *salt);
const char *password_generate_cram_md5(const char *pw);
const char *password_generate_ntlm(const char *pw);

#endif
