/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "hex-binary.h"
#include "md5.h"
#include "mycrypt.h"
#include "randgen.h"
#include "password-scheme.h"

int password_verify(const char *plaintext, const char *password,
		    const char *scheme, const char *user)
{
	unsigned char digest[16];
	const char *realm, *str;

	if (password == NULL)
		return 0;

	if (strcasecmp(scheme, "CRYPT") == 0)
		return strcmp(mycrypt(password, plaintext), plaintext) == 0;

	if (strcasecmp(scheme, "PLAIN") == 0)
		return strcmp(password, plaintext) == 0;

	if (strcasecmp(scheme, "DIGEST-MD5") == 0) {
		/* user:realm:passwd */
		realm = strchr(user, '@');
		if (realm != NULL) realm++; else realm = "";

		str = t_strconcat(t_strcut(user, '@'), ":", realm,  ":",
				  plaintext, NULL);
		md5_get_digest(str, strlen(str), digest);
		str = binary_to_hex(digest, sizeof(digest));

		return strcasecmp(str, password) == 0;
	}

	if (strcasecmp(scheme, "PLAIN-MD5") == 0) {
		md5_get_digest(plaintext, strlen(plaintext), digest);
		str = binary_to_hex(digest, sizeof(digest));
		return strcasecmp(str, password) == 0;
	}

	return -1;
}

const char *password_get_scheme(const char **password)
{
	const char *p, *scheme;

	if (*password == NULL || **password != '{')
		return NULL;

	p = strchr(*password, '}');
	if (p == NULL)
		return NULL;

	scheme = t_strdup_until(*password + 1, p);
	*password = p + 1;
	return scheme;
}

const char *password_generate(const char *plaintext, const char *user,
			      const char *scheme)
{
	static const char *salt_chars =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";
	const char *realm, *str;
	unsigned char digest[16];
	char salt[3];

	if (strcasecmp(scheme, "CRYPT") == 0) {
		random_fill(salt, 2);
		salt[0] = salt_chars[salt[0] % (sizeof(salt_chars)-1)];
		salt[1] = salt_chars[salt[1] % (sizeof(salt_chars)-1)];
		salt[2] = '\0';
		return t_strdup(mycrypt(plaintext, salt));
	}

	if (strcasecmp(scheme, "PLAIN") == 0)
		return plaintext;

	if (strcasecmp(scheme, "DIGEST-MD5") == 0) {
		/* user:realm:passwd */
		realm = strchr(user, '@');
		if (realm != NULL) realm++; else realm = "";

		str = t_strconcat(t_strcut(user, '@'), ":", realm,  ":",
				  plaintext, NULL);
		md5_get_digest(str, strlen(str), digest);
		return binary_to_hex(digest, sizeof(digest));
	}

	if (strcasecmp(scheme, "PLAIN-MD5") == 0) {
		md5_get_digest(plaintext, strlen(plaintext), digest);
		return binary_to_hex(digest, sizeof(digest));
	}

	return NULL;
}
