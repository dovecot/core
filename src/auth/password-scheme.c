/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "hex-binary.h"
#include "md5.h"
#include "mycrypt.h"
#include "randgen.h"
#include "password-scheme.h"

static const char *salt_chars =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

int password_verify(const char *plaintext, const char *password,
		    const char *scheme, const char *user)
{
	unsigned char digest[16];
	const char *realm, *str;

	if (password == NULL)
		return 0;

	if (strcasecmp(scheme, "CRYPT") == 0)
		return strcmp(mycrypt(plaintext, password), password) == 0;

	if (strcasecmp(scheme, "MD5") == 0) {
                str = password_generate_md5_crypt(plaintext, password);
		return strcmp(str, password) == 0;
	}

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

	if (*password == NULL)
		return NULL;

	if (strncmp(*password, "$1$", 3) == 0) {
		/* skip the salt */
		p = strchr(*password + 3, '$');
		if (p != NULL) {
			/* stop at next '$' */
			p = strchr(p+1, '$');
			if (p != NULL)
				*password = t_strdup_until(*password, p);
			return "MD5";
		}
	}

	if (**password != '{')
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
	const char *realm, *str;
	unsigned char digest[16];
	char salt[9];
	int i;

	if (strcasecmp(scheme, "CRYPT") == 0) {
		random_fill(salt, 2);
		salt[0] = salt_chars[salt[0] % (sizeof(salt_chars)-1)];
		salt[1] = salt_chars[salt[1] % (sizeof(salt_chars)-1)];
		salt[2] = '\0';
		return t_strdup(mycrypt(plaintext, salt));
	}

	if (strcasecmp(scheme, "MD5") == 0) {
		random_fill(salt, 8);
		for (i = 0; i < 8; i++)
			salt[i] = salt_chars[salt[i] % (sizeof(salt_chars)-1)];
		salt[8] = '\0';
		return password_generate_md5_crypt(plaintext, salt);
	}

	if (strcasecmp(scheme, "PLAIN") == 0)
		return plaintext;

	if (strcasecmp(scheme, "CRAM-MD5") == 0)
		return password_generate_cram_md5(plaintext);

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
