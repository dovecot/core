/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"

#include "auth-digest.h"

/*
 * Parsing
 */

/* Linear whitespace */
#define IS_LWS(c) ((c) == ' ' || (c) == '\t')

bool auth_digest_parse_keyvalue(char **data, char **key_r, char **value_r)
{
	/* @UNSAFE */
	char *p, *dest;

	p = *data;
	while (IS_LWS(*p)) p++;

	/* get key */
	*key_r = p;
	while (*p != '\0' && *p != '=' && *p != ',')
		p++;

	if (*p != '=') {
		*data = p;
		return FALSE;
	}

	*value_r = p+1;

	/* skip trailing whitespace in key */
	while (p > *data && IS_LWS(p[-1]))
		p--;
	*p = '\0';

	/* get value */
	p = *value_r;
	while (IS_LWS(*p)) p++;

	if (*p != '"') {
		while (*p != '\0' && *p != ',')
			p++;

		*data = p;
		/* If there is more to parse, ensure it won't get skipped
		   because *p is set to NUL below */
		if (**data != '\0') (*data)++;
		while (IS_LWS(p[-1]))
			p--;
		*p = '\0';
	} else {
		/* quoted string */
		*value_r = dest = ++p;
		while (*p != '\0' && *p != '"') {
			if (*p == '\\' && p[1] != '\0')
				p++;
			*dest++ = *p++;
		}

		*data = *p == '"' ? p+1 : p;
		*dest = '\0';
	}

	return TRUE;
}

/*
 * Processing
 */

void auth_digest_get_hash_a1_secret(const struct hash_method *hmethod,
				    const char *username, const char *realm,
				    const char *password,
				    unsigned char *digest_r)
{
	struct hash_method_context ctx;

	/* A1 = unq(username) ":" unq(realm) ":" passwd */

	hash_method_init(&ctx, hmethod);
	hash_method_loop(&ctx, username, strlen(username));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, realm, strlen(realm));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, password, strlen(password));
	hash_method_result(&ctx, digest_r);
}
