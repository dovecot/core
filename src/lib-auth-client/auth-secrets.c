/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-secrets.h"

static bool
auth_field_key_contains_icase(const char *key, size_t len, const char *part)
{
	for (size_t i = 0; i + strlen(part) <= len; i++) {
		if (str_begins_icase_with(key + i, part))
			return TRUE;
	}
	return FALSE;
}

static bool
auth_field_key_ends_with_icase(const char *key, size_t len, const char *suffix)
{
	return len >= strlen(suffix) &&
	       str_begins_icase_with(key + len - strlen(suffix), suffix);
}

static bool auth_field_key_is_secret_n(const char *key, size_t len)
{
	static const char *const secret_parts[] = {
		"pass", "pwd", "nonce", "hash", "secret",
	};
	static const char *const secret_suffixes[] = {
		"key", "key_file", "token",
	};

	for (unsigned int i = 0; i < N_ELEMENTS(secret_suffixes); i++) {
		if (auth_field_key_ends_with_icase(key, len, secret_suffixes[i]))
			return TRUE;
	}
	for (unsigned int i = 0; i < N_ELEMENTS(secret_parts); i++) {
		if (auth_field_key_contains_icase(key, len, secret_parts[i]))
			return TRUE;
	}
	return FALSE;
}

bool auth_field_key_is_secret(const char *key)
{
	return auth_field_key_is_secret_n(key, strlen(key));
}

bool auth_field_is_secret(const char *field)
{
	const char *eq = strchr(field, '=');

	if (eq == NULL)
		return FALSE;
	return auth_field_key_is_secret_n(field, eq - field);
}

const char *auth_field_hide_secret(const char *field)
{
	if (!auth_field_is_secret(field))
		return field;
	return t_strconcat(t_strdup_until(field, strchr(field, '=')),
			   "=<hidden>", NULL);
}
