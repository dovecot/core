/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
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

const char *auth_field_line_hide_secrets(const char *line)
{
	const char *const *fields = t_strsplit_tabescaped(line);
	string_t *str = t_str_new(strlen(line));
	const char *value;

	for (unsigned int i = 0; fields[i] != NULL; i++) {
		if (i > 0)
			str_append_c(str, '\t');
		if (str_begins(fields[i], "userdb_fields=", &value)) {
			const char *const *userdb_fields =
				t_strsplit_tabescaped(value);
			string_t *userdb_str = t_str_new(strlen(value));

			for (unsigned int j = 0; userdb_fields[j] != NULL; j++) {
				if (j > 0)
					str_append_c(userdb_str, '\t');
				str_append_tabescaped(userdb_str,
					auth_field_hide_secret(userdb_fields[j]));
			}
			str_append(str, "userdb_fields=");
			str_append_tabescaped(str, str_c(userdb_str));
		} else {
			str_append_tabescaped(str,
				auth_field_hide_secret(fields[i]));
		}
	}
	return str_c(str);
}
