/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "str.h"
#include "var-expand.h"
#include "mail-user-hash.h"

bool mail_user_hash(const char *username, const char *format,
		    unsigned int *hash_r, const char **error_r)
{
	unsigned char md5[MD5_RESULTLEN];
	unsigned int i, hash = 0;
	char *error_dup = NULL;
	int ret = 1;

	if (strcmp(format, "%u") == 0) {
		/* fast path */
		md5_get_digest(username, strlen(username), md5);
	} else if (strcmp(format, "%Lu") == 0) {
		/* almost as fast path */
		T_BEGIN {
			md5_get_digest(t_str_lcase(username),
				       strlen(username), md5);
		} T_END;
	} else T_BEGIN {
		const struct var_expand_table tab[] = {
			{ 'u', username, "user" },
			{ 'n', t_strcut(username, '@'), "username" },
			{ 'd', i_strchr_to_next(username, '@'), "domain" },
			{ '\0', NULL, NULL }
		};
		string_t *str = t_str_new(128);
		const char *error;

		ret = var_expand(str, format, tab, &error);
		i_assert(ret >= 0);
		if (ret == 0)
			error_dup = i_strdup(error);
		md5_get_digest(str_data(str), str_len(str), md5);
	} T_END;
	for (i = 0; i < sizeof(hash); i++)
		hash = (hash << CHAR_BIT) | md5[i];
	*hash_r = hash;
	*error_r = t_strdup(error_dup);
	i_free(error_dup);
	return ret > 0;
}
