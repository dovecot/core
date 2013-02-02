/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "str.h"
#include "var-expand.h"
#include "mail-user-hash.h"

unsigned int mail_user_hash(const char *username, const char *format)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	unsigned char md5[MD5_RESULTLEN];
	unsigned int i, hash = 0;

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
		string_t *str = t_str_new(128);

		tab = t_malloc(sizeof(static_tab));
		memcpy(tab, static_tab, sizeof(static_tab));
		tab[0].value = username;
		tab[1].value = t_strcut(username, '@');
		tab[2].value = strchr(username, '@');
		if (tab[2].value != NULL) tab[2].value++;

		var_expand(str, format, tab);
		md5_get_digest(str_data(str), str_len(str), md5);
	} T_END;
	for (i = 0; i < sizeof(hash); i++)
		hash = (hash << CHAR_BIT) | md5[i];
	return hash;
}

