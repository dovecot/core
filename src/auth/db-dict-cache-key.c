/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "db-dict.h"

const struct db_dict_key *
db_dict_set_key_find(const ARRAY_TYPE(db_dict_key) *keys, const char *name)
{
	const struct db_dict_key *key;

	array_foreach(keys, key) {
		if (strcmp(key->name, name) == 0)
			return key;
	}
	return NULL;
}


const char *
db_dict_parse_cache_key(const ARRAY_TYPE(db_dict_key) *keys,
			const ARRAY_TYPE(db_dict_field) *fields,
			const ARRAY_TYPE(db_dict_key_p) *objects)
{
	const struct db_dict_field *field;
	const struct db_dict_key *key;
	const struct db_dict_key *const *keyp;
	const char *p, *name;
	unsigned int idx, size;
	string_t *str = t_str_new(128);

	array_foreach(fields, field) {
		for (p = field->value; *p != '\0'; ) {
			if (*p != '%') {
				p++;
				continue;
			}

			var_get_key_range(++p, &idx, &size);
			if (size == 0) {
				/* broken %variable ending too early */
				break;
			}
			p += idx;
			if (size > 5 && memcmp(p, "dict:", 5) == 0) {
				name = t_strcut(t_strndup(p+5, size-5), ':');
				key = db_dict_set_key_find(keys, name);
				if (key != NULL)
					str_printfa(str, "\t%s", key->key);
			} else if (size == 1) {
				str_printfa(str, "\t%%%c", p[0]);
			} else {
				str_append(str, "\t%{");
				str_append_data(str, p, size);
				str_append_c(str, '}');
			}
			p += size;
		}
	}
	array_foreach(objects, keyp)
		str_printfa(str, "\t%s", (*keyp)->key);
	return str_c(str);
}
