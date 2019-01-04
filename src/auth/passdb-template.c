/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "passdb.h"
#include "passdb-template.h"

struct passdb_template {
	ARRAY(const char *) args;
};

struct passdb_template *passdb_template_build(pool_t pool, const char *args)
{
	struct passdb_template *tmpl;
	const char *const *tmp, *key, *value;

	tmpl = p_new(pool, struct passdb_template, 1);

	tmp = t_strsplit_spaces(args, " ");
	p_array_init(&tmpl->args, pool, str_array_length(tmp));

	for (; *tmp != NULL; tmp++) {
		value = strchr(*tmp, '=');
		if (value == NULL)
			key = *tmp;
		else
			key = t_strdup_until(*tmp, value++);

		if (*key == '\0')
			i_fatal("Invalid passdb template %s - key must not be empty",
				args);

		key = p_strdup(pool, key);
		value = p_strdup(pool, value);
		array_push_back(&tmpl->args, &key);
		array_push_back(&tmpl->args, &value);
	}
	return tmpl;
}

int passdb_template_export(struct passdb_template *tmpl,
			   struct auth_request *auth_request,
			   const char **error_r)
{
        const struct var_expand_table *table;
	string_t *str;
	const char *const *args, *value;
	unsigned int i, count;

	if (passdb_template_is_empty(tmpl))
		return 0;

	str = t_str_new(256);
	table = auth_request_get_var_expand_table(auth_request, NULL);

	args = array_get(&tmpl->args, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (args[i+1] == NULL)
			value = "";
		else {
			str_truncate(str, 0);
			if (auth_request_var_expand_with_table(str, args[i+1],
					auth_request, table, NULL, error_r) <= 0)
				return -1;
			value = str_c(str);
		}
		auth_request_set_field(auth_request, args[i], value,
				       STATIC_PASS_SCHEME);
	}
	return 0;
}

bool passdb_template_remove(struct passdb_template *tmpl,
			    const char *key, const char **value_r)
{
	const char *const *args;
	unsigned int i, count;

	args = array_get(&tmpl->args, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (strcmp(args[i], key) == 0) {
			*value_r = args[i+1];
			array_delete(&tmpl->args, i, 2);
			return TRUE;
		}
	}
	return FALSE;
}

bool passdb_template_is_empty(struct passdb_template *tmpl)
{
	return array_count(&tmpl->args) == 0;
}

const char *const *passdb_template_get_args(struct passdb_template *tmpl, unsigned int *count_r)
{
	return array_get(&tmpl->args, count_r);
}

