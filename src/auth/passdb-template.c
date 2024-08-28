/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "passdb.h"
#include "passdb-template.h"

struct passdb_template_arg {
	const char *key;
	struct var_expand_program *program;
};

struct passdb_template {
	ARRAY(struct passdb_template_arg) args;
	ARRAY_TYPE(const_string) keys;
};

struct passdb_template *passdb_template_build(pool_t pool, const char *args)
{
	struct passdb_template *tmpl;
	const char *const *tmp;

	tmpl = p_new(pool, struct passdb_template, 1);

	tmp = t_strsplit_spaces(args, " ");

	p_array_init(&tmpl->args, pool, str_array_length(tmp) / 2);
	p_array_init(&tmpl->keys, pool, str_array_length(tmp) / 2);

	for (; *tmp != NULL; tmp++) {
		const char *p = strchr(*tmp, '=');
		const char *kp;
		const char *error;

		if (p == NULL)
			kp = *tmp;
		else
			kp = t_strdup_until(*tmp, p++);

		if (*kp == '\0')
			i_fatal("Invalid passdb template %s - key must not be empty",
				args);

		char *key = p_strdup(pool, kp);
		struct var_expand_program *prog;
		if (var_expand_program_create(p, &prog, &error) < 0)
			i_fatal("Invalid passdb template value %s: %s", p, error);

		struct passdb_template_arg *arg = array_append_space(&tmpl->args);
		arg->key = key;
		arg->program = prog;
		array_push_back(&tmpl->keys, &arg->key);
	}

	return tmpl;
}

int passdb_template_export(struct passdb_template *tmpl,
			   struct auth_request *auth_request,
			   const char **error_r)
{
	string_t *str;
	const struct passdb_template_arg *arg;
	int ret = 0;

	if (passdb_template_is_empty(tmpl))
		return 0;

	const struct var_expand_params params = {
		.table = auth_request_get_var_expand_table(auth_request),
		.providers = auth_request_var_expand_providers,
		.context = auth_request,
	};

	str = t_str_new(256);

	array_foreach(&tmpl->args, arg) {
		str_truncate(str, 0);
		ret = var_expand_program_execute(str, arg->program, &params,
						 error_r);
		if (ret < 0)
			break;
		auth_request_set_field(auth_request, arg->key, str_c(str),
				       STATIC_PASS_SCHEME);
	}

	return ret;
}

bool passdb_template_is_empty(struct passdb_template *tmpl)
{
	return array_is_empty(&tmpl->args);
}

const char *const *passdb_template_get_args(struct passdb_template *tmpl,
					    unsigned int *count_r)
{
	return array_get(&tmpl->keys, count_r);
}

void passdb_template_free(struct passdb_template **_tmpl)
{
	struct passdb_template *tmpl = *_tmpl;
	if (tmpl == NULL)
		return;
	*_tmpl = NULL;

	struct passdb_template_arg *arg;

	array_foreach_modifiable(&tmpl->args, arg)
		var_expand_program_free(&arg->program);
}
