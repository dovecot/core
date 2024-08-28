/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "userdb.h"
#include "userdb-template.h"

struct userdb_template_arg {
	const char *key;
	struct var_expand_program *program;
};

struct userdb_template {
	ARRAY(struct userdb_template_arg) args;
	ARRAY_TYPE(const_string) keys;
};

struct userdb_template *
userdb_template_build(pool_t pool, const char *userdb_name, const char *args)
{
	struct userdb_template *tmpl;
	const char *const *tmp;
	uid_t uid;
	gid_t gid;

	tmpl = p_new(pool, struct userdb_template, 1);

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
			i_fatal("Invalid userdb template %s - key must not be empty",
				args);

		char *key = p_strdup(pool, kp);
		const char *nonull_value = p == NULL ? "" : p;
		if (strcasecmp(key, "uid") == 0) {
			uid = userdb_parse_uid(NULL, nonull_value);
			if (uid == (uid_t)-1) {
				i_fatal("%s userdb: Invalid uid: %s",
					userdb_name, nonull_value);
			}
			p = dec2str(uid);
		} else if (strcasecmp(key, "gid") == 0) {
			gid = userdb_parse_gid(NULL, nonull_value);
			if (gid == (gid_t)-1) {
				i_fatal("%s userdb: Invalid gid: %s",
					userdb_name, nonull_value);
			}
			p = dec2str(gid);
		} else if (*kp == '\0') {
			i_fatal("%s userdb: Empty key (=%s)",
				userdb_name, nonull_value);
		}
		struct var_expand_program *prog;
		if (var_expand_program_create(p, &prog, &error) < 0)
			i_fatal("Invalid userdb template value %s: %s", p, error);

		struct userdb_template_arg *arg = array_append_space(&tmpl->args);
		arg->key = key;
		arg->program = prog;
		array_push_back(&tmpl->keys, &arg->key);
	}

	return tmpl;
}

int userdb_template_export(struct userdb_template *tmpl,
			   struct auth_request *auth_request,
			   const char **error_r)
{
	const struct userdb_template_arg *arg;
	string_t *str;
	int ret = 0;

	if (userdb_template_is_empty(tmpl))
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
		auth_request_set_userdb_field(auth_request, arg->key, str_c(str));
	}

	return ret;
}

bool userdb_template_is_empty(struct userdb_template *tmpl)
{
	return array_is_empty(&tmpl->args);
}

const char *const *userdb_template_get_args(struct userdb_template *tmpl,
					    unsigned int *count_r)
{
	return array_get(&tmpl->keys, count_r);
}

void userdb_template_free(struct userdb_template **_tmpl)
{
	struct userdb_template *tmpl = *_tmpl;
	if (tmpl == NULL)
		return;
	*_tmpl = NULL;

	struct userdb_template_arg *arg;

	array_foreach_modifiable(&tmpl->args, arg)
		var_expand_program_free(&arg->program);
}
