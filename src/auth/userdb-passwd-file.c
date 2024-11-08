/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_PASSWD_FILE

#include "istream.h"
#include "str.h"
#include "settings.h"
#include "auth-cache.h"
#include "db-passwd-file.h"

#include <unistd.h>
#include <fcntl.h>

struct passwd_file_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct istream *input;
	char *path;
	bool skip_passdb_entries;
};

struct passwd_file_userdb_module {
        struct userdb_module module;

	struct db_passwd_file *pwf;
};

static int
passwd_file_add_extra_fields(struct auth_request *request,
			     const char *const *fields,
			     struct auth_fields *pwd_fields)
{
	string_t *str = t_str_new(512);
        const struct var_expand_table *table;
	const char *key, *value, *error;
	unsigned int i;
	int ret = 0;

	table = auth_request_get_var_expand_table(request);

	for (i = 0; fields[i] != NULL; i++) {
		key = fields[i];
		value = strchr(key, '=');
		if (value != NULL) {
			key = t_strdup_until(key, value);
			str_truncate(str, 0);
			if (auth_request_var_expand_with_table(str, value + 1,
					request, table, NULL, &error) < 0) {
				e_error(authdb_event(request),
					"Failed to expand extra field %s: %s",
					fields[i], error);
				ret = -1;
				break;
			}
			value = str_c(str);
		} else {
			value = "";
		}
		if (request->userdb->set->fields_import_all &&
		    str_begins(key, "userdb_", &key))
			auth_request_set_userdb_field(request, key, value);
		auth_fields_add(pwd_fields, key, value, 0);
	}
	if (ret == 0 && auth_request_set_userdb_fields_ex(request, pwd_fields,
							  db_passwd_file_var_expand_fn) < 0)
		ret = -1;
	return ret;
}

static void passwd_file_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_file_userdb_module *module =
		container_of(_module, struct passwd_file_userdb_module, module);
	struct passwd_user *pu;
	int ret;

	ret = db_passwd_file_lookup(module->pwf, auth_request,
				    auth_request->set->username_format, &pu);
	if (ret <= 0 || pu->uid == 0) {
		callback(ret < 0 ? USERDB_RESULT_INTERNAL_FAILURE :
			 USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	pool_t pool = pool_alloconly_create("passwd-file fields", 256);
	struct auth_fields *pwd_fields = auth_fields_init(pool);

	if (pu->uid != (uid_t)-1) {
		const char *value = dec2str(pu->uid);
		if (auth_request->userdb->set->fields_import_all) {
			auth_request_set_userdb_field(auth_request, "uid",
						      value);
		}
		auth_fields_add(pwd_fields, "uid", value, 0);
	}
	if (pu->gid != (gid_t)-1) {
		const char *value = dec2str(pu->gid);
		if (auth_request->userdb->set->fields_import_all) {
			auth_request_set_userdb_field(auth_request, "gid",
						      value);
		}
		auth_fields_add(pwd_fields, "gid", value, 0);
	}

	if (pu->home != NULL) {
		if (auth_request->userdb->set->fields_import_all) {
			auth_request_set_userdb_field(auth_request,
						      "home", pu->home);
		}
		auth_fields_add(pwd_fields, "home", pu->home, 0);
	}

	const char *const *extra_fields = pu->extra_fields != NULL ?
		pu->extra_fields : empty_str_array;
	if (passwd_file_add_extra_fields(auth_request, extra_fields,
					 pwd_fields) < 0) {
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		pool_unref(&pool);
		return;
	}

	callback(USERDB_RESULT_OK, auth_request);
	pool_unref(&pool);
}

static struct userdb_iterate_context *
passwd_file_iterate_init(struct auth_request *auth_request,
			 userdb_iter_callback_t *callback, void *context)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_file_userdb_module *module =
		container_of(_module, struct passwd_file_userdb_module, module);
	struct passwd_file_userdb_iterate_context *ctx;
	int fd;

	ctx = i_new(struct passwd_file_userdb_iterate_context, 1);
	ctx->ctx.auth_request = auth_request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	ctx->skip_passdb_entries = !module->pwf->userdb_warn_missing;
	if (module->pwf->default_file == NULL) {
		const struct var_expand_params params = {
			.table = auth_request_get_var_expand_table(auth_request),
			.providers = auth_request_var_expand_providers,
			.context = auth_request,
			.event = authdb_event(auth_request),
		};
		const char *error;
		string_t *dest = t_str_new(32);
		if (var_expand_program_execute(dest, module->pwf->prog, &params,
					       &error) < 0) {
			e_error(authdb_event(auth_request),
				"passwd-file: User iteration failed: "
				"Cannot expand '%s': %s", module->pwf->path, error);
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
		const char *path;
		if (db_passwd_fix_path(str_c(dest), &path, module->pwf->path, &error) < 0) {
			e_error(authdb_event(auth_request),
				"passwd-file: User iteration failed: "
				"Cannot normalize '%s': %s", str_c(dest), error);
			ctx->ctx.failed = TRUE;
			return &ctx->ctx;
		}
		ctx->path = i_strdup(path);
	} else {
		ctx->path = i_strdup(module->pwf->default_file->path);
	}

	/* for now we support only a single passwd-file */
	fd = open(ctx->path, O_RDONLY);
	if (fd == -1) {
		e_error(authdb_event(auth_request),
			"open(%s) failed: %m", ctx->path);
		ctx->ctx.failed = TRUE;
	} else {
		ctx->input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	}
	return &ctx->ctx;
}

static void passwd_file_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct passwd_file_userdb_iterate_context *ctx =
		container_of(_ctx, struct passwd_file_userdb_iterate_context, ctx);
	const char *line, *p;

	if (ctx->input == NULL)
		line = NULL;
	else {
		while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
			if (*line == '\0' || *line == ':' || *line == '#')
				continue; /* no username or comment */
			if (ctx->skip_passdb_entries &&
			    ((p = i_strchr_to_next(line, ':')) == NULL ||
			     strchr(p, ':') == NULL)) {
				/* only passdb info */
				continue;
			}
			break;
		}
		if (line == NULL && ctx->input->stream_errno != 0) {
			e_error(authdb_event(_ctx->auth_request),
				"read(%s) failed: %s", ctx->path,
				i_stream_get_error(ctx->input));
			_ctx->failed = TRUE;
		}
	}
	if (line == NULL)
		_ctx->callback(NULL, _ctx->context);
	else T_BEGIN {
		_ctx->callback(t_strcut(line, ':'), _ctx->context);
	} T_END;
}

static int passwd_file_iterate_deinit(struct userdb_iterate_context *_ctx)
{
	struct passwd_file_userdb_iterate_context *ctx =
		container_of(_ctx, struct passwd_file_userdb_iterate_context, ctx);
	int ret = _ctx->failed ? -1 : 0;

	i_stream_destroy(&ctx->input);
	i_free(ctx->path);
	i_free(ctx);
	return ret;
}

static int
passwd_file_preinit(pool_t pool, struct event *event,
		    struct userdb_module **module_r, const char **error_r)
{
	struct passwd_file_userdb_module *module;
	const struct passwd_file_settings *set;

	if (settings_get(event, &passwd_file_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	module = p_new(pool, struct passwd_file_userdb_module, 1);
	module->pwf = db_passwd_file_init(set->passwd_file_path, TRUE,
					  global_auth_settings->debug);
	settings_free(set);

	*module_r = &module->module;
	return 0;
}

static void passwd_file_init(struct userdb_module *_module)
{
	struct passwd_file_userdb_module *module =
		container_of(_module, struct passwd_file_userdb_module, module);

	db_passwd_file_parse(module->pwf);
}

static void passwd_file_deinit(struct userdb_module *_module)
{
	struct passwd_file_userdb_module *module =
		container_of(_module, struct passwd_file_userdb_module, module);

	db_passwd_file_unref(&module->pwf);
}

struct userdb_module_interface userdb_passwd_file = {
	.name = "passwd-file",

	.preinit = passwd_file_preinit,
	.init = passwd_file_init,
	.deinit = passwd_file_deinit,

	.lookup = passwd_file_lookup,

	.iterate_init = passwd_file_iterate_init,
	.iterate_next = passwd_file_iterate_next,
	.iterate_deinit = passwd_file_iterate_deinit
};
#else
struct userdb_module_interface userdb_passwd_file = {
	.name = "passwd-file"
};
#endif
