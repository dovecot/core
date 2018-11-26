/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_PASSWD_FILE

#include "istream.h"
#include "str.h"
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
	const char *username_format;
};

static int
passwd_file_add_extra_fields(struct auth_request *request, char *const *fields)
{
	string_t *str = t_str_new(512);
        const struct var_expand_table *table;
	const char *key, *value, *error;
	unsigned int i;

	table = auth_request_get_var_expand_table(request, NULL);

	for (i = 0; fields[i] != NULL; i++) {
		if (!str_begins(fields[i], "userdb_"))
			continue;

		key = fields[i] + 7;
		value = strchr(key, '=');
		if (value != NULL) {
			key = t_strdup_until(key, value);
			str_truncate(str, 0);
			if (auth_request_var_expand_with_table(str, value + 1,
					request, table, NULL, &error) <= 0) {
				auth_request_log_error(request, AUTH_SUBSYS_DB,
					"Failed to expand extra field %s: %s",
					fields[i], error);
				return -1;
			}
			value = str_c(str);
		} else {
			value = "";
		}
		auth_request_set_userdb_field(request, key, value);
	}
	return 0;
}

static void passwd_file_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_file_userdb_module *module =
		(struct passwd_file_userdb_module *)_module;
	struct passwd_user *pu;
	int ret;

	ret = db_passwd_file_lookup(module->pwf, auth_request,
				    module->username_format, &pu);
	if (ret <= 0 || pu->uid == 0) {
		callback(ret < 0 ? USERDB_RESULT_INTERNAL_FAILURE :
			 USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	if (pu->uid != (uid_t)-1) {
		auth_request_set_userdb_field(auth_request, "uid",
					      dec2str(pu->uid));
	}
	if (pu->gid != (gid_t)-1) {
		auth_request_set_userdb_field(auth_request, "gid",
					      dec2str(pu->gid));
	}

	if (pu->home != NULL)
		auth_request_set_userdb_field(auth_request, "home", pu->home);

	/* XXX
	 I’m not sure which function best fit the intend:
	 - auth_request_set_userdb_field
	 - auth_request_set_username
	 - auth_request_set_login_username
	 */
	if (pu->username != NULL)
		auth_request_set_userdb_field(auth_request, "username", pu->username);

	if (pu->extra_fields != NULL &&
	    passwd_file_add_extra_fields(auth_request, pu->extra_fields) < 0) {
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	callback(USERDB_RESULT_OK, auth_request);
}

static struct userdb_iterate_context *
passwd_file_iterate_init(struct auth_request *auth_request,
			 userdb_iter_callback_t *callback, void *context)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_file_userdb_module *module =
		(struct passwd_file_userdb_module *)_module;
	struct passwd_file_userdb_iterate_context *ctx;
	int fd;

	ctx = i_new(struct passwd_file_userdb_iterate_context, 1);
	ctx->ctx.auth_request = auth_request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	ctx->skip_passdb_entries = !module->pwf->userdb_warn_missing;
	if (module->pwf->default_file == NULL) {
		i_error("passwd-file: User iteration isn't currently supported "
			"with %%variable paths");
		ctx->ctx.failed = TRUE;
		return &ctx->ctx;
	}
	ctx->path = i_strdup(module->pwf->default_file->path);

	/* for now we support only a single passwd-file */
	fd = open(ctx->path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) failed: %m", ctx->path);
		ctx->ctx.failed = TRUE;
	} else {
		ctx->input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
	}
	return &ctx->ctx;
}

static void passwd_file_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct passwd_file_userdb_iterate_context *ctx =
		(struct passwd_file_userdb_iterate_context *)_ctx;
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
			i_error("read(%s) failed: %s", ctx->path,
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
		(struct passwd_file_userdb_iterate_context *)_ctx;
	int ret = _ctx->failed ? -1 : 0;

	i_stream_destroy(&ctx->input);
	i_free(ctx->path);
	i_free(ctx);
	return ret;
}

static struct userdb_module *
passwd_file_preinit(pool_t pool, const char *args)
{
	struct passwd_file_userdb_module *module;
	const char *format = PASSWD_FILE_DEFAULT_USERNAME_FORMAT;
	const char *p;

	if (str_begins(args, "username_format=")) {
		args += 16;
		p = strchr(args, ' ');
		if (p == NULL) {
			format = p_strdup(pool, args);
			args = "";
		} else {
			format = p_strdup_until(pool, args, p);
			args = p + 1;
		}
	}

	if (*args == '\0')
		i_fatal("userdb passwd-file: Missing args");

	module = p_new(pool, struct passwd_file_userdb_module, 1);
	module->pwf = db_passwd_file_init(args, TRUE,
					  global_auth_settings->debug);
	module->username_format = format;
	return &module->module;
}

static void passwd_file_init(struct userdb_module *_module)
{
	struct passwd_file_userdb_module *module =
		(struct passwd_file_userdb_module *)_module;

	db_passwd_file_parse(module->pwf);
}

static void passwd_file_deinit(struct userdb_module *_module)
{
	struct passwd_file_userdb_module *module =
		(struct passwd_file_userdb_module *)_module;

	db_passwd_file_unref(&module->pwf);
}

struct userdb_module_interface userdb_passwd_file = {
	"passwd-file",

	passwd_file_preinit,
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_lookup,

	passwd_file_iterate_init,
	passwd_file_iterate_next,
	passwd_file_iterate_deinit
};
#else
struct userdb_module_interface userdb_passwd_file = {
	.name = "passwd-file"
};
#endif
