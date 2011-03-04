/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_PASSWD_FILE

#include "istream.h"
#include "str.h"
#include "auth-cache.h"
#include "var-expand.h"
#include "db-passwd-file.h"

#include <unistd.h>
#include <fcntl.h>

#define PASSWD_FILE_CACHE_KEY "%u"

struct passwd_file_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct istream *input;
	char *path;
};

struct passwd_file_userdb_module {
        struct userdb_module module;

	struct db_passwd_file *pwf;
	const char *username_format;
};

static void passwd_file_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_file_userdb_module *module =
		(struct passwd_file_userdb_module *)_module;
	struct passwd_user *pu;
        const struct var_expand_table *table;
	string_t *str;
	const char *key, *value;
	char **p;

	pu = db_passwd_file_lookup(module->pwf, auth_request,
				   module->username_format);
	if (pu == NULL) {
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	auth_request_init_userdb_reply(auth_request);
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

	if (pu->extra_fields != NULL) {
		str = t_str_new(512);
		table = auth_request_get_var_expand_table(auth_request, NULL);

		for (p = pu->extra_fields; *p != NULL; p++) {
			if (strncmp(*p, "userdb_", 7) != 0)
				continue;

			key = *p + 7;
			value = strchr(key, '=');
			if (value != NULL) {
				key = t_strdup_until(key, value);
				str_truncate(str, 0);
				var_expand(str, value + 1, table);
				value = str_c(str);
			}
			auth_request_set_userdb_field(auth_request, key, value);
		}
	}

	callback(USERDB_RESULT_OK, auth_request);
}

static struct userdb_iterate_context *
passwd_file_iterate_init(struct userdb_module *userdb,
			 userdb_iter_callback_t *callback, void *context)
{
	struct passwd_file_userdb_module *module =
		(struct passwd_file_userdb_module *)userdb;
	struct passwd_file_userdb_iterate_context *ctx;
	int fd;

	ctx = i_new(struct passwd_file_userdb_iterate_context, 1);
	ctx->ctx.userdb = userdb;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
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
		ctx->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	}
	return &ctx->ctx;
}

static void passwd_file_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct passwd_file_userdb_iterate_context *ctx =
		(struct passwd_file_userdb_iterate_context *)_ctx;
	const char *line;

	if (ctx->input == NULL)
		line = NULL;
	else {
		while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
			if (*line == '\0' || *line == ':' || *line == '#')
				continue; /* no username or comment */
			break;
		}
		if (line == NULL && ctx->input->stream_errno != 0) {
			i_error("read(%s) failed: %m", ctx->path);
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

	if (ctx->input != NULL)
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

	if (strncmp(args, "username_format=", 16) == 0) {
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

	if (!module->pwf->vars)
		module->module.cache_key = PASSWD_FILE_CACHE_KEY;
	else {
		module->module.cache_key =
			auth_cache_parse_key(pool,
					     t_strconcat(PASSWD_FILE_CACHE_KEY,
						         module->pwf->path,
							 NULL));
	}
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
