/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-binary.h"
#include "fs-api.h"
#include "doveadm.h"
#include "doveadm-fs.h"
#include "doveadm-mail.h"
#include "doveadm-print.h"

struct mail_fs_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *path, *src_path, *dest_path;
	const char *const *paths;
	buffer_t *hash;

	enum fs_iter_flags iter_flags;
	bool recursive;
	int64_t async_count;
};

static void cmd_mail_fs_get_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "path", &cctx->path))
		doveadm_mail_help_name("mail fs get");
	doveadm_print_header("content", "content", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static int cmd_mail_fs_get_run(struct doveadm_mail_cmd_context *_cctx,
			       struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	doveadm_fs_get(_cctx->cctx, cctx->path);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_get_alloc(void)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_get_init;
	ctx->ctx.v.run = cmd_mail_fs_get_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_PAGER);
	return &ctx->ctx;
}

static void cmd_mail_fs_put_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);
	const char *hash_str;

	if (!doveadm_cmd_param_str(_cctx->cctx, "input-path", &cctx->src_path) ||
	    !doveadm_cmd_param_str(_cctx->cctx, "path", &cctx->dest_path))
		doveadm_mail_help_name("mail fs put");
	if (doveadm_cmd_param_str(_cctx->cctx, "hash", &hash_str)) {
		cctx->hash = t_buffer_create(32);
		if (hex_to_binary(optarg, cctx->hash) < 0)
			i_fatal("Invalid -h parameter: Hash not in hex");
	}
}

static int cmd_mail_fs_put_run(struct doveadm_mail_cmd_context *_cctx,
			       struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	doveadm_fs_put(_cctx->cctx, cctx->src_path,
		       cctx->dest_path, cctx->hash);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_put_alloc(void)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_put_init;
	ctx->ctx.v.run = cmd_mail_fs_put_run;
	return &ctx->ctx;
}

static void cmd_mail_fs_copy_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "source-path", &cctx->src_path) ||
	    !doveadm_cmd_param_str(_cctx->cctx, "destination-path", &cctx->dest_path))
		doveadm_mail_help_name("mail fs copy");
}

static int cmd_mail_fs_copy_run(struct doveadm_mail_cmd_context *_cctx,
				struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	doveadm_fs_copy(_cctx->cctx, cctx->src_path, cctx->dest_path);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_copy_alloc(void)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_copy_init;
	ctx->ctx.v.run = cmd_mail_fs_copy_run;
	return &ctx->ctx;
}

static void cmd_mail_fs_stat_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "path", &cctx->path))
		doveadm_mail_help_name("mail fs stat");

	doveadm_print_header_simple("path");
	doveadm_print_header("size", "size", DOVEADM_PRINT_HEADER_FLAG_NUMBER);
}

static int cmd_mail_fs_stat_run(struct doveadm_mail_cmd_context *_cctx,
				struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	doveadm_fs_stat(_cctx->cctx, cctx->path);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_stat_alloc(void)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_stat_init;
	ctx->ctx.v.run = cmd_mail_fs_stat_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{path} size=%{size}");
	return &ctx->ctx;
}

static void cmd_mail_fs_metadata_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "path", &cctx->path))
		doveadm_mail_help_name("mail fs metadata");

	doveadm_print_header_simple("key");
	doveadm_print_header_simple("value");
}

static int cmd_mail_fs_metadata_run(struct doveadm_mail_cmd_context *_cctx,
				    struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	doveadm_fs_metadata(_cctx->cctx, cctx->path);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_metadata_alloc(void)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_metadata_init;
	ctx->ctx.v.run = cmd_mail_fs_metadata_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{key}=%{value}\n");
	return &ctx->ctx;
}

static void cmd_mail_fs_delete_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	if (!doveadm_cmd_param_array(_cctx->cctx, "path", &cctx->paths))
		doveadm_mail_help_name("mail fs delete");

	(void)doveadm_cmd_param_bool(_cctx->cctx, "recursive", &cctx->recursive);
	(void)doveadm_cmd_param_int64(_cctx->cctx, "max-parallel", &cctx->async_count);
}

static int cmd_mail_fs_delete_run(struct doveadm_mail_cmd_context *_cctx,
				  struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	if (cctx->recursive) {
		doveadm_fs_delete_recursive(_cctx->cctx, cctx->paths,
					    cctx->async_count);
	} else {
		doveadm_fs_delete_paths(_cctx->cctx, cctx->paths,
					cctx->async_count);
	}
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_delete_alloc(void)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_delete_init;
	ctx->ctx.v.run = cmd_mail_fs_delete_run;
	return &ctx->ctx;
}

static void cmd_mail_fs_iter_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);
	bool b;

	if (!doveadm_cmd_param_str(_cctx->cctx, "path", &cctx->path)) {
		doveadm_mail_help_name((cctx->iter_flags & FS_ITER_FLAG_DIRS) != 0 ?
				       "mail fs iter-dirs" : "mail fs iter");
	}

	if (doveadm_cmd_param_bool(_cctx->cctx, "no-cache", &b) && b)
		cctx->iter_flags |= FS_ITER_FLAG_NOCACHE;
	if (doveadm_cmd_param_bool(_cctx->cctx, "object-ids", &b) && b)
		cctx->iter_flags |= FS_ITER_FLAG_OBJECTIDS;

	doveadm_print_header_simple("path");
}

static int cmd_mail_fs_iter_run(struct doveadm_mail_cmd_context *_cctx,
				struct mail_user *user)
{
	struct mail_fs_cmd_context *cctx =
		container_of(_cctx, struct mail_fs_cmd_context, ctx);

	doveadm_cmd_context_replace_set_event(_cctx->cctx, user->event);
	doveadm_fs_iter(_cctx->cctx, cctx->iter_flags, cctx->path);
	return 0;
}

static struct doveadm_mail_cmd_context *
cmd_mail_fs_iter_alloc_full(enum fs_iter_flags iter_flags)
{
	struct mail_fs_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_fs_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_fs_iter_init;
	ctx->ctx.v.run = cmd_mail_fs_iter_run;
	ctx->iter_flags = iter_flags;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{path}\n");
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_iter_alloc(void)
{
	return cmd_mail_fs_iter_alloc_full(0);
}

static struct doveadm_mail_cmd_context *cmd_mail_fs_iter_dirs_alloc(void)
{
	return cmd_mail_fs_iter_alloc_full(FS_ITER_FLAG_DIRS);
}

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_get = {
	.name = "mail fs get",
	.mail_cmd = cmd_mail_fs_get_alloc,
	.usage = "<config-filter-name> <path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_put = {
	.name = "mail fs put",
	.mail_cmd = cmd_mail_fs_put_alloc,
	.usage = "[-h <hash>] <config-filter-name> <input path> <path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('h', "hash", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "input-path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_copy = {
	.name = "mail fs copy",
	.mail_cmd = cmd_mail_fs_copy_alloc,
	.usage = "<config-filter-name> <source path> <dest path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "source-path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "destination-path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_stat = {
	.name = "mail fs stat",
	.mail_cmd = cmd_mail_fs_stat_alloc,
	.usage = "<config-filter-name> <path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_metadata = {
	.name = "mail fs metadata",
	.mail_cmd = cmd_mail_fs_metadata_alloc,
	.usage = "<config-filter-name> <path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_delete = {
	.name = "mail fs delete",
	.mail_cmd = cmd_mail_fs_delete_alloc,
	.usage = "[-R] [-n <count>] <config-filter-name> <path> [<path> ...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('R', "recursive", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('n', "max-parallel", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_iter = {
	.name = "mail fs iter",
	.mail_cmd = cmd_mail_fs_iter_alloc,
	.usage = "[--no-cache] [--object-ids] <config-filter-name> <path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('C', "no-cache", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('O', "object-ids", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_fs_iter_dirs = {
	.name = "mail fs iter-dirs",
	.mail_cmd = cmd_mail_fs_iter_dirs_alloc,
	.usage = "<config-filter-name> <path>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
