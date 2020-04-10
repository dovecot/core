/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"

#ifdef BUILD_CDB
#include "dict-private.h"

#include <string.h>
#include <cdb.h>
#include <unistd.h>
#include <fcntl.h>

#define CDB_WITH_NULL 1
#define CDB_WITHOUT_NULL 2

struct cdb_dict {
	struct dict dict;
	struct cdb cdb;
	char *path;
	int fd, flag;
};

struct cdb_dict_iterate_context {
	struct dict_iterate_context ctx;

	enum dict_iterate_flags flags;
	buffer_t *buffer;
	const char *values[2];
	char *path;
	unsigned cptr;
	char *error;
};

static void cdb_dict_deinit(struct dict *_dict);

static int
cdb_dict_init(struct dict *driver, const char *uri,
	      const struct dict_settings *set ATTR_UNUSED,
	      struct dict **dict_r, const char **error_r)
{
	struct cdb_dict *dict;

	dict = i_new(struct cdb_dict, 1);
	dict->dict = *driver;
	dict->path = i_strdup(uri);
	dict->flag = CDB_WITH_NULL | CDB_WITHOUT_NULL;

	/* initialize cdb to 0 (unallocated) */
	i_zero(&dict->cdb);

	dict->fd = open(dict->path, O_RDONLY);
	if (dict->fd == -1) {
		*error_r = t_strdup_printf("open(%s) failed: %m", dict->path);
		cdb_dict_deinit(&dict->dict);
		return -1;
	}

#ifdef TINYCDB_VERSION
	if (cdb_init(&dict->cdb, dict->fd) < 0) {
		*error_r = t_strdup_printf("cdb_init(%s) failed: %m", dict->path);
		cdb_dict_deinit(&dict->dict);
		return -1;
	}
#else
	cdb_init(&dict->cdb, dict->fd);
#endif

	*dict_r = &dict->dict;
	return 0;
}

static void cdb_dict_deinit(struct dict *_dict)
{
	struct cdb_dict *dict = (struct cdb_dict *)_dict;

	/* we can safely deinit unallocated cdb */
	cdb_free(&dict->cdb);

	i_close_fd_path(&dict->fd, dict->path);

	i_free(dict->path);
	i_free(dict);
}

static int
cdb_dict_lookup(struct dict *_dict,
		const struct dict_op_settings *set ATTR_UNUSED,
		pool_t pool,
	        const char *key, const char *const **values_r,
	        const char **error_r)
{
	struct cdb_dict *dict = (struct cdb_dict *)_dict;
	unsigned datalen;
	int ret = 0;
	char *data;

	/* keys and values may be null terminated... */
	if ((dict->flag & CDB_WITH_NULL) != 0) {
		ret = cdb_find(&dict->cdb, key, (unsigned)strlen(key)+1);
		if (ret > 0)
			dict->flag &= ENUM_NEGATE(CDB_WITHOUT_NULL);
	}

	/* ...or not */
	if (ret == 0 && (dict->flag & CDB_WITHOUT_NULL) != 0) {
		ret = cdb_find(&dict->cdb, key, (unsigned)strlen(key));
		if (ret > 0)
			dict->flag &= ENUM_NEGATE(CDB_WITH_NULL);
	}

	if (ret <= 0) {
		/* something bad with db */
		if (ret < 0) {
			*error_r = t_strdup_printf("cdb_find(%s) failed: %m", dict->path);
			return -1;
		}
		/* found nothing */
		return 0;
	}

	datalen = cdb_datalen(&dict->cdb);
	data = p_malloc(pool, datalen + 1);
	if (cdb_read(&dict->cdb, data, datalen, cdb_datapos(&dict->cdb)) < 0) {
		*error_r = t_strdup_printf("cdb_read(%s) failed: %m", dict->path);
		return -1;
	}
	const char **values = p_new(pool, const char *, 2);
	values[0] = data;
	*values_r = values;
	return 1;
}

static struct dict_iterate_context *
cdb_dict_iterate_init(struct dict *_dict,
		      const struct dict_op_settings *set ATTR_UNUSED,
		      const char *path, enum dict_iterate_flags flags)
{
	struct cdb_dict_iterate_context *ctx =
		i_new(struct cdb_dict_iterate_context, 1);
	struct cdb_dict *dict = (struct cdb_dict *)_dict;

	ctx->ctx.dict = &dict->dict;
	ctx->path = i_strdup(path);
	ctx->flags = flags;
	ctx->buffer = buffer_create_dynamic(default_pool, 256);

	cdb_seqinit(&ctx->cptr, &dict->cdb);

	return &ctx->ctx;
}

static bool
cdb_dict_next(struct cdb_dict_iterate_context *ctx, const char **key_r)
{
	struct cdb_dict *dict = (struct cdb_dict *)ctx->ctx.dict;
	char *data;
	unsigned datalen;
	int ret;

	if ((ret = cdb_seqnext(&ctx->cptr, &dict->cdb)) < 1) {
		if (ret < 0)
			ctx->error = i_strdup_printf("cdb_seqnext(%s) failed: %m",
						     dict->path);
		return FALSE;
	}

	buffer_set_used_size(ctx->buffer, 0);

	datalen = cdb_keylen(&dict->cdb);
	data = buffer_append_space_unsafe(ctx->buffer, datalen + 1);

	if (cdb_read(&dict->cdb, data, datalen, cdb_keypos(&dict->cdb)) < 0) {
		ctx->error = i_strdup_printf("cdb_read(%s) failed: %m",
					     dict->path);
		return FALSE;
	}

	data[datalen] = '\0';
	*key_r = data;

	return TRUE;
}

static bool cdb_dict_iterate(struct dict_iterate_context *_ctx,
			     const char **key_r, const char *const **values_r)
{
	struct cdb_dict_iterate_context *ctx =
		(struct cdb_dict_iterate_context *)_ctx;
	struct cdb_dict *dict = (struct cdb_dict *)_ctx->dict;
	const char *key;
	bool match = FALSE;
	char *data;
	unsigned datalen;

	if (ctx->error != NULL)
		return FALSE;

	while(!match && cdb_dict_next(ctx, &key)) {
		if (((ctx->flags & DICT_ITERATE_FLAG_EXACT_KEY) != 0 &&
		     strcmp(key, ctx->path) == 0) ||
		    ((ctx->flags & DICT_ITERATE_FLAG_RECURSE) != 0 &&
		     str_begins_with(key, ctx->path)) ||
		    ((ctx->flags & DICT_ITERATE_FLAG_RECURSE) == 0 &&
		     str_begins_with(key, ctx->path) &&
		     strchr(key + strlen(ctx->path), '/') == NULL)) {
			match = TRUE;
			break;
		}
	}

	if (!match)
		return FALSE;

	*key_r = key;

	if ((ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) != 0)
		return TRUE;

	datalen = cdb_datalen(&dict->cdb);
	data = buffer_append_space_unsafe(ctx->buffer, datalen + 1);

	if (cdb_read(&dict->cdb, data, datalen, cdb_datapos(&dict->cdb)) < 0) {
		ctx->error = i_strdup_printf("cdb_read(%s) failed: %m",
					     dict->path);
		return FALSE;
	}

	data[datalen] = '\0';
	ctx->values[0] = data;
	*values_r = ctx->values;

	return TRUE;
}

static int cdb_dict_iterate_deinit(struct dict_iterate_context *_ctx,
				   const char **error_r)
{
	int ret = 0;
	struct cdb_dict_iterate_context *ctx =
		(struct cdb_dict_iterate_context *)_ctx;
	if (ctx->error != NULL) {
		*error_r = t_strdup(ctx->error);
		ret = -1;
	}

	buffer_free(&ctx->buffer);
	i_free(ctx->error);
	i_free(ctx->path);
	i_free(ctx);

	return ret;
}


struct dict dict_driver_cdb = {
	.name = "cdb",
	{
		.init = cdb_dict_init,
		.deinit = cdb_dict_deinit,
		.lookup = cdb_dict_lookup,
		.iterate_init = cdb_dict_iterate_init,
		.iterate = cdb_dict_iterate,
		.iterate_deinit = cdb_dict_iterate_deinit,
	}
};
#endif
