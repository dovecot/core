/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-map.h"

struct dbox_map {
	struct dbox_storage *storage;
	struct mail_index *index;
};

struct dbox_map_append_context {
	struct dbox_mailbox *mbox;

	ARRAY_DEFINE(files, struct dbox_file *);

	uoff_t output_offset;
	unsigned int new_record_idx;
	uint32_t first_new_file_id;

	unsigned int locked_header:1;
};

struct dbox_map *dbox_map_init(struct dbox_storage *storage)
{
	struct dbox_map *map;

	map = i_new(struct dbox_map, 1);
	map->storage = storage;
	map->index = mail_index_alloc(storage->storage_dir,
				      DBOX_GLOBAL_INDEX_PREFIX);
	return map;
}

void dbox_map_deinit(struct dbox_map **_map)
{
	struct dbox_map *map = *_map;

	*_map = NULL;

	mail_index_free(&map->index);
	i_free(map);
}

bool dbox_map_lookup(struct dbox_map *map, uint32_t map_uid,
		     uint32_t *file_id_r, uoff_t *offset_r)
{
	return FALSE;
}

struct dbox_map_append_context *
dbox_map_append_begin(struct dbox_mailbox *mbox)
{
	struct dbox_map_append_context *ctx;

	ctx = i_new(struct dbox_map_append_context, 1);
	ctx->mbox = mbox;
	ctx->first_new_file_id = (uint32_t)-1;
	i_array_init(&ctx->files, 64);
	return ctx;
}

int dbox_map_append_next(struct dbox_map_append_context *ctx, uoff_t mail_size,
			 struct dbox_file **file_r, struct ostream **output_r)
{
	struct dbox_file *const *files, *file = NULL;
	unsigned int i, count;
	int ret;

	/* first try to use files already used in this append */
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (dbox_file_get_append_stream(files[i], mail_size,
						output_r) > 0) {
			*file_r = files[i];
			return 0;
		}
	}

	/* FIXME: try to find an existing appendable file */

	if (file == NULL) {
		/* create a new file */
		file = dbox_file_init_single(ctx->mbox, 0);
		if ((ret = dbox_file_get_append_stream(file, mail_size,
						       output_r)) <= 0) {
			i_assert(ret < 0);
			(void)unlink(dbox_file_get_path(file));
			dbox_file_unref(&file);
			return -1;
		}
	}

	*file_r = file;
	array_append(&ctx->files, &file, 1);
	return 0;
}

static int dbox_map_append_commit_new(struct dbox_map_append_context *ctx,
				      struct dbox_file *file)
{
	i_assert(!file->maildir_file);
	i_assert(file->append_count > 0);

	if (file->single_mbox != NULL) {
		/* single UID message file */
		i_assert(file->last_append_uid != 0);
		return dbox_file_assign_id(file, file->last_append_uid);
	}

	/* FIXME */
	return -1;
}

int dbox_map_append_assign_file_ids(struct dbox_map_append_context *ctx)
{
	struct dbox_file *const *files, *file;
	unsigned int i, count;
	int ret = 0;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		file = files[i];

		if (file->uid == 0 && file->file_id == 0) {
			if (dbox_map_append_commit_new(ctx, file) < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (ret < 0) {
		/* FIXME: we have to rollback the changes we made */
	}
	return ret;
}

int dbox_map_append_commit(struct dbox_map_append_context **_ctx)
{
	struct dbox_map_append_context *ctx = *_ctx;
	struct dbox_file **files;
	unsigned int i, count;

	*_ctx = NULL;

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++)
		dbox_file_unref(&files[i]);

	array_free(&ctx->files);
	i_free(ctx);
	return 0;
}

void dbox_map_append_rollback(struct dbox_map_append_context **_ctx)
{
	struct dbox_map_append_context *ctx = *_ctx;
	struct dbox_file *const *files, *file;
	unsigned int i, count;

	*_ctx = NULL;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		file = files[i];

		if (file->file_id != 0) {
			/* FIXME: truncate? */
		} else {
			if (unlink(dbox_file_get_path(file)) < 0) {
				i_error("unlink(%s) failed: %m",
					dbox_file_get_path(file));
			}
		}
		dbox_file_unref(&file);
	}
	array_free(&ctx->files);
	i_free(ctx);
}
