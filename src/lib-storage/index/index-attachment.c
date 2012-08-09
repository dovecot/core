/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-mkstemp.h"
#include "fs-api.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "hash-format.h"
#include "str.h"
#include "message-parser.h"
#include "rfc822-parser.h"
#include "istream-attachment-extractor.h"
#include "mail-user.h"
#include "index-mail.h"
#include "index-attachment.h"

struct mail_save_attachment {
	pool_t pool;
	struct fs *fs;
	struct istream *input;

	struct fs_file *cur_file;
	ARRAY_TYPE(mail_attachment_extref) extrefs;
};

static const char *index_attachment_dir_get(struct mail_storage *storage)
{
	return mail_user_home_expand(storage->user,
				     storage->set->mail_attachment_dir);
}

static bool index_attachment_want(const struct istream_attachment_header *hdr,
				  void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_attachment_part apart;

	memset(&apart, 0, sizeof(apart));
	apart.part = hdr->part;
	apart.content_type = hdr->content_type;
	apart.content_disposition = hdr->content_disposition;

	if (ctx->part_is_attachment != NULL)
		return ctx->part_is_attachment(ctx, &apart);

	/* don't treat text/ parts as attachments */
	return hdr->content_type != NULL &&
		strncasecmp(hdr->content_type, "text/", 5) != 0;
}

static int index_attachment_open_temp_fd(void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_storage *storage = ctx->transaction->box->storage;
	string_t *temp_path;
	int fd;

	temp_path = t_str_new(256);
	mail_user_set_get_temp_prefix(temp_path, storage->user->set);
	fd = safe_mkstemp_hostpid(temp_path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		mail_storage_set_critical(storage,
			"safe_mkstemp(%s) failed: %m", str_c(temp_path));
		return -1;
	}
	if (unlink(str_c(temp_path)) < 0) {
		mail_storage_set_critical(storage,
			"unlink(%s) failed: %m", str_c(temp_path));
		i_close_fd(&fd);
		return -1;
	}
	return fd;
}

static int
index_attachment_open_ostream(struct istream_attachment_info *info,
			      struct ostream **output_r, void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct mail_attachment_extref *extref;
	enum fs_open_flags flags = FS_OPEN_FLAG_MKDIR;
	const char *attachment_dir, *path, *digest = info->hash;
	guid_128_t guid_128;

	i_assert(ctx->attach->cur_file == NULL);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER)
		flags |= FS_OPEN_FLAG_FDATASYNC;

	if (strlen(digest) < 4) {
		/* make sure we can access first 4 bytes without accessing
		   out of bounds memory */
		digest = t_strconcat(digest, "\0\0\0\0", NULL);
	}

	guid_128_generate(guid_128);
	attachment_dir = index_attachment_dir_get(storage);
	path = t_strdup_printf("%s/%c%c/%c%c/%s-%s", attachment_dir,
			       digest[0], digest[1],
			       digest[2], digest[3], digest,
			       guid_128_to_string(guid_128));
	if (fs_open(ctx->attach->fs, path,
		    FS_OPEN_MODE_CREATE | flags, &ctx->attach->cur_file) < 0) {
		mail_storage_set_critical(storage, "%s",
			fs_last_error(ctx->attach->fs));
		return -1;
	}

	extref = array_append_space(&ctx->attach->extrefs);
	extref->start_offset = info->start_offset;
	extref->size = info->encoded_size;
	extref->path = p_strdup(ctx->attach->pool,
				path + strlen(attachment_dir) + 1);
	extref->base64_blocks_per_line = info->base64_blocks_per_line;
	extref->base64_have_crlf = info->base64_have_crlf;

	*output_r = fs_write_stream(ctx->attach->cur_file);
	return 0;
}

static int
index_attachment_close_ostream(struct ostream *output,
			       bool success, void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_storage *storage = ctx->transaction->box->storage;
	int ret = success ? 0 : -1;

	i_assert(ctx->attach->cur_file != NULL);

	if (ret < 0)
		fs_write_stream_abort(ctx->attach->cur_file, &output);
	else if (fs_write_stream_finish(ctx->attach->cur_file, &output) < 0) {
		mail_storage_set_critical(storage, "%s",
			fs_file_last_error(ctx->attach->cur_file));
		ret = -1;
	}
	fs_close(&ctx->attach->cur_file);

	if (ret < 0) {
		array_delete(&ctx->attach->extrefs,
			     array_count(&ctx->attach->extrefs)-1, 1);
	}
	return ret;
}

void index_attachment_save_begin(struct mail_save_context *ctx,
				 struct fs *fs, struct istream *input)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct istream_attachment_settings set;
	const char *error;
	pool_t pool;

	i_assert(ctx->attach == NULL);

	if (*storage->set->mail_attachment_dir == '\0')
		return;

	memset(&set, 0, sizeof(set));
	set.min_size = storage->set->mail_attachment_min_size;
	if (hash_format_init(storage->set->mail_attachment_hash,
			     &set.hash_format, &error) < 0) {
		/* we already checked this when verifying settings */
		i_panic("mail_attachment_hash=%s unexpectedly failed: %s",
			storage->set->mail_attachment_hash, error);
	}
	set.want_attachment = index_attachment_want;
	set.open_temp_fd = index_attachment_open_temp_fd;
	set.open_attachment_ostream = index_attachment_open_ostream;
	set.close_attachment_ostream = index_attachment_close_ostream;

	pool = pool_alloconly_create("save attachment", 1024);
	ctx->attach = p_new(pool, struct mail_save_attachment, 1);
	ctx->attach->pool = pool;
	ctx->attach->fs = fs;
	ctx->attach->input =
		i_stream_create_attachment_extractor(input, &set, ctx);
	p_array_init(&ctx->attach->extrefs, ctx->attach->pool, 8);
}

static int save_check_write_error(struct mail_storage *storage,
				  struct ostream *output)
{
	if (output->last_failed_errno == 0)
		return 0;

	errno = output->last_failed_errno;
	if (!mail_storage_set_error_from_errno(storage)) {
		mail_storage_set_critical(storage, "write(%s) failed: %m",
					  o_stream_get_name(output));
	}
	return -1;
}

int index_attachment_save_continue(struct mail_save_context *ctx)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	do {
		ret = i_stream_read(ctx->attach->input);
		if (ret > 0) {
			data = i_stream_get_data(ctx->attach->input, &size);
			o_stream_nsend(ctx->output, data, size);
			i_stream_skip(ctx->attach->input, size);
		}
		index_mail_cache_parse_continue(ctx->dest_mail);
		if (ret == 0 && !i_stream_attachment_extractor_can_retry(ctx->attach->input)) {
			/* need more input */
			return 0;
		}
	} while (ret != -1);

	if (ctx->output != NULL) {
		if (save_check_write_error(storage, ctx->output) < 0)
			return -1;
	}
	return 0;
}

int index_attachment_save_finish(struct mail_save_context *ctx)
{
	(void)i_stream_read(ctx->attach->input);
	i_assert(ctx->attach->input->eof);
	return ctx->attach->input->stream_errno == 0;
}

void index_attachment_save_free(struct mail_save_context *ctx)
{
	if (ctx->attach != NULL) {
		i_stream_unref(&ctx->attach->input);
		pool_unref(&ctx->attach->pool);
		ctx->attach = NULL;
	}
}

const ARRAY_TYPE(mail_attachment_extref) *
index_attachment_save_get_extrefs(struct mail_save_context *ctx)
{
	return ctx->attach == NULL ? NULL :
		&ctx->attach->extrefs;
}

static int
index_attachment_delete_real(struct mail_storage *storage,
			     struct fs *fs, const char *name)
{
	const char *path, *p, *attachment_dir;
	int ret;

	path = t_strdup_printf("%s/%s", index_attachment_dir_get(storage), name);
	if ((ret = fs_unlink(fs, path)) < 0)
		mail_storage_set_critical(storage, "%s", fs_last_error(fs));

	/* if the directory is now empty, rmdir it and its parents
	   until it fails */
	attachment_dir = index_attachment_dir_get(storage);
	while ((p = strrchr(path, '/')) != NULL) {
		path = t_strdup_until(path, p);
		if (strcmp(path, attachment_dir) == 0)
			break;

		if (fs_rmdir(fs, path) == 0) {
			/* success, continue to parent */
		} else if (errno == ENOTEMPTY || errno == EEXIST) {
			/* there are other entries in this directory */
			break;
		} else {
			mail_storage_set_critical(storage, "%s",
				fs_last_error(fs));
			break;
		}
	}
	return ret;
}

int index_attachment_delete(struct mail_storage *storage,
			    struct fs *fs, const char *name)
{
	int ret;

	T_BEGIN {
		ret = index_attachment_delete_real(storage, fs, name);
	} T_END;
	return ret;
}
