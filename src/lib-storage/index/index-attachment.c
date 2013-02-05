/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

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
	struct mail_save_attachment *attach = ctx->data.attach;
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct mail_attachment_extref *extref;
	enum fs_open_flags flags = 0;
	const char *attachment_dir, *path, *digest = info->hash;
	guid_128_t guid_128;

	i_assert(attach->cur_file == NULL);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER)
		flags |= FS_OPEN_FLAG_FSYNC;

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
	attach->cur_file = fs_file_init(attach->fs, path,
					FS_OPEN_MODE_CREATE | flags);

	extref = array_append_space(&attach->extrefs);
	extref->start_offset = info->start_offset;
	extref->size = info->encoded_size;
	extref->path = p_strdup(attach->pool,
				path + strlen(attachment_dir) + 1);
	extref->base64_blocks_per_line = info->base64_blocks_per_line;
	extref->base64_have_crlf = info->base64_have_crlf;

	*output_r = fs_write_stream(attach->cur_file);
	return 0;
}

static int
index_attachment_close_ostream(struct ostream *output,
			       bool success, void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_save_attachment *attach = ctx->data.attach;
	struct mail_storage *storage = ctx->transaction->box->storage;
	int ret = success ? 0 : -1;

	i_assert(attach->cur_file != NULL);

	if (ret < 0)
		fs_write_stream_abort(attach->cur_file, &output);
	else if (fs_write_stream_finish(attach->cur_file, &output) < 0) {
		mail_storage_set_critical(storage, "%s",
			fs_file_last_error(attach->cur_file));
		ret = -1;
	}
	fs_file_deinit(&attach->cur_file);

	if (ret < 0) {
		array_delete(&attach->extrefs,
			     array_count(&attach->extrefs)-1, 1);
	}
	return ret;
}

void index_attachment_save_begin(struct mail_save_context *ctx,
				 struct fs *fs, struct istream *input)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct mail_save_attachment *attach;
	struct istream_attachment_settings set;
	const char *error;
	pool_t pool;

	i_assert(ctx->data.attach == NULL);

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
	attach = p_new(pool, struct mail_save_attachment, 1);
	attach->pool = pool;
	attach->fs = fs;
	attach->input = i_stream_create_attachment_extractor(input, &set, ctx);
	p_array_init(&attach->extrefs, attach->pool, 8);
	ctx->data.attach = attach;
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
	struct mail_save_attachment *attach = ctx->data.attach;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	do {
		ret = i_stream_read(attach->input);
		if (ret > 0) {
			data = i_stream_get_data(attach->input, &size);
			o_stream_nsend(ctx->data.output, data, size);
			i_stream_skip(attach->input, size);
		}
		index_mail_cache_parse_continue(ctx->dest_mail);
		if (ret == 0 && !i_stream_attachment_extractor_can_retry(attach->input)) {
			/* need more input */
			return 0;
		}
	} while (ret != -1);

	if (ctx->data.output != NULL) {
		if (save_check_write_error(storage, ctx->data.output) < 0)
			return -1;
	}
	return 0;
}

int index_attachment_save_finish(struct mail_save_context *ctx)
{
	struct mail_save_attachment *attach = ctx->data.attach;

	(void)i_stream_read(attach->input);
	i_assert(attach->input->eof);
	return attach->input->stream_errno == 0;
}

void index_attachment_save_free(struct mail_save_context *ctx)
{
	struct mail_save_attachment *attach = ctx->data.attach;

	if (attach != NULL) {
		i_stream_unref(&attach->input);
		pool_unref(&attach->pool);
		ctx->data.attach = NULL;
	}
}

const ARRAY_TYPE(mail_attachment_extref) *
index_attachment_save_get_extrefs(struct mail_save_context *ctx)
{
	return ctx->data.attach == NULL ? NULL :
		&ctx->data.attach->extrefs;
}

static int
index_attachment_delete_real(struct mail_storage *storage,
			     struct fs *fs, const char *name)
{
	struct fs_file *file;
	const char *path;
	int ret;

	path = t_strdup_printf("%s/%s", index_attachment_dir_get(storage), name);
	file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
	if ((ret = fs_delete(file)) < 0)
		mail_storage_set_critical(storage, "%s", fs_last_error(fs));
	fs_file_deinit(&file);
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
