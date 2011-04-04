/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

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
#include "mail-user.h"
#include "index-mail.h"
#include "index-attachment.h"

#define BASE64_ATTACHMENT_MAX_EXTRA_BYTES 1024

enum mail_attachment_state {
	MAIL_ATTACHMENT_STATE_NO,
	MAIL_ATTACHMENT_STATE_MAYBE,
	MAIL_ATTACHMENT_STATE_YES
};

enum base64_state {
	BASE64_STATE_0 = 0,
	BASE64_STATE_1,
	BASE64_STATE_2,
	BASE64_STATE_3,
	BASE64_STATE_CR,
	BASE64_STATE_EOB,
	BASE64_STATE_EOM
};

struct mail_save_attachment_part {
	char *content_type, *content_disposition;
	enum mail_attachment_state state;
	/* start offset of the message part in the original input stream */
	uoff_t start_offset;

	/* for saving attachments base64-decoded: */
	enum base64_state base64_state;
	unsigned int base64_line_blocks, cur_base64_blocks;
	uoff_t base64_bytes;
	bool base64_have_crlf; /* CRLF linefeeds */
	bool base64_failed;

	int temp_fd;
	struct ostream *output;
	struct hash_format *part_hash;
	buffer_t *part_buf;
};

struct mail_save_attachment {
	pool_t pool;
	struct message_parser_ctx *parser;
	struct fs *fs;
	struct istream *input;

	/* per-MIME part data */
	struct mail_save_attachment_part part;
	struct message_part *prev_part;

	ARRAY_TYPE(mail_attachment_extref) extrefs;
};

static const char *index_attachment_dir_get(struct mail_storage *storage)
{
	return mail_user_home_expand(storage->user,
				     storage->set->mail_attachment_dir);
}

void index_attachment_save_begin(struct mail_save_context *ctx,
				 struct fs *fs, struct istream *input)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	pool_t pool;

	i_assert(ctx->attach == NULL);

	if (*storage->set->mail_attachment_dir == '\0')
		return;

	pool = pool_alloconly_create("save attachment", 1024*4);
	ctx->attach = p_new(pool, struct mail_save_attachment, 1);
	ctx->attach->pool = pool;
	ctx->attach->fs = fs;
	ctx->attach->input = input;
	ctx->attach->parser =
		message_parser_init(ctx->attach->pool, input, 0, 0);
	p_array_init(&ctx->attach->extrefs, ctx->attach->pool, 8);
}

static void parse_content_type(struct mail_save_context *ctx,
			       const struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	T_BEGIN {
		content_type = t_str_new(64);
		if (rfc822_parse_content_type(&parser, content_type) >= 0) {
			i_free(ctx->attach->part.content_type);
			ctx->attach->part.content_type =
				i_strdup(str_c(content_type));
		}
	} T_END;
}

static void
parse_content_disposition(struct mail_save_context *ctx,
			  const struct message_header_line *hdr)
{
	/* just pass it as-is to backend. */
	i_free(ctx->attach->part.content_disposition);
	ctx->attach->part.content_disposition =
		i_strndup(hdr->full_value, hdr->full_value_len);
}

static void index_attachment_save_mail_header(struct mail_save_context *ctx,
					      struct message_header_line *hdr)
{
	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	if (strcasecmp(hdr->name, "Content-Type") == 0)
		parse_content_type(ctx, hdr);
	else if (strcasecmp(hdr->name, "Content-Disposition") == 0)
		parse_content_disposition(ctx, hdr);

	o_stream_send(ctx->output, hdr->name, hdr->name_len);
	o_stream_send(ctx->output, hdr->middle, hdr->middle_len);
	o_stream_send(ctx->output, hdr->full_value, hdr->full_value_len);
	if (!hdr->no_newline) {
		if (hdr->crlf_newline)
			o_stream_send(ctx->output, "\r\n", 2);
		else
			o_stream_send(ctx->output, "\n", 1);
	}
}

static bool save_is_attachment(struct mail_save_context *ctx,
			       struct message_part *part)
{
	struct mailbox *box = ctx->transaction->box;
	struct mail_attachment_part apart;

	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0) {
		/* multiparts may contain attachments as children,
		   but they're never themselves */
		return FALSE;
	}
	if (box->v.save_is_attachment == NULL)
		return TRUE;

	memset(&apart, 0, sizeof(apart));
	apart.part = part;
	apart.content_type = ctx->attach->part.content_type;
	apart.content_disposition = ctx->attach->part.content_disposition;
	return box->v.save_is_attachment(ctx, &apart);
}

static int index_attachment_save_temp_open_fd(struct mail_storage *storage)
{
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
		(void)close(fd);
		return -1;
	}
	return fd;
}

static struct hash_format *
index_attachment_hash_format_init(struct mail_save_context *ctx)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct hash_format *format;
	const char *error;

	if (hash_format_init(storage->set->mail_attachment_hash,
			     &format, &error) < 0) {
		/* we already checked this when verifying settings */
		i_panic("mail_attachment_hash=%s unexpectedly failed: %s",
			storage->set->mail_attachment_hash, error);
	}
	return format;
}

static int index_attachment_save_temp_open(struct mail_save_context *ctx)
{
	int fd;

	fd = index_attachment_save_temp_open_fd(ctx->transaction->box->storage);
	if (fd == -1)
		return -1;

	ctx->attach->part.temp_fd = fd;
	ctx->attach->part.output = o_stream_create_fd(fd, 0, FALSE);
	o_stream_cork(ctx->attach->part.output);

	ctx->attach->part.part_hash = index_attachment_hash_format_init(ctx);
	return 0;
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

static int index_attachment_base64_decode(struct mail_save_context *ctx)
{
	struct mail_save_attachment_part *part = &ctx->attach->part;
	struct mail_storage *storage = ctx->transaction->box->storage;
	buffer_t *extra_buf = NULL;
	struct istream *input, *base64_input;
	struct ostream *output;
	struct hash_format *hash;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	buffer_t *buf;
	int outfd;
	bool failed = FALSE;

	if (part->base64_bytes < storage->set->mail_attachment_min_size ||
	    part->output->offset > part->base64_bytes +
	    				BASE64_ATTACHMENT_MAX_EXTRA_BYTES) {
		/* only a small part of the MIME part is base64-encoded. */
		return -1;
	}

	if (part->base64_line_blocks == 0) {
		/* only one line of base64 */
		part->base64_line_blocks = part->cur_base64_blocks;
		i_assert(part->base64_line_blocks > 0);
	}

	/* decode base64 data and write it to another temp file */
	outfd = index_attachment_save_temp_open_fd(storage);
	if (outfd == -1)
		return -1;

	hash = index_attachment_hash_format_init(ctx);
	buf = buffer_create_dynamic(default_pool, 1024);
	input = i_stream_create_fd(part->temp_fd, IO_BLOCK_SIZE, FALSE);
	base64_input = i_stream_create_limit(input, part->base64_bytes);
	output = o_stream_create_fd_file(outfd, 0, FALSE);
	o_stream_cork(output);

	while ((ret = i_stream_read(base64_input)) > 0) {
		data = i_stream_get_data(base64_input, &size);
		buffer_set_used_size(buf, 0);
		if (base64_decode(data, size, &size, buf) < 0) {
			mail_storage_set_critical(storage,
				"Attachment base64 data unexpectedly broke");
			failed = TRUE;
			break;
		}
		i_stream_skip(base64_input, size);
		o_stream_send(output, buf->data, buf->used);
		hash_format_loop(hash, buf->data, buf->used);
	}
	if (ret != -1) {
		i_assert(failed);
	} else if (base64_input->stream_errno != 0) {
		mail_storage_set_critical(storage,
					  "read(attachment-temp) failed: %m");

		failed = TRUE;
	}
	(void)o_stream_flush(output);
	if (save_check_write_error(storage, output) < 0)
		failed = TRUE;

	buffer_free(&buf);
	i_stream_unref(&base64_input);
	o_stream_unref(&output);

	if (input->v_offset != part->output->offset && !failed) {
		/* write the rest of the data to the message stream */
		extra_buf = buffer_create_dynamic(default_pool, 1024);
		while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
			buffer_append(extra_buf, data, size);
			i_stream_skip(input, size);
		}
		i_assert(ret == -1);
		if (input->stream_errno != 0) {
			mail_storage_set_critical(storage,
				"read(attachment-temp) failed: %m");
			failed = TRUE;
		}
	}
	i_stream_unref(&input);

	if (failed) {
		hash_format_deinit_free(&hash);
		if (close(outfd) < 0) {
			mail_storage_set_critical(storage,
				"close(attachment-temp) failed: %m");
		}
		return -1;
	}

	/* successfully wrote it. switch to using it. */
	o_stream_destroy(&part->output);
	if (close(part->temp_fd) < 0) {
		mail_storage_set_critical(storage,
			"close(attachment-decoded-temp) failed: %m");
	}
	part->temp_fd = outfd;

	if (extra_buf != NULL) {
		o_stream_send(ctx->output, extra_buf->data, extra_buf->used);
		buffer_free(&extra_buf);
	}
	hash_format_deinit_free(&part->part_hash);
	part->part_hash = hash;
	return 0;
}

static int index_attachment_save_finish_part(struct mail_save_context *ctx)
{
	struct mail_save_attachment_part *part = &ctx->attach->part;
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct fs_file *file;
	struct istream *input;
	struct ostream *output;
	uint8_t guid_128[MAIL_GUID_128_SIZE];
	const char *attachment_dir, *path, *digest;
	string_t *digest_str;
	const unsigned char *data;
	size_t size;
	uoff_t attachment_size;
	enum fs_open_flags flags = FS_OPEN_FLAG_MKDIR;
	int ret = 0;

	if (o_stream_flush(part->output) < 0) {
		save_check_write_error(storage, part->output);
		return -1;
	}

	if (!part->base64_failed) {
		if (part->base64_state == BASE64_STATE_0 &&
		    part->base64_bytes > 0) {
			/* there is no trailing LF or '=' characters,
			   but it's not completely empty */
			part->base64_state = BASE64_STATE_EOM;
		}
		if (part->base64_state == BASE64_STATE_EOM) {
			/* base64 data looks ok. */
			if (index_attachment_base64_decode(ctx) < 0)
				part->base64_failed = TRUE;
		} else {
			part->base64_failed = TRUE;
		}
	}

	/* open the attachment destination file */
	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER)
		flags |= FS_OPEN_FLAG_FDATASYNC;

	digest_str = t_str_new(128);
	hash_format_deinit(&part->part_hash, digest_str);
	digest = str_c(digest_str);
	if (strlen(digest) < 4) {
		/* make sure we can access first 4 bytes without accessing
		   out of bounds memory */
		digest = t_strconcat(digest, "\0\0\0\0", NULL);
	}

	mail_generate_guid_128(guid_128);
	attachment_dir = index_attachment_dir_get(storage);
	path = t_strdup_printf("%s/%c%c/%c%c/%s-%s", attachment_dir,
			       digest[0], digest[1],
			       digest[2], digest[3], digest,
			       mail_guid_128_to_string(guid_128));
	if (fs_open(ctx->attach->fs, path,
		    FS_OPEN_MODE_CREATE | flags, &file) < 0) {
		mail_storage_set_critical(storage, "%s",
			fs_last_error(ctx->attach->fs));
		return -1;
	}

	/* copy data to it from temp file */
	input = i_stream_create_fd(part->temp_fd, IO_BLOCK_SIZE, FALSE);
	output = fs_write_stream(file);
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		o_stream_send(output, data, size);
		i_stream_skip(input, size);
	}

	if (input->stream_errno != 0) {
		mail_storage_set_critical(storage,
			"read(%s) failed: %m", i_stream_get_name(input));
		ret = -1;
	}
	attachment_size = !part->base64_failed ?
		part->base64_bytes : input->v_offset;
	i_stream_destroy(&input);

	if (ret < 0)
		fs_write_stream_abort(file, &output);
	else if (fs_write_stream_finish(file, &output) < 0) {
		mail_storage_set_critical(storage, "%s",
					  fs_file_last_error(file));
		ret = -1;
	}
	fs_close(&file);

	if (ret == 0) {
		struct mail_attachment_extref *extref;

		extref = array_append_space(&ctx->attach->extrefs);
		extref->start_offset = part->start_offset;
		extref->size = attachment_size;
		extref->path = p_strdup(ctx->attach->pool,
					path + strlen(attachment_dir) + 1);
		extref->base64_blocks_per_line =
			part->base64_failed ? 0 : part->base64_line_blocks;
		extref->base64_have_crlf = part->base64_have_crlf;
	}
	return ret;
}

static int
index_attachment_try_base64_decode_char(struct mail_save_attachment_part *part,
					size_t pos, char chr)
{
	switch (part->base64_state) {
	case BASE64_STATE_0:
		if (base64_is_valid_char(chr))
			part->base64_state++;
		else if (chr == '\r')
			part->base64_state = BASE64_STATE_CR;
		else if (chr == '\n') {
			part->base64_state = BASE64_STATE_0;
			if (part->cur_base64_blocks <
			    part->base64_line_blocks) {
				/* last line */
				part->base64_state = BASE64_STATE_EOM;
				return 0;
			} else if (part->base64_line_blocks == 0) {
				/* first line */
				if (part->cur_base64_blocks == 0)
					return -1;
				part->base64_line_blocks =
					part->cur_base64_blocks;
			} else if (part->cur_base64_blocks ==
				   part->base64_line_blocks) {
				/* line is ok */
			} else {
				return -1;
			}
			part->cur_base64_blocks = 0;
		} else {
			return -1;
		}
		break;
	case BASE64_STATE_1:
		if (!base64_is_valid_char(chr))
			return -1;
		part->base64_state++;
		break;
	case BASE64_STATE_2:
		if (base64_is_valid_char(chr))
			part->base64_state++;
		else if (chr == '=')
			part->base64_state = BASE64_STATE_EOB;
		else
			return -1;
		break;
	case BASE64_STATE_3:
		part->base64_bytes = part->output->offset + pos + 1;
		if (base64_is_valid_char(chr)) {
			part->base64_state = BASE64_STATE_0;
			part->cur_base64_blocks++;
		} else if (chr == '=') {
			part->base64_state = BASE64_STATE_EOM;
			part->cur_base64_blocks++;
			return 0;
		} else {
			return -1;
		}
		break;
	case BASE64_STATE_CR:
		if (chr != '\n')
			return -1;
		part->base64_have_crlf = TRUE;
		break;
	case BASE64_STATE_EOB:
		if (chr != '=')
			return -1;

		part->base64_bytes = part->output->offset + pos + 1;
		part->base64_state = BASE64_STATE_EOM;
		part->cur_base64_blocks++;
		return 0;
	case BASE64_STATE_EOM:
		i_unreached();
	}
	return 1;
}

static void
index_attachment_try_base64_decode(struct mail_save_attachment_part *part,
				   const unsigned char *data, size_t size)
{
	size_t i;
	int ret;

	if (part->base64_failed || part->base64_state == BASE64_STATE_EOM)
		return;

	for (i = 0; i < size; i++) {
		ret = index_attachment_try_base64_decode_char(part, i,
							      (char)data[i]);
		if (ret <= 0) {
			if (ret < 0)
				part->base64_failed = TRUE;
			break;
		}
	}
}

static void index_attachment_save_body(struct mail_save_context *ctx,
				       const struct message_block *block)
{
	struct mail_save_attachment_part *part = &ctx->attach->part;
	struct mail_storage *storage = ctx->transaction->box->storage;
	buffer_t *part_buf;
	size_t new_size;

	switch (part->state) {
	case MAIL_ATTACHMENT_STATE_NO:
		o_stream_send(ctx->output, block->data, block->size);
		break;
	case MAIL_ATTACHMENT_STATE_MAYBE:
		if (part->part_buf == NULL) {
			part->part_buf =
				buffer_create_dynamic(default_pool,
					storage->set->mail_attachment_min_size);
		}
		part_buf = part->part_buf;
		new_size = part_buf->used + block->size;
		if (new_size < storage->set->mail_attachment_min_size) {
			buffer_append(part_buf, block->data, block->size);
			break;
		}
		/* attachment is large enough. we'll first write it to
		   temp file. */
		if (index_attachment_save_temp_open(ctx) < 0) {
			/* failed, fallback to just saving it inline */
			part->state = MAIL_ATTACHMENT_STATE_NO;
			o_stream_send(ctx->output, part_buf->data,
				      part_buf->used);
			o_stream_send(ctx->output, block->data, block->size);
			break;
		}
		part->state = MAIL_ATTACHMENT_STATE_YES;
		index_attachment_try_base64_decode(part, part_buf->data,
						   part_buf->used);
		hash_format_loop(part->part_hash,
				 part_buf->data, part_buf->used);
		o_stream_send(part->output, part_buf->data, part_buf->used);
		buffer_set_used_size(part_buf, 0);
		/* fall through */
	case MAIL_ATTACHMENT_STATE_YES:
		index_attachment_try_base64_decode(part, block->data,
						   block->size);
		hash_format_loop(part->part_hash, block->data, block->size);
		o_stream_send(part->output, block->data, block->size);
		break;
	}
}

static void index_attachment_save_close(struct mail_save_context *ctx)
{
	struct mail_save_attachment_part *part = &ctx->attach->part;
	struct mail_storage *storage = ctx->transaction->box->storage;

	if (part->output != NULL)
		o_stream_destroy(&part->output);
	if (close(part->temp_fd) < 0) {
		mail_storage_set_critical(storage,
					  "close(attachment-temp) failed: %m");
	}
	part->temp_fd = -1;
}

static int
index_attachment_save_body_part_changed(struct mail_save_context *ctx)
{
	struct mail_save_attachment_part *part = &ctx->attach->part;
	int ret = 0;

	/* body part changed. we're now parsing the end of a
	   boundary, possibly followed by message epilogue */
	switch (part->state) {
	case MAIL_ATTACHMENT_STATE_NO:
		break;
	case MAIL_ATTACHMENT_STATE_MAYBE:
		/* body part wasn't large enough. write to main file. */
		if (part->part_buf != NULL) {
			o_stream_send(ctx->output, part->part_buf->data,
				      part->part_buf->used);
		}
		break;
	case MAIL_ATTACHMENT_STATE_YES:
		if (index_attachment_save_finish_part(ctx) < 0)
			ret = -1;
		index_attachment_save_close(ctx);
		break;
	}
	part->state = MAIL_ATTACHMENT_STATE_NO;

	i_free_and_null(part->content_type);
	i_free_and_null(part->content_disposition);
	if (part->part_buf != NULL)
		buffer_free(&part->part_buf);
	memset(part, 0, sizeof(*part));
	return ret;
}

int index_attachment_save_continue(struct mail_save_context *ctx)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct message_parser_ctx *parser = ctx->attach->parser;
	struct message_block block;
	struct ostream *output;
	int ret;

	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (block.part != ctx->attach->prev_part) {
			if (index_attachment_save_body_part_changed(ctx) < 0)
				return -1;
			ctx->attach->prev_part = block.part;
		}

		if (block.hdr != NULL)
			index_attachment_save_mail_header(ctx, block.hdr);
		else if (block.size == 0) {
			/* end of headers */
			if (save_is_attachment(ctx, block.part)) {
				ctx->attach->part.state =
					MAIL_ATTACHMENT_STATE_MAYBE;
				ctx->attach->part.start_offset =
					ctx->attach->input->v_offset;
			}
		} else {
			/* body */
			index_attachment_save_body(ctx, &block);
		}

		output = ctx->attach->part.output != NULL ?
			ctx->attach->part.output : ctx->output;
		if (output->last_failed_errno != 0)
			break;
		index_mail_cache_parse_continue(ctx->dest_mail);
	}
	if (ret == 0)
		return 0;

	if (ctx->attach->input->stream_errno != 0) {
		errno = ctx->attach->input->stream_errno;
		mail_storage_set_critical(storage, "read(%s) failed: %m",
			i_stream_get_name(ctx->attach->input));
		return -1;
	}
	if (ctx->attach->part.output != NULL) {
		if (save_check_write_error(storage,
					   ctx->attach->part.output) < 0)
			return -1;
	}
	if (ctx->output != NULL) {
		if (save_check_write_error(storage, ctx->output) < 0)
			return -1;
	}
	return 0;
}

int index_attachment_save_finish(struct mail_save_context *ctx)
{
	struct message_part *parts;
	int ret = 0, ret2;

	if (ctx->attach->parser != NULL) {
		if (index_attachment_save_body_part_changed(ctx) < 0)
			ret = -1;
		ret2 = message_parser_deinit(&ctx->attach->parser, &parts);
		i_assert(ret2 == 0);
	}
	i_assert(ctx->attach->part.output == NULL);
	return ret;
}

void index_attachment_save_free(struct mail_save_context *ctx)
{
	if (ctx->attach != NULL) {
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
