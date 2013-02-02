/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "istream.h"
#include "istream-crlf.h"
#include "istream-seekable.h"
#include "istream-base64.h"
#include "istream-qp.h"
#include "istream-header-filter.h"
#include "ostream.h"
#include "message-binary-part.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "mail-user.h"
#include "index-storage.h"
#include "index-mail.h"

#define MAIL_BINARY_CACHE_EXPIRE_MSECS (60*1000)

#define IS_CONVERTED_CTE(cte) \
	((cte) == MESSAGE_CTE_QP || (cte) == MESSAGE_CTE_BASE64)

struct binary_block {
	struct istream *input;
	uoff_t physical_pos;
	unsigned int body_lines_count;
	bool converted, converted_hdr;
};

struct binary_ctx {
	struct mail *mail;
	struct istream *input;
	bool has_nuls, converted;
	ARRAY(struct binary_block) blocks;

	uoff_t copy_start_offset;
};

static void binary_copy_to(struct binary_ctx *ctx, uoff_t end_offset)
{
	struct binary_block *block;
	struct istream *linput, *cinput;
	uoff_t orig_offset, size;

	i_assert(end_offset >= ctx->copy_start_offset);

	if (end_offset == ctx->copy_start_offset)
		return;

	size = end_offset - ctx->copy_start_offset;
	orig_offset = ctx->input->v_offset;

	i_stream_seek(ctx->input, ctx->copy_start_offset);
	linput = i_stream_create_limit(ctx->input, size);
	cinput = i_stream_create_crlf(linput);
	i_stream_unref(&linput);

	block = array_append_space(&ctx->blocks);
	block->input = cinput;

	i_stream_seek(ctx->input, orig_offset);
}

static void
binary_cte_filter_callback(struct header_filter_istream *input,
			   struct message_header_line *hdr,
			   bool *matched ATTR_UNUSED, void *context ATTR_UNUSED)
{
	static const char *cte_binary = "Content-Transfer-Encoding: binary\r\n";

	if (hdr != NULL && hdr->eoh) {
		i_stream_header_filter_add(input, cte_binary,
					   strlen(cte_binary));
	}
}

static int
add_binary_part(struct binary_ctx *ctx, const struct message_part *part,
		bool include_hdr)
{
	static const char *filter_headers[] = {
		"Content-Transfer-Encoding",
	};
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct message_part *child;
	struct message_size hdr_size;
	struct istream *linput;
	struct binary_block *block;
	enum message_cte cte;
	uoff_t part_end_offset;
	int ret;

	/* first parse the header to find c-t-e. */
	i_stream_seek(ctx->input, part->physical_pos);

	cte = MESSAGE_CTE_78BIT;
	parser = message_parse_header_init(ctx->input, &hdr_size, 0);
	while ((ret = message_parse_header_next(parser, &hdr)) > 0) {
		if (strcasecmp(hdr->name, "Content-Transfer-Encoding") == 0)
			cte = message_decoder_parse_cte(hdr);
	}
	i_assert(ret < 0);
	if (message_parse_header_has_nuls(parser)) {
		/* we're not converting NULs to 0x80 when doing a binary fetch,
		   even if they're in the message header. */
		ctx->has_nuls = TRUE;
	}
	message_parse_header_deinit(&parser);

	if (ctx->input->stream_errno != 0) {
		errno = ctx->input->stream_errno;
		mail_storage_set_critical(ctx->mail->box->storage,
			"read(%s) failed: %m", i_stream_get_name(ctx->input));
		return -1;
	}

	if (cte == MESSAGE_CTE_UNKNOWN) {
		mail_storage_set_error(ctx->mail->box->storage,
				       MAIL_ERROR_CONVERSION,
				       "Unknown Content-Transfer-Encoding.");
		return -1;
	}

	i_stream_seek(ctx->input, part->physical_pos);
	if (!include_hdr) {
		/* body only */
	} else if (IS_CONVERTED_CTE(cte)) {
		/* write header with modified content-type */
		if (ctx->copy_start_offset != 0)
			binary_copy_to(ctx, part->physical_pos);
		block = array_append_space(&ctx->blocks);
		block->physical_pos = part->physical_pos;
		block->converted = TRUE;
		block->converted_hdr = TRUE;

		linput = i_stream_create_limit(ctx->input, (uoff_t)-1);
		block->input = i_stream_create_header_filter(linput,
				HEADER_FILTER_EXCLUDE | HEADER_FILTER_HIDE_BODY,
				filter_headers, N_ELEMENTS(filter_headers),
				binary_cte_filter_callback, (void *)NULL);
		i_stream_unref(&linput);
	} else {
		/* copy everything as-is until the end of this header */
		binary_copy_to(ctx, part->physical_pos +
			       part->header_size.physical_size);
	}
	ctx->copy_start_offset = part->physical_pos +
		part->header_size.physical_size;
	part_end_offset = part->physical_pos +
		part->header_size.physical_size +
		part->body_size.physical_size;

	if (part->children != NULL) {
		/* multipart */
		for (child = part->children; child != NULL; child = child->next) {
			if (add_binary_part(ctx, child, TRUE) < 0)
				return -1;
		}
		binary_copy_to(ctx, part_end_offset);
		ctx->copy_start_offset = part_end_offset;
		return 0;
	}
	if (part->body_size.physical_size == 0) {
		/* no body */
		ctx->copy_start_offset = part_end_offset;
		return 0;
	}

	/* single part - write decoded data */
	block = array_append_space(&ctx->blocks);
	block->physical_pos = part->physical_pos;

	i_stream_seek(ctx->input, part->physical_pos +
		      part->header_size.physical_size);
	linput = i_stream_create_limit(ctx->input, part->body_size.physical_size);
	switch (cte) {
	case MESSAGE_CTE_UNKNOWN:
		i_unreached();
	case MESSAGE_CTE_78BIT:
	case MESSAGE_CTE_BINARY:
		/* no conversion necessary */
		if ((part->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0)
			ctx->has_nuls = TRUE;
		block->input = i_stream_create_crlf(linput);
		break;
	case MESSAGE_CTE_QP:
		block->input = i_stream_create_qp_decoder(linput);
		ctx->converted = block->converted = TRUE;
		break;
	case MESSAGE_CTE_BASE64:
		block->input = i_stream_create_base64_decoder(linput);
		ctx->converted = block->converted = TRUE;
		break;
	}
	i_stream_unref(&linput);

	ctx->copy_start_offset = part_end_offset;
	return 0;
}

static int fd_callback(const char **path_r, void *context)
{
	struct mail *_mail = context;
	string_t *path;
	int fd;

	path = t_str_new(256);
	mail_user_set_get_temp_prefix(path, _mail->box->storage->user->set);
	fd = safe_mkstemp_hostpid(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("Temp file creation to %s failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		i_close_fd(&fd);
		return -1;
	}
	*path_r = str_c(path);
	return fd;
}

static void binary_streams_free(struct binary_ctx *ctx)
{
	struct binary_block *block;

	array_foreach_modifiable(&ctx->blocks, block)
		i_stream_unref(&block->input);
}

static void
binary_parts_update(struct binary_ctx *ctx, const struct message_part *part,
		    struct message_binary_part **msg_bin_parts)
{
	struct index_mail *mail = (struct index_mail *)ctx->mail;
	struct binary_block *blocks;
	struct message_binary_part bin_part;
	unsigned int i, count;
	uoff_t size;
	bool found;

	blocks = array_get_modifiable(&ctx->blocks, &count);
	for (; part != NULL; part = part->next) {
		binary_parts_update(ctx, part->children, msg_bin_parts);

		memset(&bin_part, 0, sizeof(bin_part));
		/* default to unchanged header */
		bin_part.binary_hdr_size = part->header_size.virtual_size;
		bin_part.physical_pos = part->physical_pos;
		found = FALSE;
		for (i = 0; i < count; i++) {
			if (blocks[i].physical_pos != part->physical_pos ||
			    !blocks[i].converted)
				continue;

			size = blocks[i].input->v_offset;
			if (blocks[i].converted_hdr)
				bin_part.binary_hdr_size = size;
			else
				bin_part.binary_body_size = size;
			found = TRUE;
		}
		if (found) {
			bin_part.next = *msg_bin_parts;
			*msg_bin_parts = p_new(mail->mail.data_pool,
					       struct message_binary_part, 1);
			**msg_bin_parts = bin_part;
		}
	}
}

static void binary_parts_cache(struct binary_ctx *ctx)
{
	struct index_mail *mail = (struct index_mail *)ctx->mail;
	buffer_t *buf;

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	message_binary_part_serialize(mail->data.bin_parts, buf);
	index_mail_cache_add(mail, MAIL_CACHE_BINARY_PARTS,
			     buf->data, buf->used);
}

static struct istream **blocks_get_streams(struct binary_ctx *ctx)
{
	struct istream **streams;
	const struct binary_block *blocks;
	unsigned int i, count;

	blocks = array_get(&ctx->blocks, &count);
	streams = t_new(struct istream *, count+1);
	for (i = 0; i < count; i++) {
		streams[i] = blocks[i].input;
		i_assert(streams[i]->v_offset == 0);
	}
	return streams;
}

static int
blocks_count_lines(struct binary_ctx *ctx, struct istream *full_input)
{
	struct binary_block *blocks, *cur_block;
	unsigned int block_idx, block_count;
	uoff_t cur_offset, cur_size;
	const unsigned char *data, *p;
	size_t size, skip;
	ssize_t ret;

	blocks = array_get_modifiable(&ctx->blocks, &block_count);
	cur_block = blocks;
	cur_offset = 0;
	block_idx = 0;

	while ((ret = i_stream_read_data(full_input, &data, &size, 0)) > 0) {
		i_assert(cur_offset <= cur_block->input->v_offset);
		if (cur_block->input->eof) {
			cur_size = cur_block->input->v_offset +
				i_stream_get_data_size(cur_block->input);
			i_assert(size >= cur_size - cur_offset);
			size = cur_size - cur_offset;
		}
		skip = size;
		while ((p = memchr(data, '\n', size)) != NULL) {
			size -= p-data+1;
			data = p+1;
			cur_block->body_lines_count++;
		}
		i_stream_skip(full_input, skip);
		cur_offset += skip;

		if (cur_block->input->eof) {
			if (++block_idx == block_count)
				cur_block = NULL;
			else
				cur_block++;
			cur_offset = 0;
		}
	}
	i_assert(ret == -1);
	if (full_input->stream_errno != 0)
		return -1;
	i_assert(block_count == 0 || !i_stream_have_bytes_left(cur_block->input));
	i_assert(block_count == 0 || block_idx+1 == block_count);
	return 0;
}

static int
index_mail_read_binary_to_cache(struct mail *_mail,
				const struct message_part *part,
				bool include_hdr, bool *binary_r,
				bool *converted_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct mail_binary_cache *cache = &_mail->box->storage->binary_cache;
	struct binary_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.mail = _mail;
	t_array_init(&ctx.blocks, 8);

	mail_storage_free_binary_cache(_mail->box->storage);
	if (mail_get_stream(_mail, NULL, NULL, &ctx.input) < 0)
		return -1;

	if (add_binary_part(&ctx, part, include_hdr) < 0) {
		binary_streams_free(&ctx);
		return -1;
	}

	cache->to = timeout_add(MAIL_BINARY_CACHE_EXPIRE_MSECS,
				mail_storage_free_binary_cache,
				_mail->box->storage);
	cache->box = _mail->box;
	cache->uid = _mail->uid;
	cache->orig_physical_pos = part->physical_pos;
	cache->include_hdr = include_hdr;

	if (array_count(&ctx.blocks) != 0) {
		cache->input = i_streams_merge(blocks_get_streams(&ctx),
					       IO_BLOCK_SIZE,
					       fd_callback, _mail);
	} else {
		cache->input = i_stream_create_from_data("", 0);
	}
	i_stream_set_name(cache->input, t_strdup_printf(
		"<binary stream of mailbox %s UID %u>",
		_mail->box->vname, _mail->uid));
	if (blocks_count_lines(&ctx, cache->input) < 0) {
		if (cache->input->stream_errno == EINVAL) {
			/* MIME part contains invalid data */
			mail_storage_set_error(_mail->box->storage,
					       MAIL_ERROR_INVALIDDATA,
					       "Invalid data in MIME part");
		} else {
			mail_storage_set_critical(_mail->box->storage,
				"read(%s) failed: %m",
				i_stream_get_name(cache->input));
		}
		mail_storage_free_binary_cache(_mail->box->storage);
		binary_streams_free(&ctx);
		return -1;
	}
	i_assert(!i_stream_have_bytes_left(cache->input));
	cache->size = cache->input->v_offset;
	i_stream_seek(cache->input, 0);

	if (part->parent == NULL && include_hdr &&
	    mail->data.bin_parts == NULL) {
		binary_parts_update(&ctx, part, &mail->data.bin_parts);
		binary_parts_cache(&ctx);
	}
	binary_streams_free(&ctx);

	*binary_r = ctx.converted ? TRUE : ctx.has_nuls;
	*converted_r = ctx.converted;
	return 0;
}

static bool get_cached_binary_parts(struct index_mail *mail)
{
	const unsigned int field_idx =
		mail->ibox->cache_fields[MAIL_CACHE_BINARY_PARTS].idx;
	buffer_t *part_buf;
	int ret;

	if (mail->data.bin_parts != NULL)
		return TRUE;

	part_buf = buffer_create_dynamic(pool_datastack_create(), 128);
	ret = index_mail_cache_lookup_field(mail, part_buf, field_idx);
	if (ret <= 0)
		return FALSE;

	if (message_binary_part_deserialize(mail->mail.data_pool,
					    part_buf->data, part_buf->used,
					    &mail->data.bin_parts) < 0) {
		mail_cache_set_corrupted(mail->mail.mail.box->cache,
			"Corrupted cached binary.parts data");
		return FALSE;
	}
	return TRUE;
}

static struct message_part *
msg_part_find(struct message_part *parts, uoff_t physical_pos)
{
	struct message_part *part, *child;

	for (part = parts; part != NULL; part = part->next) {
		if (part->physical_pos == physical_pos)
			return part;
		child = msg_part_find(part->children, physical_pos);
		if (child != NULL)
			return child;
	}
	return NULL;
}

static int
index_mail_get_binary_size(struct mail *_mail,
			   const struct message_part *part, bool include_hdr,
			   uoff_t *size_r, unsigned int *lines_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct message_part *all_parts, *msg_part;
	const struct message_binary_part *bin_part, *root_bin_part;
	uoff_t size, end_offset;
	unsigned int lines;
	bool binary, converted;

	if (mail_get_parts(_mail, &all_parts) < 0)
		return -1;

	/* first lookup from cache */
	if (!get_cached_binary_parts(mail)) {
		/* not found. parse the whole message */
		if (index_mail_read_binary_to_cache(_mail, all_parts, TRUE,
						    &binary, &converted) < 0)
			return -1;
	}

	size = part->header_size.virtual_size +
		part->body_size.virtual_size;
	/* note that we assume here that binary translation doesn't change the
	   headers' line counts. this isn't true if the original message
	   contained duplicate Content-Transfer-Encoding lines, but since
	   that's invalid anyway we don't bother trying to handle it. */
	lines = part->header_size.lines + part->body_size.lines;
	end_offset = part->physical_pos + size;

	bin_part = mail->data.bin_parts; root_bin_part = NULL;
	for (; bin_part != NULL; bin_part = bin_part->next) {
		msg_part = msg_part_find(all_parts, bin_part->physical_pos);
		if (msg_part == NULL) {
			mail_set_cache_corrupted(_mail, MAIL_FETCH_MESSAGE_PARTS);
			return -1;
		}
		if (msg_part->physical_pos >= part->physical_pos &&
		    msg_part->physical_pos < end_offset) {
			if (msg_part->physical_pos == part->physical_pos)
				root_bin_part = bin_part;
			size -= msg_part->header_size.virtual_size +
				msg_part->body_size.virtual_size;
			size += bin_part->binary_hdr_size +
				bin_part->binary_body_size;
			lines -= msg_part->body_size.lines;
			lines += bin_part->binary_body_lines_count;
		}
	}
	if (!include_hdr) {
		if (root_bin_part != NULL)
			size -= root_bin_part->binary_hdr_size;
		else
			size -= part->header_size.virtual_size;
		lines -= part->header_size.lines;
	}
	*size_r = size;
	*lines_r = lines;
	return 0;
}

int index_mail_get_binary_stream(struct mail *_mail,
				 const struct message_part *part,
				 bool include_hdr, uoff_t *size_r,
				 unsigned int *lines_r, bool *binary_r,
				 struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct mail_binary_cache *cache = &_mail->box->storage->binary_cache;
	struct istream *input;
	bool binary, converted;

	if (stream_r == NULL) {
		return index_mail_get_binary_size(_mail, part, include_hdr,
						  size_r, lines_r);
	}
	/* current implementation doesn't bother implementing this,
	   because it's not needed by anything. */
	i_assert(lines_r == NULL);

	/* FIXME: always put the header to temp file. skip it when needed. */
	if (cache->box == _mail->box && cache->uid == _mail->uid &&
	    cache->orig_physical_pos == part->physical_pos &&
	    cache->include_hdr == include_hdr) {
		/* we have this cached already */
		i_stream_seek(cache->input, 0);
		timeout_reset(cache->to);
		binary = TRUE;
		converted = TRUE;
	} else {
		if (index_mail_read_binary_to_cache(_mail, part, include_hdr,
						    &binary, &converted) < 0)
			return -1;
		mail->data.cache_fetch_fields |= MAIL_FETCH_STREAM_BINARY;
	}
	*size_r = cache->size;
	*binary_r = binary;
	if (stream_r != NULL) {
		i_stream_ref(cache->input);
		*stream_r = cache->input;
	}
	if (!converted) {
		/* don't keep this cached. it's exactly the same as
		   the original stream */
		mail_storage_free_binary_cache(_mail->box->storage);
		if (stream_r != NULL) {
			i_stream_unref(stream_r);
			i_stream_seek(mail->data.stream, part->physical_pos +
				      (include_hdr ? 0 :
				       part->header_size.physical_size));
			input = i_stream_create_crlf(mail->data.stream);
			*stream_r = i_stream_create_limit(input, *size_r);
			i_stream_unref(&input);
		}
	}
	return 0;
}
