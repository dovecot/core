/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

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
#include "message-parser.h"
#include "message-decoder.h"
#include "mail-user.h"
#include "index-mail.h"

#define MAIL_BINARY_CACHE_EXPIRE_MSECS (60*1000)

struct binary_ctx {
	struct mail *mail;
	struct istream *input;
	bool has_nuls, converted;
	ARRAY_DEFINE(streams, struct istream *);

	uoff_t copy_start_offset;
};

static void binary_copy_to(struct binary_ctx *ctx, uoff_t end_offset)
{
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
	array_append(&ctx->streams, &cinput, 1);

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
	struct istream *linput, *cinput;
	enum message_cte cte;
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
				       MAIL_ERROR_CONVERSION, "Unknown CTE");
		return -1;
	}

	i_stream_seek(ctx->input, part->physical_pos);
	if (!include_hdr) {
		/* body only */
	} else if (cte == MESSAGE_CTE_QP || cte == MESSAGE_CTE_BASE64) {
		/* write header with modified content-type */
		if (ctx->copy_start_offset != 0)
			binary_copy_to(ctx, part->physical_pos);
		linput = i_stream_create_limit(ctx->input, (uoff_t)-1);
		cinput = i_stream_create_header_filter(linput,
				HEADER_FILTER_EXCLUDE | HEADER_FILTER_HIDE_BODY,
				filter_headers, N_ELEMENTS(filter_headers),
				binary_cte_filter_callback, ctx);
		i_stream_unref(&linput);
		array_append(&ctx->streams, &cinput, 1);
	} else {
		/* copy everything as-is until the end of this header */
		binary_copy_to(ctx, part->physical_pos +
			       part->header_size.physical_size);
	}
	ctx->copy_start_offset = part->physical_pos +
		part->header_size.physical_size;

	if (part->children != NULL) {
		/* multipart */
		for (child = part->children; child != NULL; child = child->next) {
			if (add_binary_part(ctx, child, TRUE) < 0)
				return -1;
		}
		binary_copy_to(ctx, part->physical_pos +
			       part->header_size.physical_size +
			       part->body_size.physical_size);
		return 0;
	}

	/* single part - write decoded data */
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
		cinput = linput;
		i_stream_ref(cinput);
		break;
	case MESSAGE_CTE_QP:
		cinput = i_stream_create_qp_decoder(linput);
		ctx->converted = TRUE;
		break;
	case MESSAGE_CTE_BASE64:
		cinput = i_stream_create_base64_decoder(linput);
		ctx->converted = TRUE;
		break;
	}
	i_stream_unref(&linput);
	array_append(&ctx->streams, &cinput, 1);

	ctx->copy_start_offset = part->physical_pos +
		part->header_size.physical_size +
		part->body_size.physical_size;
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
	struct istream **input;

	array_foreach_modifiable(&ctx->streams, input) {
		if (*input != NULL)
			i_stream_unref(input);
	}
}

int index_mail_get_binary_stream(struct mail *_mail,
				 const struct message_part *part,
				 bool include_hdr, uoff_t *size_r,
				 bool *binary_r, struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct mail_binary_cache *cache = &_mail->box->storage->binary_cache;
	struct binary_ctx ctx;

	/* FIXME: if stream_r=NULL try to lookup the size from cache. */

	memset(&ctx, 0, sizeof(ctx));
	if (cache->box == _mail->box && cache->uid == _mail->uid &&
	    cache->orig_physical_pos == part->physical_pos &&
	    cache->include_hdr == include_hdr) {
		/* we have this cached already */
		i_stream_seek(cache->input, 0);
		timeout_reset(cache->to);
		ctx.converted = TRUE;
	} else {
		mail->data.cache_fetch_fields |= MAIL_FETCH_STREAM_BINARY;

		ctx.mail = _mail;
		t_array_init(&ctx.streams, 8);

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

		(void)array_append_space(&ctx.streams);
		cache->input = i_streams_merge(
					array_idx_modifiable(&ctx.streams, 0),
					IO_BLOCK_SIZE, fd_callback, _mail);
		binary_streams_free(&ctx);

		if (i_stream_get_size(cache->input, TRUE, &cache->size) < 0) {
			mail_storage_set_critical(_mail->box->storage,
					"read(%s) failed: %m",
					i_stream_get_name(cache->input));
			mail_storage_free_binary_cache(_mail->box->storage);
			return -1;
		}
	}
	*size_r = cache->size;
	*binary_r = ctx.converted ? TRUE : ctx.has_nuls;
	if (stream_r != NULL) {
		i_stream_ref(cache->input);
		*stream_r = cache->input;
	}
	if (!ctx.converted) {
		/* don't keep this cached. it's the original stream. */
		mail_storage_free_binary_cache(_mail->box->storage);
		if (stream_r != NULL) {
			i_stream_unref(stream_r);
			i_stream_seek(ctx.input, part->physical_pos +
				      (include_hdr ? 0 :
				       part->header_size.physical_size));
			*stream_r = i_stream_create_limit(ctx.input, *size_r);
		}
	}
	return 0;
}

#if 0
static struct message_binary_part *
get_cached_binary_parts(struct index_mail *mail)
{
	const unsigned int field_idx =
		mail->ibox->cache_fields[MAIL_CACHE_BINARY_PARTS].idx;
	struct message_binary_part *parts;
	buffer_t *part_buf;
	const char *error;
	int ret;

	if (mail->data.bin_parts != NULL)
		return mail->data.bin_parts;

	part_buf = buffer_create_dynamic(pool_datastack_create(), 128);
	ret = index_mail_cache_lookup_field(mail, part_buf, field_idx);
	if (ret <= 0)
		return NULL;

	if (message_binary_part_deserialize(mail->data_pool, part_buf->data,
					    part_buf->used, &parts, &error) < 0) {
		mail_cache_set_corrupted(mail->mail.mail.box->cache,
			"Corrupted cached binary.parts data (%s)", error);
	}
	return parts;
}
#endif
