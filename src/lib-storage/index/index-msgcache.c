/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "imap-date.h"
#include "imap-message-cache.h"
#include "message-part-serialize.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "index-storage.h"

#include <unistd.h>

typedef struct {
	MailIndex *index;
	MailIndexRecord *rec;
	time_t internal_date;
} IndexMsgcacheContext;

int index_msgcache_open(ImapMessageCache *cache, MailIndex *index,
			MailIndexRecord *rec, ImapCacheField fields)
{
	IndexMsgcacheContext *ctx;
	uoff_t vp_header_size, vp_body_size, full_virtual_size;
	const uoff_t *uoff_p;
	size_t size;

	ctx = t_new(IndexMsgcacheContext, 1);
	ctx->index = index;
	ctx->rec = rec;
	ctx->internal_date = (time_t)-1;

	full_virtual_size = (uoff_t)-1;
	vp_header_size = (uoff_t)-1;
	vp_body_size = (uoff_t)-1;

	if ((ctx->rec->index_flags & INDEX_MAIL_FLAG_BINARY_HEADER)) {
		uoff_p = ctx->index->lookup_field_raw(ctx->index, ctx->rec,
						      DATA_HDR_HEADER_SIZE,
						      &size);
		if (uoff_p != NULL) {
			i_assert(size == sizeof(*uoff_p));
			vp_header_size = *uoff_p;
		}
	}

	if ((ctx->rec->index_flags & INDEX_MAIL_FLAG_BINARY_BODY)) {
		uoff_p = ctx->index->lookup_field_raw(ctx->index, ctx->rec,
						      DATA_HDR_BODY_SIZE,
						      &size);
		if (uoff_p != NULL) {
			i_assert(size == sizeof(*uoff_p));
			vp_body_size = *uoff_p;
		}
	}

	if (vp_header_size != (uoff_t)-1 && vp_body_size != (uoff_t)-1)
		full_virtual_size = vp_header_size + vp_body_size;
	else {
		uoff_p = ctx->index->lookup_field_raw(ctx->index, ctx->rec,
						      DATA_HDR_VIRTUAL_SIZE,
						      &size);
		if (uoff_p != NULL) {
			i_assert(size == sizeof(*uoff_p));
			full_virtual_size = *uoff_p;
		}
	}

	return imap_msgcache_open(cache, rec->uid, fields,
				  vp_header_size, vp_body_size,
				  full_virtual_size, ctx);
}

static IBuffer *index_msgcache_open_mail(void *context)
{
	IndexMsgcacheContext *ctx = context;
	int deleted;

	return ctx->index->open_mail(ctx->index, ctx->rec,
				     &ctx->internal_date, &deleted);
}

static IBuffer *index_msgcache_inbuf_rewind(IBuffer *inbuf,
					    void *context __attr_unused__)
{
	if (!i_buffer_seek(inbuf, 0)) {
		i_error("index_msgcache_inbuf_rewind: lseek() failed: %m");

		i_buffer_unref(inbuf);
		return NULL;
	}

	return inbuf;
}

static const char *index_msgcache_get_cached_field(ImapCacheField field,
						   void *context)
{
	IndexMsgcacheContext *ctx = context;
	MailDataField data_field;
	const time_t *time_p;
	const char *ret;
	size_t size;

	switch (field) {
	case IMAP_CACHE_INTERNALDATE:
		if (ctx->internal_date != (time_t)-1)
			return imap_to_datetime(ctx->internal_date);

		time_p = ctx->index->lookup_field_raw(ctx->index, ctx->rec,
						      DATA_HDR_INTERNAL_DATE,
						      &size);
		if (time_p == NULL) {
			i_assert(size == sizeof(*time_p));
			return imap_to_datetime(*time_p);
		} else {
			ctx->index->cache_fields_later(ctx->index,
						       DATA_HDR_INTERNAL_DATE);
			return NULL;
		}
	case IMAP_CACHE_BODY:
		data_field = DATA_FIELD_BODY;
		break;
	case IMAP_CACHE_BODYSTRUCTURE:
		data_field = DATA_FIELD_BODYSTRUCTURE;
		break;
	case IMAP_CACHE_ENVELOPE:
		data_field = DATA_FIELD_ENVELOPE;
		break;
	default:
		return NULL;
	}

	ret = ctx->index->lookup_field(ctx->index, ctx->rec, data_field);
	if (ret == NULL)
		ctx->index->cache_fields_later(ctx->index, data_field);
	return ret;
}

static MessagePart *index_msgcache_get_cached_parts(Pool pool, void *context)
{
	IndexMsgcacheContext *ctx = context;
	MessagePart *part;
	const void *part_data;
	size_t part_size;

	part_data = ctx->index->lookup_field_raw(ctx->index, ctx->rec,
						 DATA_FIELD_MESSAGEPART,
						 &part_size);
	if (part_data == NULL) {
		ctx->index->cache_fields_later(ctx->index,
					       DATA_FIELD_MESSAGEPART);
		return NULL;
	}

	part = message_part_deserialize(pool, part_data, part_size);
	if (part == NULL) {
		index_set_corrupted(ctx->index,
				    "Corrupted cached MessagePart data");
		return NULL;
	}

	return part;
}

static time_t index_msgcache_get_internal_date(void *context)
{
	IndexMsgcacheContext *ctx = context;

	if (ctx->internal_date != (time_t)-1)
		return ctx->internal_date;

	return ctx->index->get_internal_date(ctx->index, ctx->rec);
}

ImapMessageCacheIface index_msgcache_iface = {
	index_msgcache_open_mail,
	index_msgcache_inbuf_rewind,
	index_msgcache_get_cached_field,
	index_msgcache_get_cached_parts,
	index_msgcache_get_internal_date
};
