/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "imap-message-cache.h"
#include "message-part-serialize.h"
#include "mail-index.h"
#include "mail-index-util.h"

#include <unistd.h>

typedef struct {
	MailIndex *index;
	MailIndexRecord *rec;
} IndexMsgcacheContext;

void *index_msgcache_get_context(MailIndex *index, MailIndexRecord *rec)
{
	IndexMsgcacheContext *ctx;

	ctx = t_new(IndexMsgcacheContext, 1);
	ctx->index = index;
	ctx->rec = rec;
	return ctx;
}

static IOBuffer *index_msgcache_open_mail(void *context)
{
        IndexMsgcacheContext *ctx = context;

	return ctx->index->open_mail(ctx->index, ctx->rec);
}

static IOBuffer *index_msgcache_inbuf_rewind(IOBuffer *inbuf,
					     void *context __attr_unused__)
{
	if (!io_buffer_seek(inbuf, 0)) {
		i_error("index_msgcache_inbuf_rewind: lseek() failed: %m");

		io_buffer_destroy(inbuf);
		return NULL;
	}

	return inbuf;
}

static const char *index_msgcache_get_cached_field(ImapCacheField field,
						   void *context)
{
	IndexMsgcacheContext *ctx = context;
	MailField index_field;

	switch (field) {
	case IMAP_CACHE_BODY:
		index_field = FIELD_TYPE_BODY;
		break;
	case IMAP_CACHE_BODYSTRUCTURE:
		index_field = FIELD_TYPE_BODYSTRUCTURE;
		break;
	case IMAP_CACHE_ENVELOPE:
		index_field = FIELD_TYPE_ENVELOPE;
		break;
	default:
		index_field = 0;
	}

	return index_field == 0 ? NULL :
		ctx->index->lookup_field(ctx->index, ctx->rec, index_field);
}

static MessagePart *index_msgcache_get_cached_parts(Pool pool, void *context)
{
	IndexMsgcacheContext *ctx = context;
	MessagePart *part;
	const void *part_data;
	size_t part_size;

	part_data = ctx->index->lookup_field_raw(ctx->index, ctx->rec,
						 FIELD_TYPE_MESSAGEPART,
						 &part_size);
	if (part_data == NULL)
		return NULL;

	part = message_part_deserialize(pool, part_data, part_size);
	if (part == NULL) {
		index_set_corrupted(ctx->index,
				    "Corrupted cached MessagePart data");
		return NULL;
	}

	return part;
}

ImapMessageCacheIface index_msgcache_iface = {
	index_msgcache_open_mail,
	index_msgcache_inbuf_rewind,
	index_msgcache_get_cached_field,
	index_msgcache_get_cached_parts
};
