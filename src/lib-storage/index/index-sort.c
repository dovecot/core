/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ostream.h"
#include "rfc822-date.h"
#include "imap-envelope.h"
#include "imap-message-cache.h"
#include "mail-index.h"
#include "index-storage.h"
#include "index-sort.h"

static ImapMessageCache *search_open_cache(IndexSortContext *ctx,
					   unsigned int uid)
{
	if (ctx->last_uid != uid) {
		ctx->cached = FALSE;
		ctx->last_uid = uid;
		ctx->rec = ctx->ibox->index->lookup_uid_range(ctx->ibox->index,
							      uid, uid, NULL);
		if (ctx->rec == NULL) {
			ctx->last_uid = 0;
			return NULL;
		}
	}

	if (!ctx->cached) {
		ctx->cached = TRUE;
		(void)index_msgcache_open(ctx->ibox->cache,
					  ctx->ibox->index, ctx->rec,
					  IMAP_CACHE_ENVELOPE);
	}

	return ctx->ibox->cache;
}

static uoff_t _input_uofft(MailSortType type, unsigned int id, void *context)
{
	IndexSortContext *ctx = context;
        ImapMessageCache *cache;

	if (type != MAIL_SORT_SIZE) {
		i_unreached();
		return 0;
	}

        cache = search_open_cache(ctx, id);
	return cache == NULL ? 0 : imap_msgcache_get_virtual_size(cache);
}

static const char *_input_str(MailSortType type, unsigned int id, void *context)
{
	IndexSortContext *ctx = context;
	ImapEnvelopeField env_field;
	const char *envelope;

	switch (type) {
	case MAIL_SORT_CC:
		env_field = IMAP_ENVELOPE_CC;
		break;
	case MAIL_SORT_DATE:
                env_field = IMAP_ENVELOPE_DATE;
		break;
	case MAIL_SORT_FROM:
                env_field = IMAP_ENVELOPE_FROM;
		break;
	case MAIL_SORT_SUBJECT:
                env_field = IMAP_ENVELOPE_SUBJECT;
		break;
	case MAIL_SORT_TO:
                env_field = IMAP_ENVELOPE_TO;
		break;
	default:
		i_unreached();
		return NULL;
	}

	/* get field from hopefully cached envelope */
	envelope = imap_msgcache_get(search_open_cache(ctx, id),
				     IMAP_CACHE_ENVELOPE);
	return envelope == NULL ? NULL :
		imap_envelope_parse(envelope, env_field);
}

static time_t _input_time(MailSortType type, unsigned int id, void *context)
{
	IndexSortContext *ctx = context;
        ImapMessageCache *cache;
	const char *str;
	time_t time;
	int timezone_offset;

	switch (type) {
	case MAIL_SORT_ARRIVAL:
		cache = search_open_cache(ctx, id);
		return cache == NULL ? 0 :
			imap_msgcache_get_internal_date(cache);
	case MAIL_SORT_DATE:
		str = _input_str(type, id, context);
		if (str == NULL)
			return 0;

		if (!rfc822_parse_date(str, &time, &timezone_offset))
			return 0;

		return time - timezone_offset*60;
	default:
		i_unreached();
		return 0;
	}
}

static void _input_reset(void *context)
{
	IndexSortContext *ctx = context;

	ctx->cached = FALSE;
}

static void _output(unsigned int *data, size_t count, void *context)
{
	IndexSortContext *ctx = context;
	char num[MAX_INT_STRLEN+1];
	size_t i, len;

	for (i = 0; i < count; i++) {
		len = i_snprintf(num, sizeof(num), " %u", data[i]);
		o_stream_send(ctx->output, num, len);
	}
}

MailSortFuncs index_sort_funcs = {
	_input_time,
	_input_uofft,
	_input_str,
	_input_reset,
	_output
};
