/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ostream.h"
#include "message-date.h"
#include "imap-envelope.h"
#include "imap-message-cache.h"
#include "mail-index.h"
#include "mail-modifylog.h"
#include "index-storage.h"
#include "index-sort.h"

static struct mail_index_record *
lookup_client_seq(struct index_sort_context *ctx, unsigned int client_seq)
{
	struct mail_index_record *rec;
        unsigned int expunges_before;

	if (ctx->synced_sequences)
		return ctx->ibox->index->lookup(ctx->ibox->index, client_seq);

	t_push();
	if (mail_modifylog_seq_get_expunges(ctx->ibox->index->modifylog,
					    client_seq, client_seq,
					    &expunges_before) == NULL) {
		rec = NULL;
	} else {
		rec = ctx->ibox->index->lookup(ctx->ibox->index,
					       client_seq - expunges_before);
	}
	t_pop();

	return rec;
}

static struct imap_message_cache *
search_open_cache(struct index_sort_context *ctx, unsigned int id)
{
	i_assert(id != 0);

	if (ctx->last_id != id) {
		ctx->cached = FALSE;
		ctx->last_id = id;

		if ((ctx->id_is_uid && ctx->current_rec->uid == id) ||
		    (!ctx->id_is_uid && ctx->current_client_seq == id)) {
			ctx->rec = ctx->current_rec;
		} else if (ctx->id_is_uid) {
			ctx->rec = ctx->ibox->index->
				lookup_uid_range(ctx->ibox->index,
						 id, id, NULL);
		} else {
			ctx->rec = lookup_client_seq(ctx, id);
		}

		if (ctx->rec == NULL) {
			ctx->last_id = 0;
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

static uoff_t _input_uofft(enum mail_sort_type type,
			   unsigned int id, void *context)
{
	struct index_sort_context *ctx = context;
        struct imap_message_cache *cache;

	if (type != MAIL_SORT_SIZE) {
		i_unreached();
		return 0;
	}

        cache = search_open_cache(ctx, id);
	return cache == NULL ? 0 : imap_msgcache_get_virtual_size(cache);
}

static const char *_input_mailbox(enum mail_sort_type type, unsigned int id,
				  void *context)
{
	struct index_sort_context *ctx = context;
	enum imap_envelope_field env_field;
	const char *envelope, *str;

	switch (type) {
	case MAIL_SORT_CC:
		env_field = IMAP_ENVELOPE_CC;
		break;
	case MAIL_SORT_FROM:
                env_field = IMAP_ENVELOPE_FROM;
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
	if (envelope == NULL)
		return NULL;

	if (!imap_envelope_parse(envelope, env_field,
				 IMAP_ENVELOPE_RESULT_TYPE_FIRST_MAILBOX, &str))
		return NULL;

	return str;
}

static const char *_input_str(enum mail_sort_type type,
			      unsigned int id, void *context)
{
	struct index_sort_context *ctx = context;
	enum imap_envelope_field env_field;
	const char *envelope, *str;

	switch (type) {
	case MAIL_SORT_DATE:
                env_field = IMAP_ENVELOPE_DATE;
		break;
	case MAIL_SORT_SUBJECT:
                env_field = IMAP_ENVELOPE_SUBJECT;
		break;
	default:
		i_unreached();
		return NULL;
	}

	/* get field from hopefully cached envelope */
	envelope = imap_msgcache_get(search_open_cache(ctx, id),
				     IMAP_CACHE_ENVELOPE);
	if (envelope == NULL)
		return NULL;

	if (!imap_envelope_parse(envelope, env_field,
				 IMAP_ENVELOPE_RESULT_TYPE_STRING, &str))
		return NULL;

	return str;
}

static time_t _input_time(enum mail_sort_type type,
			  unsigned int id, void *context)
{
	struct index_sort_context *ctx = context;
        struct imap_message_cache *cache;
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

		if (!message_date_parse(str, &time, &timezone_offset))
			return 0;

		return time;
	default:
		i_unreached();
		return 0;
	}
}

static void _input_reset(void *context)
{
	struct index_sort_context *ctx = context;

	ctx->cached = FALSE;
}

struct mail_sort_callbacks index_sort_callbacks = {
	_input_time,
	_input_uofft,
	_input_mailbox,
	_input_str,
	_input_reset
};
