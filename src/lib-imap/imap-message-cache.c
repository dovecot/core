/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "temp-string.h"
#include "mmap-util.h"
#include "message-parser.h"
#include "message-part-serialize.h"
#include "message-size.h"
#include "imap-bodystructure.h"
#include "imap-envelope.h"
#include "imap-message-cache.h"

#include <unistd.h>

/* It's not very useful to cache lots of messages, as they're mostly wanted
   just once. The biggest reason for this cache to exist is to get just the
   latest message. */
#define MAX_CACHED_MESSAGES 16

#define DEFAULT_MESSAGE_POOL_SIZE 4096

typedef struct _CachedMessage CachedMessage;

struct _CachedMessage {
	CachedMessage *next;

	Pool pool;
	unsigned int uid;

	MessagePart *part;
	MessageSize *hdr_size;
	MessageSize *body_size;
	MessageSize *partial_size;

	time_t internal_date;
	uoff_t full_virtual_size;

	char *cached_body;
	char *cached_bodystructure;
	char *cached_envelope;

	MessagePartEnvelopeData *envelope;
};

struct _ImapMessageCache {
	ImapMessageCacheIface *iface;

	CachedMessage *messages;
	int messages_count;

	CachedMessage *open_msg;
	IStream *open_stream;

	void *context;
};

ImapMessageCache *imap_msgcache_alloc(ImapMessageCacheIface *iface)
{
	ImapMessageCache *cache;

	cache = i_new(ImapMessageCache, 1);
	cache->iface = iface;
	return cache;
}

static void cached_message_free(CachedMessage *msg)
{
	pool_unref(msg->pool);
}

void imap_msgcache_clear(ImapMessageCache *cache)
{
	CachedMessage *next;

	imap_msgcache_close(cache);

	while (cache->messages != NULL) {
		next = cache->messages->next;
		cached_message_free(cache->messages);
		cache->messages = next;
	}
}

void imap_msgcache_free(ImapMessageCache *cache)
{
	imap_msgcache_clear(cache);
	i_free(cache);
}

static CachedMessage *cache_new(ImapMessageCache *cache, unsigned int uid)
{
	CachedMessage *msg, **msgp;
	Pool pool;

	if (cache->messages_count < MAX_CACHED_MESSAGES)
		cache->messages_count++;
	else {
		/* remove the last message from cache */
                msgp = &cache->messages;
		while ((*msgp)->next != NULL)
			msgp = &(*msgp)->next;

		cached_message_free(*msgp);
		*msgp = NULL;
	}

	pool = pool_create("CachedMessage", DEFAULT_MESSAGE_POOL_SIZE, FALSE);

	msg = p_new(pool, CachedMessage, 1);
	msg->pool = pool;
	msg->uid = uid;
	msg->internal_date = (time_t)-1;
	msg->full_virtual_size = (uoff_t)-1;

	msg->next = cache->messages;
	cache->messages = msg;
	return msg;
}

static CachedMessage *cache_open_or_create(ImapMessageCache *cache,
					   unsigned int uid)
{
	CachedMessage **pos, *msg;

	pos = &cache->messages;
	for (; *pos != NULL; pos = &(*pos)->next) {
		if ((*pos)->uid == uid)
			break;
	}

	if (*pos == NULL) {
		/* not found, add it */
		msg = cache_new(cache, uid);
	} else if (*pos != cache->messages) {
		/* move it to first in list */
		msg = *pos;
		*pos = msg->next;

		msg->next = cache->messages;
		cache->messages = msg;
	} else {
		msg = *pos;
	}

	return msg;
}

static void parse_envelope_header(MessagePart *part,
				  const char *name, size_t name_len,
				  const char *value, size_t value_len,
				  void *context)
{
	CachedMessage *msg = context;

	if (part == NULL || part->parent == NULL) {
		/* parse envelope headers if we're at the root message part */
		imap_envelope_parse_header(msg->pool, &msg->envelope,
					   t_strndup(name, name_len),
					   value, value_len);
	}
}

static int imap_msgcache_get_stream(ImapMessageCache *cache, uoff_t offset)
{
	if (cache->open_stream == NULL)
		cache->open_stream = cache->iface->open_mail(cache->context);
	else if (offset < cache->open_stream->v_offset) {
		/* need to rewind */
		cache->open_stream =
			cache->iface->stream_rewind(cache->open_stream,
						    cache->context);
	}

	if (cache->open_stream == NULL)
		return FALSE;

	i_assert(offset >= cache->open_stream->v_offset);

	i_stream_skip(cache->open_stream,
		      offset - cache->open_stream->v_offset);
	return TRUE;
}

static void msg_get_part(ImapMessageCache *cache)
{
	if (cache->open_msg->part == NULL) {
		cache->open_msg->part =
			cache->iface->get_cached_parts(cache->open_msg->pool,
						       cache->context);
	}
}

/* Caches the fields for given message if possible */
static int cache_fields(ImapMessageCache *cache, ImapCacheField fields)
{
        CachedMessage *msg;
	const char *value;
	int failed;

	msg = cache->open_msg;
	failed = FALSE;

	t_push();

	if ((fields & IMAP_CACHE_BODYSTRUCTURE) &&
	    msg->cached_bodystructure == NULL) {
		value = cache->iface->get_cached_field(IMAP_CACHE_BODYSTRUCTURE,
						       cache->context);
		if (value == NULL && imap_msgcache_get_stream(cache, 0)) {
			msg_get_part(cache);

			value = imap_part_get_bodystructure(msg->pool,
							    &msg->part,
							    cache->open_stream,
							    TRUE);
		}

		msg->cached_bodystructure = p_strdup(msg->pool, value);
		failed = value == NULL;
	}

	if ((fields & IMAP_CACHE_BODY) && msg->cached_body == NULL) {
		value = cache->iface->get_cached_field(IMAP_CACHE_BODY,
						       cache->context);
		if (value == NULL && cache->open_stream != NULL) {
			/* we can generate it from cached BODYSTRUCTURE.
			   do it only if the file isn't open already, since
			   this takes more CPU than parsing message headers. */
			value = cache->iface->get_cached_field(
						IMAP_CACHE_BODYSTRUCTURE,
						cache->context);
			if (value != NULL) {
				value = imap_body_parse_from_bodystructure(
									value);
			}
		}

		if (value == NULL && imap_msgcache_get_stream(cache, 0)) {
			msg_get_part(cache);

			value = imap_part_get_bodystructure(msg->pool,
							    &msg->part,
							    cache->open_stream,
							    FALSE);
		}

		msg->cached_body = p_strdup(msg->pool, value);
		failed = value == NULL;
	}

	if ((fields & IMAP_CACHE_ENVELOPE) && msg->cached_envelope == NULL) {
		value = cache->iface->get_cached_field(IMAP_CACHE_ENVELOPE,
						       cache->context);
		if (value == NULL) {
			if (msg->envelope == NULL &&
			    imap_msgcache_get_stream(cache, 0)) {
				/* envelope isn't parsed yet, do it. header
				   size is calculated anyway so save it */
				if (msg->hdr_size == NULL) {
					msg->hdr_size = p_new(msg->pool,
							      MessageSize, 1);
				}

				message_parse_header(NULL, cache->open_stream,
						     msg->hdr_size,
						     parse_envelope_header,
						     msg);
			}

			value = imap_envelope_get_part_data(msg->envelope);
		}

		msg->cached_envelope = p_strdup(msg->pool, value);
		failed = value == NULL;
	}

	if ((fields & IMAP_CACHE_VIRTUAL_SIZE) &&
	    msg->full_virtual_size == (uoff_t)-1) {
		fields |= IMAP_CACHE_MESSAGE_HDR_SIZE |
			IMAP_CACHE_MESSAGE_BODY_SIZE;
	}

	if ((fields & IMAP_CACHE_MESSAGE_BODY_SIZE) && msg->body_size == NULL) {
		/* we don't have body size. and since we're already going
		   to scan the whole message body, we might as well build
		   the MessagePart. FIXME: this slows down things when it's
		   not needed, do we really want to? */
                fields |= IMAP_CACHE_MESSAGE_PART;
	}

	if (fields & IMAP_CACHE_MESSAGE_PART) {
		msg_get_part(cache);

		if (msg->part == NULL && imap_msgcache_get_stream(cache, 0)) {
			/* we need to parse the message */
			MessageHeaderFunc func;

			if ((fields & IMAP_CACHE_ENVELOPE) &&
			    msg->cached_envelope == NULL) {
				/* we need envelope too, fill the info
				   while parsing headers */
				func = parse_envelope_header;
			} else {
				func = NULL;
			}

			msg->part = message_parse(msg->pool, cache->open_stream,
						  func, msg);
		} else {
			failed = TRUE;
		}
	}

	if ((fields & IMAP_CACHE_MESSAGE_BODY_SIZE) && msg->body_size == NULL) {
		i_assert(msg->part != NULL);

		msg->body_size = p_new(msg->pool, MessageSize, 1);
		if (msg->hdr_size == NULL)
			msg->hdr_size = p_new(msg->pool, MessageSize, 1);

		*msg->hdr_size = msg->part->header_size;
		*msg->body_size = msg->part->body_size;
	}

	if ((fields & IMAP_CACHE_MESSAGE_HDR_SIZE) && msg->hdr_size == NULL) {
		msg_get_part(cache);

		msg->hdr_size = p_new(msg->pool, MessageSize, 1);
		if (msg->part != NULL) {
			/* easy, get it from root part */
			*msg->hdr_size = msg->part->header_size;

			if (msg->body_size == NULL) {
				msg->body_size = p_new(msg->pool,
						       MessageSize, 1);
				*msg->body_size = msg->part->body_size;
			}
		} else {
			/* need to do some light parsing */
			if (imap_msgcache_get_stream(cache, 0)) {
				message_get_header_size(cache->open_stream,
							msg->hdr_size);
			} else {
				failed = TRUE;
			}
		}
	}

	if ((fields & IMAP_CACHE_VIRTUAL_SIZE) &&
	    msg->full_virtual_size == (uoff_t)-1) {
		if (msg->hdr_size == NULL || msg->body_size == NULL)
			failed = TRUE;
		else {
			msg->full_virtual_size = msg->hdr_size->virtual_size +
                                msg->body_size->virtual_size;
		}
	}

	if (fields & IMAP_CACHE_MESSAGE_OPEN) {
		/* this isn't needed for anything else than pre-opening the
		   mail and seeing if it fails. */
		failed = !imap_msgcache_get_stream(cache, 0);
	}

	if ((fields & IMAP_CACHE_INTERNALDATE) &&
	    msg->internal_date == (time_t)-1) {
		/* keep this last, since we may get it when mail file is
		   opened. */
		msg->internal_date =
			cache->iface->get_internal_date(cache->context);
		failed = msg->internal_date == (time_t)-1;
	}

	t_pop();
	return !failed;
}

int imap_msgcache_open(ImapMessageCache *cache, unsigned int uid,
		       ImapCacheField fields,
		       uoff_t vp_header_size, uoff_t vp_body_size,
		       uoff_t full_virtual_size, void *context)
{
	CachedMessage *msg;

	msg = cache_open_or_create(cache, uid);
	if (cache->open_msg != msg) {
		imap_msgcache_close(cache);

		cache->open_msg = msg;
		cache->context = context;
	}

	if (vp_header_size != (uoff_t)-1 && msg->hdr_size == NULL) {
		/* physical size == virtual size */
		msg->hdr_size = p_new(msg->pool, MessageSize, 1);
		msg->hdr_size->physical_size = msg->hdr_size->virtual_size =
			vp_header_size;
	}

	if (vp_body_size != (uoff_t)-1 && msg->body_size == NULL) {
		/* physical size == virtual size */
		msg->body_size = p_new(msg->pool, MessageSize, 1);
		msg->body_size->physical_size = msg->body_size->virtual_size =
			vp_body_size;
	}

	msg->full_virtual_size = full_virtual_size;

	return cache_fields(cache, fields);
}

void imap_msgcache_close(ImapMessageCache *cache)
{
	if (cache->open_stream != NULL) {
		i_stream_unref(cache->open_stream);
		cache->open_stream = NULL;
	}

	cache->open_msg = NULL;
	cache->context = NULL;
}

const char *imap_msgcache_get(ImapMessageCache *cache, ImapCacheField field)
{
	CachedMessage *msg;

	i_assert(cache->open_msg != NULL);

	msg = cache->open_msg;
	switch (field) {
	case IMAP_CACHE_BODY:
		if (msg->cached_body == NULL)
			cache_fields(cache, field);
		return msg->cached_body;
	case IMAP_CACHE_BODYSTRUCTURE:
		if (msg->cached_bodystructure == NULL)
			cache_fields(cache, field);
		return msg->cached_bodystructure;
	case IMAP_CACHE_ENVELOPE:
		if (msg->cached_envelope == NULL)
			cache_fields(cache, field);
		return msg->cached_envelope;
	default:
                i_unreached();
	}

	return NULL;
}

MessagePart *imap_msgcache_get_parts(ImapMessageCache *cache)
{
	if (cache->open_msg->part == NULL)
		cache_fields(cache, IMAP_CACHE_MESSAGE_PART);
	return cache->open_msg->part;
}

uoff_t imap_msgcache_get_virtual_size(ImapMessageCache *cache)
{
	if (cache->open_msg->full_virtual_size == (uoff_t)-1)
		cache_fields(cache, IMAP_CACHE_VIRTUAL_SIZE);
	return cache->open_msg->full_virtual_size;
}

time_t imap_msgcache_get_internal_date(ImapMessageCache *cache)
{
	if (cache->open_msg->internal_date == (time_t)-1)
		cache_fields(cache, IMAP_CACHE_INTERNALDATE);
	return cache->open_msg->internal_date;
}

int imap_msgcache_get_rfc822(ImapMessageCache *cache, IStream **stream,
			     MessageSize *hdr_size, MessageSize *body_size)
{
	CachedMessage *msg;
	uoff_t offset;

	i_assert(cache->open_msg != NULL);

	msg = cache->open_msg;
	if (stream != NULL) {
		if (msg->hdr_size == NULL)
			cache_fields(cache, IMAP_CACHE_MESSAGE_HDR_SIZE);
		offset = hdr_size != NULL ? 0 :
			msg->hdr_size->physical_size;
		if (!imap_msgcache_get_stream(cache, offset))
			return FALSE;
                *stream = cache->open_stream;
	}

	if (body_size != NULL) {
		if (msg->body_size == NULL)
			cache_fields(cache, IMAP_CACHE_MESSAGE_BODY_SIZE);
		if (msg->body_size == NULL)
			return FALSE;
		*body_size = *msg->body_size;
	}

	if (hdr_size != NULL) {
		if (msg->hdr_size == NULL)
			cache_fields(cache, IMAP_CACHE_MESSAGE_HDR_SIZE);
		if (msg->hdr_size == NULL)
			return FALSE;
		*hdr_size = *msg->hdr_size;
	}

	return TRUE;
}

static void get_partial_size(IStream *stream,
			     uoff_t virtual_skip, uoff_t max_virtual_size,
			     MessageSize *partial, MessageSize *dest,
			     int *cr_skipped)
{
	/* see if we can use the existing partial */
	if (partial->virtual_size > virtual_skip)
		memset(partial, 0, sizeof(MessageSize));
	else {
		i_stream_skip(stream, partial->physical_size);
		virtual_skip -= partial->virtual_size;
	}

	message_skip_virtual(stream, virtual_skip, partial, cr_skipped);
	message_get_body_size(stream, dest, max_virtual_size);

	if (*cr_skipped) {
		dest->virtual_size--;
		partial->virtual_size--;
	}
}

int imap_msgcache_get_rfc822_partial(ImapMessageCache *cache,
				     uoff_t virtual_skip,
				     uoff_t max_virtual_size,
				     int get_header, MessageSize *size,
                                     IStream **stream, int *cr_skipped)
{
	CachedMessage *msg;
	uoff_t physical_skip, full_size;
	int size_got;

	i_assert(cache->open_msg != NULL);

	memset(size, 0, sizeof(MessageSize));
	*stream = NULL;
	*cr_skipped = FALSE;

	msg = cache->open_msg;

	if (msg->hdr_size == NULL) {
		cache_fields(cache, IMAP_CACHE_MESSAGE_HDR_SIZE);
		if (msg->hdr_size == NULL)
			return FALSE;
	}

	/* see if we can do this easily */
	size_got = FALSE;
	if (virtual_skip == 0) {
		if (msg->body_size == NULL) {
			cache_fields(cache, IMAP_CACHE_MESSAGE_BODY_SIZE);
			if (msg->body_size == NULL)
				return FALSE;
		}

		full_size = msg->body_size->virtual_size;
		if (get_header)
			full_size += msg->hdr_size->virtual_size;

		if (max_virtual_size >= full_size) {
			memcpy(size, msg->body_size, sizeof(MessageSize));
			if (get_header)
				message_size_add(size, msg->hdr_size);
			size_got = TRUE;
		}
	}

	if (size_got) {
		physical_skip = get_header ? 0 : msg->hdr_size->physical_size;
	} else {
		if (!imap_msgcache_get_stream(cache, 0))
			return FALSE;

		if (msg->partial_size == NULL)
			msg->partial_size = p_new(msg->pool, MessageSize, 1);
		if (!get_header)
			virtual_skip += msg->hdr_size->virtual_size;

		get_partial_size(cache->open_stream, virtual_skip,
				 max_virtual_size, msg->partial_size, size,
				 cr_skipped);

		physical_skip = msg->partial_size->physical_size;
	}

	/* seek to wanted position */
	if (!imap_msgcache_get_stream(cache, physical_skip))
		return FALSE;

        *stream = cache->open_stream;
	return TRUE;
}

int imap_msgcache_get_data(ImapMessageCache *cache, IStream **stream)
{
	i_assert(cache->open_msg != NULL);

	if (!imap_msgcache_get_stream(cache, 0))
		return FALSE;

        *stream = cache->open_stream;
	return TRUE;
}
