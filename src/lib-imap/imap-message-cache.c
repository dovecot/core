/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "temp-string.h"
#include "mmap-util.h"
#include "message-parser.h"
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

	char *cached_body;
	char *cached_bodystructure;
	char *cached_envelope;

	MessagePartEnvelopeData *envelope;
};

struct _ImapMessageCache {
	CachedMessage *messages;
	int messages_count;

	CachedMessage *open_msg;
	IOBuffer *open_inbuf;
	uoff_t open_virtual_size;

	IOBuffer *(*inbuf_rewind)(IOBuffer *inbuf, void *context);
	void *context;
};

ImapMessageCache *imap_msgcache_alloc(void)
{
	return i_new(ImapMessageCache, 1);
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
				  const char *name, unsigned int name_len,
				  const char *value, unsigned int value_len,
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

static CachedMessage *cache_find(ImapMessageCache *cache, unsigned int uid)
{
	CachedMessage *msg;

	for (msg = cache->messages; msg != NULL; msg = msg->next) {
		if (msg->uid == uid)
			return msg;
	}

	return NULL;
}

static void imap_msgcache_get_inbuf(ImapMessageCache *cache, uoff_t offset)
{
	if (offset < cache->open_inbuf->offset) {
		/* need to rewind */
		cache->open_inbuf = cache->inbuf_rewind(cache->open_inbuf,
							cache->context);
		if (cache->open_inbuf == NULL)
			i_fatal("Can't rewind message buffer");
	}

	io_buffer_skip(cache->open_inbuf, offset - cache->open_inbuf->offset);
}

int imap_msgcache_is_cached(ImapMessageCache *cache, unsigned int uid,
			    ImapCacheField fields)
{
	CachedMessage *msg;

	if (cache->open_msg != NULL && cache->open_msg->uid == uid)
		return TRUE;

	/* not open, see if the wanted fields are cached */
	msg = cache_find(cache, uid);
	if (msg == NULL)
		return FALSE;

	if ((fields & IMAP_CACHE_BODY) && msg->cached_body == NULL)
		return FALSE;
	if ((fields & IMAP_CACHE_BODYSTRUCTURE) &&
	    msg->cached_bodystructure == NULL)
		return FALSE;
	if ((fields & IMAP_CACHE_ENVELOPE) && msg->cached_envelope == NULL)
		return FALSE;

	if ((fields & IMAP_CACHE_MESSAGE_OPEN) && msg != cache->open_msg)
		return FALSE;
	if ((fields & IMAP_CACHE_MESSAGE_PART) && msg->part == NULL)
		return FALSE;
	if ((fields & IMAP_CACHE_MESSAGE_HDR_SIZE) && msg->hdr_size == NULL)
		return FALSE;
	if ((fields & IMAP_CACHE_MESSAGE_BODY_SIZE) && msg->body_size == NULL)
		return FALSE;

	return TRUE;
}

/* Caches the fields for given message if possible */
static void cache_fields(ImapMessageCache *cache, CachedMessage *msg,
			 ImapCacheField fields)
{
	const char *value;

	t_push();
	if ((fields & IMAP_CACHE_BODY) && msg->cached_body == NULL &&
	    msg == cache->open_msg) {
                imap_msgcache_get_inbuf(cache, 0);
		value = imap_part_get_bodystructure(msg->pool, &msg->part,
						    cache->open_inbuf, FALSE);
		msg->cached_body = p_strdup(msg->pool, value);
	}

	if ((fields & IMAP_CACHE_BODYSTRUCTURE) &&
	    msg->cached_bodystructure == NULL && msg == cache->open_msg) {
                imap_msgcache_get_inbuf(cache, 0);
		value = imap_part_get_bodystructure(msg->pool, &msg->part,
						    cache->open_inbuf, TRUE);
		msg->cached_bodystructure = p_strdup(msg->pool, value);
	}

	if ((fields & IMAP_CACHE_ENVELOPE) && msg->cached_envelope == NULL) {
		if (msg->envelope == NULL && msg == cache->open_msg) {
			/* envelope isn't parsed yet, do it. header size
			   is calculated anyway so save it */
			if (msg->hdr_size == NULL) {
				msg->hdr_size = p_new(msg->pool,
						      MessageSize, 1);
			}

			imap_msgcache_get_inbuf(cache, 0);
			message_parse_header(NULL, cache->open_inbuf,
					     msg->hdr_size,
					     parse_envelope_header, msg);
		}

		if (msg->envelope != NULL) {
			value = imap_envelope_get_part_data(msg->envelope);
			msg->cached_envelope = p_strdup(msg->pool, value);
		}
	}

	if ((fields & IMAP_CACHE_MESSAGE_PART) && msg->part == NULL &&
	    msg == cache->open_msg) {
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

                imap_msgcache_get_inbuf(cache, 0);
		msg->part = message_parse(msg->pool, cache->open_inbuf,
					  func, msg);
	}

	if ((fields & IMAP_CACHE_MESSAGE_BODY_SIZE) &&
	    msg->body_size == NULL &&
	    (msg == cache->open_msg || msg->part != NULL)) {
		/* fill the body size, and while at it fill the header size
		   as well */
		if (msg->hdr_size == NULL)
			msg->hdr_size = p_new(msg->pool, MessageSize, 1);
		msg->body_size = p_new(msg->pool, MessageSize, 1);

		if (msg->part != NULL) {
			/* easy, get it from root part */
			*msg->hdr_size = msg->part->header_size;
			*msg->body_size = msg->part->body_size;
		} else {
			/* first get the header's size, then calculate the
			   body size from it and the total virtual size */
			imap_msgcache_get_inbuf(cache, 0);
			message_get_header_size(cache->open_inbuf,
						msg->hdr_size);

			/* FIXME: this may actually happen if file size is
			   shrinked.. */
			i_assert(msg->hdr_size->physical_size <=
				 cache->open_inbuf->size);
			i_assert(msg->hdr_size->virtual_size <=
				 cache->open_virtual_size);

			msg->body_size->lines = 0;
			msg->body_size->physical_size =
				cache->open_inbuf->size -
				msg->hdr_size->physical_size;
			msg->body_size->virtual_size =
				cache->open_virtual_size -
				msg->hdr_size->virtual_size;
		}
	}

	if ((fields & IMAP_CACHE_MESSAGE_HDR_SIZE) && msg->hdr_size == NULL &&
	    (msg == cache->open_msg || msg->part != NULL)) {
		msg->hdr_size = p_new(msg->pool, MessageSize, 1);

		if (msg->part != NULL) {
			/* easy, get it from root part */
			*msg->hdr_size = msg->part->header_size;
		} else {
			/* need to do some light parsing */
			imap_msgcache_get_inbuf(cache, 0);
			message_get_header_size(cache->open_inbuf,
						msg->hdr_size);
		}
	}

	t_pop();
}

void imap_msgcache_message(ImapMessageCache *cache, unsigned int uid,
			   ImapCacheField fields, uoff_t virtual_size,
			   uoff_t pv_headers_size, uoff_t pv_body_size,
			   IOBuffer *inbuf,
			   IOBuffer *(*inbuf_rewind)(IOBuffer *inbuf,
						     void *context),
			   void *context)
{
	CachedMessage *msg;

	msg = cache_open_or_create(cache, uid);
	if (cache->open_msg != msg) {
		imap_msgcache_close(cache);

		cache->open_msg = msg;
		cache->open_inbuf = inbuf;
		cache->open_virtual_size = virtual_size;

		cache->inbuf_rewind = inbuf_rewind;
		cache->context = context;
	}

	if (pv_headers_size != 0 && msg->hdr_size == NULL) {
		/* physical size == virtual size */
		msg->hdr_size = p_new(msg->pool, MessageSize, 1);
		msg->hdr_size->physical_size = msg->hdr_size->virtual_size =
			pv_headers_size;
	}

	if (pv_body_size != 0 && msg->body_size == NULL) {
		/* physical size == virtual size */
		msg->body_size = p_new(msg->pool, MessageSize, 1);
		msg->body_size->physical_size = msg->body_size->virtual_size =
			pv_body_size;
	}

	cache_fields(cache, msg, fields);
}

void imap_msgcache_close(ImapMessageCache *cache)
{
	if (cache->open_inbuf != NULL) {
		(void)close(cache->open_inbuf->fd);
		io_buffer_destroy(cache->open_inbuf);
		cache->open_inbuf = NULL;
	}

	cache->open_msg = NULL;
	cache->open_virtual_size = 0;
}

void imap_msgcache_set(ImapMessageCache *cache, unsigned int uid,
		       ImapCacheField field, const char *value)
{
	CachedMessage *msg;

	msg = cache_find(cache, uid);
	if (msg == NULL)
		msg = cache_new(cache, uid);

	switch (field) {
	case IMAP_CACHE_BODY:
		msg->cached_body = p_strdup(msg->pool, value);
		break;
	case IMAP_CACHE_BODYSTRUCTURE:
		msg->cached_bodystructure = p_strdup(msg->pool, value);
		break;
	case IMAP_CACHE_ENVELOPE:
		msg->cached_envelope = p_strdup(msg->pool, value);
		break;
	default:
		i_assert(0);
	}
}

const char *imap_msgcache_get(ImapMessageCache *cache, unsigned int uid,
			      ImapCacheField field)
{
	CachedMessage *msg;

	msg = cache_find(cache, uid);
	if (msg == NULL)
		return NULL;

	switch (field) {
	case IMAP_CACHE_BODY:
		if (msg->cached_body == NULL)
			cache_fields(cache, msg, field);
		return msg->cached_body;
	case IMAP_CACHE_BODYSTRUCTURE:
		if (msg->cached_bodystructure == NULL)
			cache_fields(cache, msg, field);
		return msg->cached_bodystructure;
	case IMAP_CACHE_ENVELOPE:
		if (msg->cached_envelope == NULL)
			cache_fields(cache, msg, field);
		return msg->cached_envelope;
	default:
		i_assert(0);
	}

	return NULL;
}

MessagePart *imap_msgcache_get_parts(ImapMessageCache *cache, unsigned int uid)
{
	CachedMessage *msg;

	msg = cache_find(cache, uid);
	if (msg == NULL)
		return NULL;

	if (msg->part == NULL)
		cache_fields(cache, msg, IMAP_CACHE_MESSAGE_PART);
	return msg->part;
}

int imap_msgcache_get_rfc822(ImapMessageCache *cache, unsigned int uid,
			     MessageSize *hdr_size, MessageSize *body_size,
			     IOBuffer **inbuf)
{
	CachedMessage *msg;
	uoff_t offset;

	if (inbuf != NULL) {
		if (cache->open_msg == NULL || cache->open_msg->uid != uid)
			return FALSE;

		msg = cache->open_msg;

		offset = hdr_size != NULL ? 0 :
			msg->hdr_size->physical_size;
		imap_msgcache_get_inbuf(cache, offset);
                *inbuf = cache->open_inbuf;
	} else {
		msg = cache_find(cache, uid);
		if (msg == NULL)
			return FALSE;
	}

	if (body_size != NULL) {
		if (msg->body_size == NULL)
			cache_fields(cache, msg, IMAP_CACHE_MESSAGE_BODY_SIZE);
		if (msg->body_size == NULL)
			return FALSE;
		*body_size = *msg->body_size;
	}

	if (hdr_size != NULL) {
		if (msg->hdr_size == NULL)
			cache_fields(cache, msg, IMAP_CACHE_MESSAGE_HDR_SIZE);
		if (msg->hdr_size == NULL)
			return FALSE;
		*hdr_size = *msg->hdr_size;
	}

	return TRUE;
}

static void get_partial_size(IOBuffer *inbuf,
			     uoff_t virtual_skip, uoff_t max_virtual_size,
			     MessageSize *partial, MessageSize *dest)
{
	unsigned char *msg;
	unsigned int size;
	int cr_skipped;

	/* see if we can use the existing partial */
	if (partial->virtual_size > virtual_skip)
		memset(partial, 0, sizeof(MessageSize));
	else {
		io_buffer_skip(inbuf, partial->physical_size);
		virtual_skip -= partial->virtual_size;
	}

	message_skip_virtual(inbuf, virtual_skip, partial, &cr_skipped);

	if (!cr_skipped) {
		/* see if we need to add virtual CR */
		while (io_buffer_read_data(inbuf, &msg, &size, 0) >= 0) {
			if (size > 0) {
				if (msg[0] == '\n')
					dest->virtual_size++;
				break;
			}
		}
	}

	message_get_body_size(inbuf, dest, max_virtual_size);
}

int imap_msgcache_get_rfc822_partial(ImapMessageCache *cache, unsigned int uid,
				     uoff_t virtual_skip,
				     uoff_t max_virtual_size,
				     int get_header, MessageSize *size,
                                     IOBuffer **inbuf)
{
	CachedMessage *msg;
	uoff_t physical_skip;
	int size_got;

	msg = cache->open_msg;
	if (msg == NULL || msg->uid != uid)
		return FALSE;

	if (msg->hdr_size == NULL) {
		msg->hdr_size = p_new(msg->pool, MessageSize, 1);
                imap_msgcache_get_inbuf(cache, 0);
		message_get_header_size(cache->open_inbuf, msg->hdr_size);
	}

	physical_skip = get_header ? 0 : msg->hdr_size->physical_size;

	/* see if we can do this easily */
	size_got = FALSE;
	if (virtual_skip == 0) {
		if (msg->body_size == NULL) {
			/* FIXME: may underflow */
			msg->body_size = p_new(msg->pool, MessageSize, 1);
			msg->body_size->physical_size =
				cache->open_inbuf->size -
				msg->hdr_size->physical_size;
			msg->body_size->virtual_size =
				cache->open_virtual_size -
				msg->hdr_size->virtual_size;
		}

		if (max_virtual_size >= msg->body_size->virtual_size) {
			*size = *msg->body_size;
			size_got = TRUE;
		}
	}

	if (!size_got) {
		if (msg->partial_size == NULL)
			msg->partial_size = p_new(msg->pool, MessageSize, 1);

		imap_msgcache_get_inbuf(cache, msg->hdr_size->physical_size);
		get_partial_size(cache->open_inbuf, virtual_skip,
				 max_virtual_size, msg->partial_size, size);

		physical_skip += msg->partial_size->physical_size;
	}

	if (get_header)
		message_size_add(size, msg->hdr_size);

	/* seek to wanted position */
	imap_msgcache_get_inbuf(cache, physical_skip);
        *inbuf = cache->open_inbuf;
	return TRUE;
}

int imap_msgcache_get_data(ImapMessageCache *cache, unsigned int uid,
			   IOBuffer **inbuf)
{
	if (cache->open_msg == NULL || cache->open_msg->uid != uid)
		return FALSE;

	imap_msgcache_get_inbuf(cache, 0);
        *inbuf = cache->open_inbuf;
	return TRUE;
}
