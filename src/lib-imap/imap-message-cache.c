/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
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
	int open_fd;
	void *open_mmap_base;
	const char *open_msg_data;
	off_t open_start_pos;
	size_t open_mmap_size, open_size, open_virtual_size;
};

ImapMessageCache *imap_msgcache_alloc(void)
{
	ImapMessageCache *cache;

	cache = i_new(ImapMessageCache, 1);
	cache->open_fd = -1;
	return cache;
}

static void cached_message_free(CachedMessage *msg)
{
	pool_unref(msg->pool);
}

static void cache_close_msg(ImapMessageCache *cache)
{
	if (cache->open_mmap_base != NULL) {
		(void)munmap(cache->open_mmap_base, cache->open_mmap_size);
		cache->open_mmap_base = NULL;
		cache->open_msg_data = NULL;
	}

	if (cache->open_fd != -1) {
		(void)close(cache->open_fd);
		cache->open_fd = -1;
	}

	cache->open_msg = NULL;
	cache->open_size = 0;
	cache->open_start_pos = 0;
}

void imap_msgcache_clear(ImapMessageCache *cache)
{
	CachedMessage *next;

	cache_close_msg(cache);

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

static void parse_envelope_header(MessagePart *part,
				  const char *name, unsigned int name_len,
				  const char *value, unsigned int value_len,
				  void *user_data)
{
	CachedMessage *msg = user_data;

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
		value = imap_part_get_bodystructure(msg->pool, &msg->part,
						    cache->open_msg_data,
						    cache->open_size, FALSE);
		msg->cached_body = p_strdup(msg->pool, value);
	}

	if ((fields & IMAP_CACHE_BODYSTRUCTURE) &&
	    msg->cached_bodystructure == NULL && msg == cache->open_msg) {
		value = imap_part_get_bodystructure(msg->pool, &msg->part,
						    cache->open_msg_data,
						    cache->open_size, TRUE);
		msg->cached_bodystructure = p_strdup(msg->pool, value);
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

		msg->part = message_parse(msg->pool, cache->open_msg_data,
					  cache->open_size, func, msg);
	}

	if ((fields & IMAP_CACHE_ENVELOPE) && msg->cached_envelope == NULL) {
		if (msg->envelope == NULL && msg == cache->open_msg) {
			/* envelope isn't parsed yet, do it. header size
			   is calculated anyway so save it */
			if (msg->hdr_size == NULL) {
				msg->hdr_size = p_new(msg->pool,
						      MessageSize, 1);
			}
			message_parse_header(NULL, cache->open_msg_data,
					     cache->open_size, msg->hdr_size,
					     parse_envelope_header, msg);
		}

		if (msg->envelope != NULL) {
			value = imap_envelope_get_part_data(msg->envelope);
			msg->cached_envelope = p_strdup(msg->pool, value);
		}
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
			message_get_header_size(cache->open_msg_data,
						cache->open_size,
						msg->hdr_size);

			msg->body_size->lines = 0;
			msg->body_size->physical_size = cache->open_size -
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
			message_get_header_size(cache->open_msg_data,
						cache->open_size,
						msg->hdr_size);
		}
	}

	t_pop();
}

static int cache_mmap(ImapMessageCache *cache)
{
	if (cache->open_mmap_base == NULL) {
		cache->open_mmap_base =
			mmap_aligned(cache->open_fd, PROT_READ,
				     cache->open_start_pos, cache->open_size,
				     (void **) &cache->open_msg_data,
				     &cache->open_mmap_size);
		if (cache->open_mmap_base == MAP_FAILED) {
			i_error("mmap() failed for msg %u: %m",
				cache->open_msg->uid);
			return FALSE;
		}
	}
	return TRUE;
}

void imap_msgcache_message(ImapMessageCache *cache, unsigned int uid,
			   int fd, off_t offset, size_t size,
			   size_t virtual_size, size_t pv_headers_size,
			   size_t pv_body_size, ImapCacheField fields)
{
	CachedMessage **pos, *msg;

	i_assert(fd != -1);

	if (cache->open_msg == NULL || cache->open_msg->uid != uid) {
		cache_close_msg(cache);

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

		cache->open_msg = msg;
		cache->open_fd = fd;
		cache->open_size = size;
		cache->open_virtual_size = virtual_size;
		cache->open_start_pos = offset;

		if (!cache_mmap(cache)) {
			cache_close_msg(cache);
			return;
		}
	}

	msg = cache->open_msg;

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
			     const char **data, int *fd)
{
	CachedMessage *msg;

	if (data != NULL || fd != NULL) {
		if (cache->open_msg == NULL || cache->open_msg->uid != uid)
			return FALSE;

		msg = cache->open_msg;
		if (data != NULL)
			*data = cache->open_msg_data;
		if (fd != NULL) {
			*fd = cache->open_fd;
			if (*fd != -1 && lseek(*fd, cache->open_start_pos,
					       SEEK_SET) == (off_t)-1)
				*fd = -1;
		}
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
	} else {
		/* header isn't wanted, skip it */
		if (data != NULL)
			*data += msg->hdr_size->physical_size;
		if (fd != NULL) {
			if (lseek(*fd, (off_t) msg->hdr_size->physical_size,
				  SEEK_CUR) == (off_t)-1)
				return FALSE;
		}
	}

	return TRUE;
}

static void get_partial_size(const char *msg, size_t max_physical_size,
			     off_t virtual_skip, size_t max_virtual_size,
			     MessageSize *partial, MessageSize *dest)
{
	const char *msg_start, *msg_end, *cr;

	msg_end = msg + max_physical_size;

	/* see if we can use the existing partial */
	if (partial->virtual_size > (size_t) virtual_skip)
		memset(partial, 0, sizeof(MessageSize));

	/* first do the virtual skip - FIXME: <..\r><\n..> skipping! */
	if (virtual_skip > 0) {
		msg = msg_start = msg + partial->physical_size;

		cr = NULL;
		while (msg != msg_end &&
		       partial->virtual_size < (size_t) virtual_skip) {
			if (*msg == '\r')
				cr = msg;
			else if (*msg == '\n') {
				partial->lines++;

				if (cr != msg-1) {
					if (++partial->virtual_size ==
					    (size_t) virtual_skip) {
						/* FIXME: CR thingy */
					}
				}
			}

			msg++;
			partial->virtual_size++;
		}

		partial->physical_size += (int) (msg-msg_start);
                max_physical_size -= partial->physical_size;
	}

	if (max_virtual_size == 0) {
		/* read the rest of the message */
		message_get_body_size(msg, max_physical_size, dest);
		return;
	}

	/* now read until the message is either finished or we've read
	   max_virtual_size */
	msg_start = msg;
	memset(dest, 0, sizeof(MessageSize));

	cr = NULL;
	while (msg != msg_end && dest->virtual_size < (size_t) virtual_skip) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			dest->lines++;

			if (cr != msg-1)
				dest->virtual_size++;
		}

		msg++;
		dest->virtual_size++;
	}

	dest->physical_size = (int) (msg-msg_start);
}

int imap_msgcache_get_rfc822_partial(ImapMessageCache *cache, unsigned int uid,
				     off_t virtual_skip,
				     size_t max_virtual_size,
				     int get_header, MessageSize *size,
				     const char **data, int *fd)
{
	CachedMessage *msg;
	const char *body;
	size_t body_size;
	off_t physical_skip;
	int size_got;

	msg = cache->open_msg;
	if (msg == NULL || msg->uid != uid)
		return FALSE;

	if (msg->hdr_size == NULL) {
		msg->hdr_size = p_new(msg->pool, MessageSize, 1);
		message_get_header_size(cache->open_msg_data,
					cache->open_size,
					msg->hdr_size);
	}

	body = cache->open_msg_data + msg->hdr_size->physical_size;
	body_size = cache->open_size - msg->hdr_size->physical_size;

	if (fd != NULL) *fd = cache->open_fd;
	physical_skip = get_header ? 0 : msg->hdr_size->physical_size;

	/* see if we can do this easily */
	size_got = FALSE;
	if (virtual_skip == 0) {
		if (max_virtual_size == 0 && msg->body_size == NULL) {
			msg->body_size = p_new(msg->pool, MessageSize, 1);
			msg->body_size->physical_size = cache->open_size -
				msg->hdr_size->physical_size;
			msg->body_size->virtual_size =
				cache->open_virtual_size -
				msg->hdr_size->virtual_size;
		}

		if (msg->body_size != NULL &&
		    (max_virtual_size == 0 ||
		     max_virtual_size >= msg->body_size->virtual_size)) {
			*size = *msg->body_size;
			size_got = TRUE;
		}
	}

	if (!size_got) {
		if (msg->partial_size == NULL)
			msg->partial_size = p_new(msg->pool, MessageSize, 1);

		get_partial_size(body, body_size, virtual_skip,
				 max_virtual_size, msg->partial_size, size);

		physical_skip += msg->partial_size->physical_size;
	}

	if (get_header)
		message_size_add(size, msg->hdr_size);

	/* seek to wanted position */
	*data = cache->open_msg_data + physical_skip;
	if (fd != NULL && *fd != -1) {
		if (lseek(*fd, cache->open_start_pos + physical_skip,
			  SEEK_SET) == (off_t)-1)
			*fd = -1;
	}
	return TRUE;
}

int imap_msgcache_get_data(ImapMessageCache *cache, unsigned int uid,
			   const char **data, int *fd, size_t *size)
{
	if (cache->open_msg == NULL || cache->open_msg->uid != uid)
		return FALSE;

	*data = cache->open_msg_data;
	if (fd != NULL) {
		*fd = cache->open_fd;
		if (lseek(*fd, cache->open_start_pos, SEEK_SET) == (off_t)-1)
			return FALSE;
	}

	if (size != NULL)
		*size = cache->open_size;

	return TRUE;
}
