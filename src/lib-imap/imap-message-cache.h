#ifndef __IMAP_MESSAGE_CACHE_H
#define __IMAP_MESSAGE_CACHE_H

// FIXME: update comments

/* IMAP message cache. Caches are mailbox-specific and must be cleared
   if UID validity changes.

   Caching is mostly done to avoid parsing the same message multiple times
   when client fetches the message in parts.
*/

#include "message-parser.h"

typedef enum {
	IMAP_CACHE_BODY			= 0x01,
	IMAP_CACHE_BODYSTRUCTURE	= 0x02,
	IMAP_CACHE_ENVELOPE		= 0x04,

	IMAP_CACHE_MESSAGE_OPEN		= 0x08,
	IMAP_CACHE_MESSAGE_PART		= 0x10,
	IMAP_CACHE_MESSAGE_HDR_SIZE	= 0x20,
	IMAP_CACHE_MESSAGE_BODY_SIZE	= 0x40
} ImapCacheField;

typedef struct _ImapMessageCache ImapMessageCache;

ImapMessageCache *imap_msgcache_alloc(void);
void imap_msgcache_clear(ImapMessageCache *cache);
void imap_msgcache_free(ImapMessageCache *cache);

/* Returns TRUE if all given fields are fully cached, or at least the
   message is open (ie. you don't need imap_msgcache_message()). */
int imap_msgcache_is_cached(ImapMessageCache *cache, unsigned int uid,
			    ImapCacheField fields);

/* Parse and cache the message. If pv_headers_size and pv_body_size is
   non-zero, they're set to saved to message's both physical and virtual
   sizes (ie. doesn't need to be calculated). */
void imap_msgcache_message(ImapMessageCache *cache, unsigned int uid,
			   ImapCacheField fields, size_t virtual_size,
			   size_t pv_headers_size, size_t pv_body_size,
			   IOBuffer *inbuf,
			   IOBuffer *(*inbuf_rewind)(IOBuffer *inbuf,
						     void *user_data),
			   void *user_data);

/* Close the IOBuffer for cached message. */
void imap_msgcache_close(ImapMessageCache *cache);

/* Store a value for field in cache */
void imap_msgcache_set(ImapMessageCache *cache, unsigned int uid,
		       ImapCacheField field, const char *value);

/* Returns the field from cache, or NULL if it's not cached. */
const char *imap_msgcache_get(ImapMessageCache *cache, unsigned int uid,
			      ImapCacheField field);

/* Returns the root MessagePart for message, or NULL if it's not cached. */
MessagePart *imap_msgcache_get_parts(ImapMessageCache *cache, unsigned int uid);

/* Returns FALSE if message isn't in cache. If data is not NULL, it's set to
   point to beginning of message data. If fd is not NULL, it's set to contain
   the message file descriptor seeked to same position as *data. If hdr_size
   is NULL, *data contains only the message body. */
int imap_msgcache_get_rfc822(ImapMessageCache *cache, unsigned int uid,
			     MessageSize *hdr_size, MessageSize *body_size,
                             IOBuffer **inbuf);

/* Returns FALSE if message isn't in cache. *inbuf is set to point to the first
   non-skipped character. size is set to specify the full size for message. */
int imap_msgcache_get_rfc822_partial(ImapMessageCache *cache, unsigned int uid,
				     off_t virtual_skip, off_t max_virtual_size,
				     int get_header, MessageSize *size,
				     IOBuffer **inbuf);

/* Like imap_msgcache_get_rfc822() without calculating virtual sizes. */
int imap_msgcache_get_data(ImapMessageCache *cache, unsigned int uid,
                           IOBuffer **inbuf);

#endif
