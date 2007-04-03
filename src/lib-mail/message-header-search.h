#ifndef __MESSAGE_HEADER_SEARCH_H
#define __MESSAGE_HEADER_SEARCH_H

struct message_header_search_context;

/* Returns 1 if ok, 0 if unknown charset, -1 if key contains invalid characters
   in given charset. */
int message_header_search_init(pool_t pool, const char *key,
			       const char *charset,
			       struct message_header_search_context **ctx_r);
/* Deinitialize search context. Not needed if you just destroy the pool. */
void message_header_search_deinit(struct message_header_search_context **ctx);

/* Returns TRUE if key is found from header. This function may be called
   multiple times with partial header blocks, but the blocks must contain only
   full lines so RFC2047 parsing can be done. */
bool message_header_search(struct message_header_search_context *ctx,
			   const unsigned char *header_block, size_t size);

/* Next call to message_header_search() will begin a new header. */
void message_header_search_reset(struct message_header_search_context *ctx);

#endif
