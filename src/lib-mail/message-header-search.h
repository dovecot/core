#ifndef __MESSAGE_HEADER_SEARCH_H
#define __MESSAGE_HEADER_SEARCH_H

typedef struct _HeaderSearchContext HeaderSearchContext;

/* Initialize new search. Returns NULL if charset is unknown or key is not
   valid in specified charset. */
HeaderSearchContext *
message_header_search_init(Pool pool, const char *key, const char *charset,
			   int *unknown_charset);

/* Free search context. Not needed if you just destroy the pool. */
void message_header_search_free(HeaderSearchContext *ctx);

/* Returns TRUE if key is found from header. This function may be called
   multiple times with partial header blocks, but the blocks must contain only
   full lines so RFC2047 parsing can be done. *header_size is updated to
   contain the number of bytes we didn't access (either because we got a match,
   or because end of headers). */
int message_header_search(const unsigned char *header_block,
			  size_t *header_size, HeaderSearchContext *ctx);

/* Next call to message_header_search() will begin a new header. */
void message_header_search_reset(HeaderSearchContext *ctx);

#endif
