#ifndef __MESSAGE_BODY_SEARCH_H
#define __MESSAGE_BODY_SEARCH_H

struct message_part;
struct message_body_search_context;

/* Returns 1 if ok, 0 if unknown charset, -1 if key contains invalid characters
   in given charset. If charset is NULL, the key isn't assumed to be in any
   specific charset but is compared to message data without any translation. */
int message_body_search_init(pool_t pool, const char *key, const char *charset,
			     bool search_header,
			     struct message_body_search_context **ctx_r);
/* Deinitialize search context. Not needed if you just destroy the pool. */
void message_body_search_deinit(struct message_body_search_context **ctx);

/* Returns 1 if key is found from input buffer, 0 if not and -1 if message_part
   is invalid. */
int message_body_search(struct message_body_search_context *ctx,
			struct istream *input, const struct message_part *part);

#endif
