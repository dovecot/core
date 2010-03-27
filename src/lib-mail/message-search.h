#ifndef MESSAGE_SEARCH_H
#define MESSAGE_SEARCH_H

struct message_block;
struct message_part;
struct message_search_context;

enum message_search_flags {
	/* Skip the main header and all the MIME headers. */
	MESSAGE_SEARCH_FLAG_SKIP_HEADERS	= 0x01
};

/* Returns 1 if ok, 0 if unknown charset, -1 if key contains invalid characters
   in given charset. */
int message_search_init(const char *key, const char *charset,
			enum message_search_flags flags,
			struct message_search_context **ctx_r);
void message_search_deinit(struct message_search_context **ctx);

/* Returns TRUE if key is found from input buffer, FALSE if not. */
bool message_search_more(struct message_search_context *ctx,
			 struct message_block *raw_block);
/* The data has already passed through decoder. */
bool message_search_more_decoded(struct message_search_context *ctx,
				 struct message_block *block);
void message_search_reset(struct message_search_context *ctx);
/* Search a full message. Returns 1 if match was found, 0 if not,
   -1 if error (if stream_error == 0, the parts contained broken data) */
int message_search_msg(struct message_search_context *ctx,
		       struct istream *input, struct message_part *parts);

#endif
