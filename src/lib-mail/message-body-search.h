#ifndef __MESSAGE_BODY_SEARCH_H
#define __MESSAGE_BODY_SEARCH_H

struct message_part;

enum message_body_search_error {
	/* Don't know the given charset. */
	MESSAGE_BODY_SEARCH_ERROR_UNKNOWN_CHARSET,
	/* Key contains invalid characters in given charset. */
	MESSAGE_BODY_SEARCH_ERROR_INVALID_KEY,
	/* Message_part doesn't match the reality in input stream. */
	MESSAGE_BODY_SEARCH_ERROR_MESSAGE_PART_BROKEN
};

/* Returns 1 if key is found from input buffer, 0 if not and -1 if error.
   If charset is NULL, the key isn't assumed to be in any specific charset but
   is compared to message data without any translation. */
int message_body_search(const char *key, const char *charset,
			struct istream *input,
			const struct message_part *part, bool search_header,
                        enum message_body_search_error *error_r);

#endif
