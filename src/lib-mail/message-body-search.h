#ifndef __MESSAGE_BODY_SEARCH_H
#define __MESSAGE_BODY_SEARCH_H

/* Returns 1 if key is found from input buffer, 0 if not and -1 if error.
   There's two possible errors: either the charset is unknown or the key
   is invalid. If charset is NULL, the key isn't assumed to be in any
   specific charset but is compared to message data without any translation. */
int message_body_search(const char *key, const char *charset,
			int *unknown_charset, IStream *input,
			MessagePart *part, int search_header);

#endif
