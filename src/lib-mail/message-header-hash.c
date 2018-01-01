/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"
#include "message-header-hash.h"

void message_header_hash_more(struct message_header_hash_context *ctx,
			      const struct hash_method *method, void *context,
			      unsigned int version,
			      const unsigned char *data, size_t size)
{
	size_t i, start;

	i_assert(version >= 1 && version <= MESSAGE_HEADER_HASH_MAX_VERSION);

	if (version == 1) {
		method->loop(context, data, size);
		return;
	}
	/* - Dovecot IMAP replaces NULs with 0x80 character.
	   - Dovecot POP3 with outlook-no-nuls workaround replaces NULs
	   with 0x80 character.
	   - Zimbra replaces 8bit chars with '?' in header fetches,
	   but not body fetches.
	   - Yahoo replaces 8bit chars with '?' in partial header
	   fetches, but not POP3 TOP. UTF-8 character sequence writes only a
	   single '?'

	   So we'll just replace all control and 8bit chars with '?' and
	   remove any repeated '?', which hopefully will satisfy everybody.

	   Also:
	   - Zimbra removes trailing spaces and tabs from IMAP BODY[HEADER],
	   but not IMAP BODY[] or POP3 TOP. Just strip away all spaces with
	   version 3 and tabs also with version 4.
	*/
	for (i = start = 0; i < size; i++) {
		bool cur_is_questionmark = FALSE;

		switch (data[i]) {
		case ' ':
			if (version >= 3) {
				/* strip away spaces */
				method->loop(context, data + start, i-start);
				start = i+1;
			}
			break;
		case '\t':
			if (version >= 4) {
				/* strip away tabs */
				method->loop(context, data + start, i-start);
				start = i+1;
			}
			break;
		case '\n':
			break;
		default:
			if (data[i] < 0x20 || data[i] >= 0x7f || data[i] == '?') {
				/* remove repeated '?' */
				if (start < i || !ctx->prev_was_questionmark) {
					method->loop(context, data + start, i-start);
					method->loop(context, "?", 1);
				}
				start = i+1;
				cur_is_questionmark = TRUE;
			}
			break;
		}
		ctx->prev_was_questionmark = cur_is_questionmark;
	}
	method->loop(context, data + start, i-start);
}
