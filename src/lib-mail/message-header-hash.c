/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"
#include "message-header-hash.h"

void message_header_hash_more(const struct hash_method *method, void *context,
			      unsigned int version,
			      const unsigned char *data, size_t size)
{
	size_t i, start;

	i_assert(version == 1 || version == 2);

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
	*/
	for (i = start = 0; i < size; i++) {
		if ((data[i] < 0x20 || data[i] >= 0x7f || data[i] == '?') &&
		    (data[i] != '\t' && data[i] != '\n')) {
			/* remove repeated '?' */
			if (start < i || i == 0) {
				method->loop(context, data + start, i-start);
				method->loop(context, "?", 1);
			}
			start = i+1;
		}
	}
	method->loop(context, data + start, i-start);
}
