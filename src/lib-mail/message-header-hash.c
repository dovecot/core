/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "message-header-hash.h"

void message_header_hash_more(struct md5_context *md5_ctx,
			      unsigned int version,
			      const unsigned char *data, size_t size)
{
	size_t i, start;

	i_assert(version == 1 || version == 2);

	if (version == 1) {
		md5_update(md5_ctx, data, size);
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

	   (Keep this code in sync with pop3-migration plugin.)
	   */
	for (i = start = 0; i < size; i++) {
		if ((data[i] < 0x20 || data[i] >= 0x7f || data[i] == '?') &&
		    (data[i] != '\t' && data[i] != '\n')) {
			/* remove repeated '?' */
			if (start < i || i == 0) {
				md5_update(md5_ctx, data + start, i-start);
				md5_update(md5_ctx, "?", 1);
			}
			start = i+1;
		}
	}
	md5_update(md5_ctx, data + start, i-start);
}
