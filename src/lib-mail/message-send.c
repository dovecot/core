/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "message-parser.h"
#include "message-send.h"
#include "message-size.h"

int message_skip_virtual(struct istream *input, uoff_t virtual_skip,
			 struct message_size *msg_size,
			 bool cr_skipped, bool *last_cr)
{
	const unsigned char *msg;
	size_t i, size, startpos;
	int ret;

	if (virtual_skip == 0) {
		*last_cr = cr_skipped;
		return 0;
	}

	*last_cr = FALSE;
	startpos = 0;
	while ((ret = i_stream_read_data(input, &msg, &size, startpos)) > 0) {
		for (i = startpos; i < size && virtual_skip > 0; i++) {
			virtual_skip--;

			if (msg[i] == '\r') {
				/* CR */
				if (virtual_skip == 0)
					*last_cr = TRUE;
			} else if (msg[i] == '\n') {
				/* LF */
				if ((i == 0 && !cr_skipped) ||
				    (i > 0 && msg[i-1] != '\r')) {
					/* missing CR */
					if (msg_size != NULL)
						msg_size->virtual_size++;

					if (virtual_skip == 0) {
						/* CR/LF boundary */
						*last_cr = TRUE;
						break;
					}

					virtual_skip--;
				}

				/* increase after making sure we didn't break
				   at virtual \r */
				if (msg_size != NULL)
					msg_size->lines++;
			}
		}

		i_stream_skip(input, i);
		if (msg_size != NULL) {
			msg_size->physical_size += i;
			msg_size->virtual_size += i;
		}

		if (i < size)
			return 0;

		cr_skipped = msg[i-1] == '\r';
	}
	i_assert(ret == -1);
	return input->stream_errno == 0 ? 0 : -1;
}
