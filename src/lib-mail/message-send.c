/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "message-send.h"
#include "message-size.h"

int message_send(OStream *output, IStream *input, MessageSize *msg_size,
		 uoff_t virtual_skip, uoff_t max_virtual_size)
{
	const unsigned char *msg;
	uoff_t old_limit, limit;
	size_t i, size;
	int cr_skipped, add_cr, ret;

	if (msg_size->physical_size == 0 ||
	    virtual_skip >= msg_size->virtual_size)
		return TRUE;

	if (max_virtual_size > msg_size->virtual_size - virtual_skip)
		max_virtual_size = msg_size->virtual_size - virtual_skip;

	if (msg_size->physical_size == msg_size->virtual_size) {
		/* no need to kludge with CRs, we can use sendfile() */
		i_stream_skip(input, virtual_skip);

		old_limit = input->v_limit;
		limit = input->v_offset + max_virtual_size;
		i_stream_set_read_limit(input, I_MIN(limit, old_limit));
		ret = o_stream_send_istream(output, input) > 0;
		i_stream_set_read_limit(input, old_limit);

		return ret;
	}

	message_skip_virtual(input, virtual_skip, NULL, &cr_skipped);

	/* go through the message data and insert CRs where needed.  */
	while (i_stream_read_data(input, &msg, &size, 0) > 0) {
		add_cr = FALSE;
		for (i = 0; i < size; i++) {
			if (msg[i] == '\n') {
				if ((i == 0 && !cr_skipped) ||
				    (i > 0 && msg[i-1] != '\r')) {
					/* missing CR */
					if (max_virtual_size > 0)
						max_virtual_size--;
					add_cr = TRUE;
					break;
				}

			}

			if (max_virtual_size > 0) {
				if (--max_virtual_size == 0) {
					i++;
					break;
				}
			}
		}

		if (o_stream_send(output, msg, i) < 0)
			return FALSE;

		if (add_cr) {
			if (o_stream_send(output, "\r", 1) < 0)
				return FALSE;
			cr_skipped = TRUE;
		} else {
			cr_skipped = i > 0 && msg[i-1] == '\r';
		}

		/* see if we've reached the limit */
		if (max_virtual_size == 0)
			break;

		i_stream_skip(input, i);
	}

	return TRUE;
}
