/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "message-send.h"
#include "message-size.h"

int message_send(IOBuffer *outbuf, IOBuffer *inbuf, MessageSize *msg_size,
		 uoff_t virtual_skip, uoff_t max_virtual_size)
{
	unsigned char *msg;
	unsigned int i, size;
	int cr_skipped, add_cr;

	if (msg_size->physical_size == 0 ||
	    virtual_skip >= msg_size->virtual_size)
		return TRUE;

	if (max_virtual_size > msg_size->virtual_size - virtual_skip)
		max_virtual_size = msg_size->virtual_size - virtual_skip;

	if (msg_size->physical_size == msg_size->virtual_size) {
		/* no need to kludge with CRs, we can use sendfile() */
		io_buffer_skip(inbuf, virtual_skip);
		return io_buffer_send_iobuffer(outbuf, inbuf,
					       max_virtual_size) > 0;
	}

	message_skip_virtual(inbuf, virtual_skip, NULL, &cr_skipped);

	/* go through the message data and insert CRs where needed.  */
	while (io_buffer_read_data(inbuf, &msg, &size, 0) >= 0) {
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

		if (io_buffer_send(outbuf, msg, i) <= 0)
			return FALSE;

		if (add_cr) {
			if (io_buffer_send(outbuf, "\r", 1) <= 0)
				return FALSE;
		}

		/* see if we've reached the limit */
		if (max_virtual_size == 0)
			break;

		cr_skipped = TRUE;
		io_buffer_skip(inbuf, i);
	}

	return TRUE;
}
