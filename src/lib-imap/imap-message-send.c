/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "imap-message-send.h"

int imap_message_send(IOBuffer *outbuf, const char *msg, int msg_fd,
		      MessageSize *size, off_t virtual_skip,
		      size_t max_virtual_size)
{
	const char *msg_start, *msg_end, *cr;
	unsigned int len;

	if (size->physical_size == 0)
		return TRUE;

	if (size->physical_size == size->virtual_size) {
		/* no need to kludge with CRs, we can use sendfile() */
		size_t send_size;

		send_size = size->physical_size - virtual_skip;
		if (msg_fd == -1) {
			return io_buffer_send(outbuf, msg + virtual_skip,
					      send_size) > 0;
		} else {
			return io_buffer_send_file(outbuf, msg_fd, virtual_skip,
						   msg + virtual_skip,
						   send_size) > 0;
		}
	}

	msg_start = msg;
	msg_end = msg + size->physical_size;

	/* first do the virtual skip - FIXME: <..\r><\n..> skipping! */
	if (virtual_skip > 0) {
		cr = NULL;
		while (msg != msg_end && virtual_skip > 0) {
			if (*msg == '\r')
				cr = msg;
			else if (*msg == '\n') {
				if (cr != msg-1) {
					if (--virtual_skip == 0) {
						/* FIXME: cr thingy */
					}
				}
			}

			msg++;
			virtual_skip--;
		}

		msg_start = msg;
	}

	/* go through the message data and insert CRs where needed.  */
	cr = NULL;
	while (msg != msg_end) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n' && cr != msg-1) {
			len = (unsigned int) (msg - msg_start);
			if (max_virtual_size != 0 && max_virtual_size <= len) {
				/* reached max. size limit */
				return io_buffer_send(outbuf, msg_start,
						      max_virtual_size) > 0;
			}

			if (io_buffer_send(outbuf, msg_start, len) <= 0)
				return FALSE;

			if (io_buffer_send(outbuf, "\r", 1) <= 0)
				return FALSE;

			/* update max. size */
			if (max_virtual_size == len+1)
				return TRUE;
			max_virtual_size -= len+1;

			msg_start = msg;
		}
		msg++;
	}

	/* send the rest */
	len = (unsigned int) (msg - msg_start);
	if (max_virtual_size != 0 && max_virtual_size < len)
		len = max_virtual_size;
	return io_buffer_send(outbuf, msg_start, len) > 0;
}
