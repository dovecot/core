/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "message-parser.h"
#include "message-size.h"

void message_get_header_size(IStream *input, MessageSize *hdr)
{
	const unsigned char *msg;
	size_t i, size, startpos, missing_cr_count;

	memset(hdr, 0, sizeof(MessageSize));

	missing_cr_count = 0; startpos = 0;
	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] != '\n')
				continue;

			hdr->lines++;
			if (i == 0 || msg[i-1] != '\r') {
				/* missing CR */
				missing_cr_count++;
			}

			if (i == 0 || (i == 1 && msg[i-1] == '\r')) {
				/* no headers at all */
				break;
			}

			if ((i > 0 && msg[i-1] == '\n') ||
			    (i > 1 && msg[i-2] == '\n' && msg[i-1] == '\r')) {
				/* \n\n or \n\r\n - end of headers */
				break;
			}
		}

		if (i < size) {
			/* end of header */
			startpos = i+1;
			break;
		}

		/* leave the last two characters, they may be \r\n */
		startpos = size == 1 ? 1 : 2;
		i_stream_skip(input, i - startpos);

		hdr->physical_size += i - startpos;
	}
	i_stream_skip(input, startpos);
	hdr->physical_size += startpos;

	hdr->virtual_size = hdr->physical_size + missing_cr_count;
	i_assert(hdr->virtual_size >= hdr->physical_size);
}

void message_get_body_size(IStream *input, MessageSize *body,
			   uoff_t max_virtual_size)
{
	const unsigned char *msg;
	size_t i, size, startpos, missing_cr_count;

	memset(body, 0, sizeof(MessageSize));

	missing_cr_count = 0; startpos = 0;
	while (max_virtual_size != 0 &&
	       i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size && max_virtual_size != 0; i++) {
			if (max_virtual_size > 0)
				max_virtual_size--;

			if (msg[i] != '\n')
				continue;

			if (i == 0 || msg[i-1] != '\r') {
				/* missing CR */
				missing_cr_count++;

				if (max_virtual_size > 0) {
					if (max_virtual_size == 0)
						break;

					max_virtual_size--;
				}
			}

			/* increase after making sure we didn't break
			   at virtual \r */
			body->lines++;
		}

		/* leave the last character, it may be \r */
		i_stream_skip(input, i - 1);
		startpos = 1;

		body->physical_size += i - 1;
	}
	i_stream_skip(input, startpos);
	body->physical_size += startpos;

	body->virtual_size = body->physical_size + missing_cr_count;
	i_assert(body->virtual_size >= body->physical_size);
}

void message_skip_virtual(IStream *input, uoff_t virtual_skip,
			  MessageSize *msg_size, int *cr_skipped)
{
	const unsigned char *msg;
	size_t i, size, startpos;

	*cr_skipped = FALSE;
	if (virtual_skip == 0)
		return;

	startpos = 0;
	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size && virtual_skip > 0; i++) {
			virtual_skip--;

			if (msg[i] == '\r') {
				/* CR */
				if (virtual_skip == 0)
					*cr_skipped = TRUE;
			} else if (msg[i] == '\n') {
				/* LF */
				if (i == 0 || msg[i-1] != '\r') {
					/* missing CR */
					if (msg_size != NULL)
						msg_size->virtual_size++;

					if (virtual_skip == 0) {
						/* CR/LF boundary */
						*cr_skipped = TRUE;
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

		if (msg_size != NULL) {
			msg_size->physical_size += i;
			msg_size->virtual_size += i;
		}

		if (i < size) {
			i_stream_skip(input, i);
			break;
		}

		/* leave the last character, it may be \r */
		i_stream_skip(input, i - 1);
		startpos = 1;
	}
}

void message_size_add(MessageSize *dest, const MessageSize *src)
{
	dest->virtual_size += src->virtual_size;
	dest->physical_size += src->physical_size;
	dest->lines += src->lines;
}
