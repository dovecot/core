/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "message-parser.h"
#include "message-size.h"

void message_get_header_size(struct istream *input, struct message_size *hdr,
			     int *has_nuls)
{
	const unsigned char *msg;
	size_t i, size, startpos, missing_cr_count;

	memset(hdr, 0, sizeof(struct message_size));
	if (has_nuls != NULL)
		*has_nuls = FALSE;

	missing_cr_count = 0; startpos = 0;
	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] != '\n') {
				if (msg[i] == '\0' && has_nuls != NULL)
					*has_nuls = TRUE;
				continue;
			}

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

void message_get_body_size(struct istream *input, struct message_size *body,
			   uoff_t max_virtual_size, int *last_cr, int *has_nuls)
{
	const unsigned char *msg;
	size_t i, size, startpos, missing_cr_count;
	int cr;

	memset(body, 0, sizeof(struct message_size));
	if (has_nuls != NULL)
		*has_nuls = FALSE;

	cr = 0;
	missing_cr_count = 0; startpos = 0;
	while (max_virtual_size != 0 &&
	       i_stream_read_data(input, &msg, &size, startpos) > 0) {
		cr = 0;
		for (i = startpos; i < size && max_virtual_size > 0; i++) {
			max_virtual_size--;

			if (msg[i] == '\0') {
				if (has_nuls != NULL)
					*has_nuls = TRUE;
			} else if (msg[i] == '\n') {
				if (i == 0 || msg[i-1] != '\r') {
					/* missing CR */
					missing_cr_count++;

					if (max_virtual_size == 0) {
						cr = 2;
						break;
					}

					max_virtual_size--;
				}

				/* increase after making sure we didn't break
				   at virtual \r */
				body->lines++;
			}
		}

		if (cr == 0 && i > 0 && msg[i-1] == '\r')
			cr = 1;

		/* leave the last character, it may be \r */
		i_stream_skip(input, i - 1);
		startpos = 1;

		body->physical_size += i - 1;
	}
	i_stream_skip(input, startpos);
	body->physical_size += startpos;

	body->virtual_size = body->physical_size + missing_cr_count;
	i_assert(body->virtual_size >= body->physical_size);

	if (last_cr != NULL)
		*last_cr = cr;
}

void message_size_add(struct message_size *dest,
		      const struct message_size *src)
{
	dest->virtual_size += src->virtual_size;
	dest->physical_size += src->physical_size;
	dest->lines += src->lines;
}
