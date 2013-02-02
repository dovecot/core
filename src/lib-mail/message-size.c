/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "message-parser.h"
#include "message-size.h"

int message_get_header_size(struct istream *input, struct message_size *hdr,
			    bool *has_nuls_r)
{
	const unsigned char *msg;
	size_t i, size, startpos, missing_cr_count;
	int ret;

	memset(hdr, 0, sizeof(struct message_size));
	*has_nuls_r = FALSE;

	missing_cr_count = 0; startpos = 0;
	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
		for (i = startpos; i < size; i++) {
			if (msg[i] != '\n') {
				if (msg[i] == '\0')
					*has_nuls_r = TRUE;
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
	ret = input->stream_errno != 0 ? -1 : 0;
	i_stream_skip(input, startpos);
	hdr->physical_size += startpos;

	hdr->virtual_size = hdr->physical_size + missing_cr_count;
	i_assert(hdr->virtual_size >= hdr->physical_size);
	return ret;
}

int message_get_body_size(struct istream *input, struct message_size *body,
			  bool *has_nuls_r)
{
	const unsigned char *msg;
	size_t i, size, missing_cr_count;
	int ret;

	memset(body, 0, sizeof(struct message_size));
	*has_nuls_r = FALSE;

	missing_cr_count = 0;
	if ((ret = i_stream_read_data(input, &msg, &size, 0)) <= 0)
		return ret < 0 && input->stream_errno != 0 ? -1 : 0;

	if (msg[0] == '\n')
		missing_cr_count++;

	do {
		for (i = 1; i < size; i++) {
			if (msg[i] > '\n')
				continue;

			if (msg[i] == '\n') {
				if (msg[i-1] != '\r') {
					/* missing CR */
					missing_cr_count++;
				}

				/* increase after making sure we didn't break
				   at virtual \r */
				body->lines++;
			} else if (msg[i] == '\0') {
				*has_nuls_r = TRUE;
			}
		}

		/* leave the last character, it may be \r */
		i_stream_skip(input, i - 1);
		body->physical_size += i - 1;
	} while (i_stream_read_data(input, &msg, &size, 1) > 0);

	ret = input->stream_errno != 0 ? -1 : 0;

	i_stream_skip(input, 1);
	body->physical_size++;

	body->virtual_size = body->physical_size + missing_cr_count;
	i_assert(body->virtual_size >= body->physical_size);
	return ret;
}

void message_size_add(struct message_size *dest,
		      const struct message_size *src)
{
	dest->virtual_size += src->virtual_size;
	dest->physical_size += src->physical_size;
	dest->lines += src->lines;
}

int message_skip_virtual(struct istream *input, uoff_t virtual_skip,
			 bool *last_cr_r)
{
	const unsigned char *msg;
	size_t i, size;
	bool cr_skipped = FALSE;
	int ret;

	*last_cr_r = FALSE;
	if (virtual_skip == 0)
		return 0;

	while ((ret = i_stream_read_data(input, &msg, &size, 0)) > 0) {
		for (i = 0; i < size && virtual_skip > 0; i++) {
			virtual_skip--;

			if (msg[i] == '\r') {
				/* CR */
				if (virtual_skip == 0)
					*last_cr_r = TRUE;
			} else if (msg[i] == '\n') {
				/* LF */
				if ((i == 0 && !cr_skipped) ||
				    (i > 0 && msg[i-1] != '\r')) {
					if (virtual_skip == 0) {
						/* CR/LF boundary */
						*last_cr_r = TRUE;
						break;
					}

					virtual_skip--;
				}
			}
		}
		i_stream_skip(input, i);

		if (i < size)
			return 0;

		cr_skipped = msg[i-1] == '\r';
	}
	i_assert(ret == -1);
	return input->stream_errno == 0 ? 0 : -1;
}
