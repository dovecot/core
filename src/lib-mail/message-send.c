/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "message-parser.h"
#include "message-send.h"
#include "message-size.h"

off_t message_send(struct ostream *output, struct istream *input,
		   const struct message_size *msg_size,
		   int cr_skipped, uoff_t max_virtual_size, int *last_cr,
		   int fix_nuls)
{
	const unsigned char *msg;
	size_t i, size;
	off_t ret;
	unsigned char add;

	if (last_cr != NULL)
		*last_cr = -1;

	if (msg_size->physical_size == 0)
		return 0;

	if (msg_size->physical_size == msg_size->virtual_size && !fix_nuls) {
		/* no need to kludge with CRs, we can use sendfile() */
		input = i_stream_create_limit(default_pool, input,
					      input->v_offset,
					      max_virtual_size);
		ret = o_stream_send_istream(output, input);
		i_stream_unref(input);
		return ret;
	}

	/* go through the message data and insert CRs where needed.  */
	ret = 0;
	while (max_virtual_size > 0 &&
	       i_stream_read_data(input, &msg, &size, 0) > 0) {
		add = '\0';
		for (i = 0; i < size && max_virtual_size > 0; i++) {
			max_virtual_size--;

			if (msg[i] == '\n') {
				if ((i > 0 && msg[i-1] != '\r') ||
				    (i == 0 && !cr_skipped)) {
					/* missing CR */
					add = '\r';
					break;
				}
			} else if (msg[i] == '\0') {
				add = 128;
				break;
			}
		}

		ret += i;
		if (o_stream_send(output, msg, i) < 0)
			return -1;

		if (add != '\0') {
			ret++;
			if (o_stream_send(output, &add, 1) < 0)
				return -1;
			cr_skipped = add == '\r';
			if (add == 128) i++;
		} else {
			cr_skipped = i > 0 && msg[i-1] == '\r';
		}

		i_stream_skip(input, i);
	}

	if (last_cr != NULL)
		*last_cr = cr_skipped;
	return ret;
}

void message_skip_virtual(struct istream *input, uoff_t virtual_skip,
			  struct message_size *msg_size,
			  int cr_skipped, int *last_cr)
{
	const unsigned char *msg;
	size_t i, size, startpos;

	if (virtual_skip == 0) {
		*last_cr = cr_skipped;
		return;
	}

	*last_cr = FALSE;
	startpos = 0;
	while (i_stream_read_data(input, &msg, &size, startpos) > 0) {
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
		cr_skipped = FALSE;
	}
}
