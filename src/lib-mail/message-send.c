/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "message-parser.h"
#include "message-send.h"
#include "message-size.h"

off_t message_send(struct ostream *output, struct istream *input,
		   const struct message_size *msg_size,
		   uoff_t virtual_skip, uoff_t max_virtual_size, int *last_cr)
{
	const unsigned char *msg;
	uoff_t old_limit, limit;
	size_t i, size;
	off_t ret;
	int cr_skipped, add_cr;

	if (last_cr != NULL)
		*last_cr = -1;

	if (msg_size->physical_size == 0 ||
	    virtual_skip >= msg_size->virtual_size)
		return 0;

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

	message_skip_virtual(input, virtual_skip, NULL, 0, &cr_skipped);

	/* go through the message data and insert CRs where needed.  */
	ret = 0;
	while (max_virtual_size > 0 &&
	       i_stream_read_data(input, &msg, &size, 0) > 0) {
		add_cr = FALSE;
		for (i = 0; i < size && max_virtual_size > 0; i++) {
			max_virtual_size--;

			if (msg[i] == '\n') {
				if ((i == 0 && !cr_skipped) ||
				    (i > 0 && msg[i-1] != '\r')) {
					/* missing CR */
					add_cr = TRUE;
					break;
				}
			}
		}

		ret += i;
		if (o_stream_send(output, msg, i) < 0)
			return -1;

		if (add_cr) {
			ret++;
			if (o_stream_send(output, "\r", 1) < 0)
				return -1;
			cr_skipped = TRUE;
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
