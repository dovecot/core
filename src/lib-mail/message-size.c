/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "message-parser.h"
#include "message-size.h"

void message_get_header_size(const char *msg, size_t size, MessageSize *hdr)
{
	const char *msg_start, *msg_end, *cr, *last_lf;
	int missing_cr_count;

	hdr->lines = 0;

	msg_start = msg;
	msg_end = msg + size;

	/* get header size */

	cr = last_lf = NULL; missing_cr_count = 0;
	while (msg != msg_end) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			hdr->lines++;

			if (msg == msg_start ||
			    (cr == msg_start && cr == msg-1)) {
				/* no headers at all */
				if (cr != msg-1)
					missing_cr_count++;
				msg++;
				break;
			}

			if (cr == msg-1) {
				/* CR+LF */
				if (last_lf == cr-1) {
					/* LF+CR+LF -> end of headers */
					msg++;
					break;
				}
			} else {
				/* missing CR */
				missing_cr_count++;

				if (last_lf == msg-1) {
					/* LF+LF -> end of headers */
					msg++;
					break;
				}
			}
			last_lf = msg;
		}

		msg++;
	}

	hdr->physical_size = (int) (msg-msg_start);
	hdr->virtual_size = hdr->physical_size + missing_cr_count;
}

void message_get_body_size(const char *msg, size_t size, MessageSize *body)
{
	const char *msg_start, *msg_end, *cr;
	int missing_cr_count;

	msg_start = msg;
	msg_end = msg + size;

	body->lines = 0;

	cr = NULL; missing_cr_count = 0;
	while (msg != msg_end) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			body->lines++;

			if (cr != msg-1)
				missing_cr_count++;
		}

		msg++;
	}

	body->physical_size = (int) (msg-msg_start);
	body->virtual_size = (int) (msg-msg_start) + missing_cr_count;
}

void message_size_add(MessageSize *dest, MessageSize *src)
{
	dest->virtual_size += src->virtual_size;
	dest->physical_size += src->physical_size;
	dest->lines += src->lines;
}
