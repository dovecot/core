/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "message-parser.h"
#include "mail-storage-private.h"
#include "mail-save.h"

static int write_with_crlf(struct ostream *output, const void *v_data,
			   size_t size)
{
	const unsigned char *data = v_data;
	size_t i, start;

	i_assert(size <= SSIZE_T_MAX);

	if (size == 0)
		return 0;

	start = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n' && (i == 0 || data[i-1] != '\r')) {
			/* missing CR */
			if (o_stream_send(output, data + start, i - start) < 0)
				return -1;
			if (o_stream_send(output, "\r", 1) < 0)
				return -1;

			/* \n is written next time */
			start = i;
		}
	}

	/* if last char is \r, leave it to buffer */
	if (data[size-1] == '\r')
		size--;

	if (o_stream_send(output, data + start, size - start) < 0)
		return -1;

	return size;
}

static int write_with_lf(struct ostream *output, const void *v_data,
			 size_t size)
{
	const unsigned char *data = v_data;
	size_t i, start;

	i_assert(size <= SSIZE_T_MAX);

	if (size == 0)
		return 0;

	start = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n' && i > 0 && data[i-1] == '\r') {
			/* \r\n - skip \r */
			if (o_stream_send(output, data + start,
					   i - start - 1) < 0)
				return -1;

			/* \n is written next time */
			start = i;
		}
	}

	/* if last char is \r, leave it to buffer */
	if (data[size-1] == '\r')
		size--;

	if (o_stream_send(output, data + start, size - start) < 0)
		return -1;

	return size;
}

static void set_write_error(struct mail_storage *storage,
			    struct ostream *output, const char *path)
{
	errno = output->stream_errno;
	if (ENOSPACE(errno))
		mail_storage_set_error(storage, "Not enough disk space");
	else {
		mail_storage_set_critical(storage,
					  "Can't write to file %s: %m", path);
	}
}

static int save_headers(struct istream *input, struct ostream *output,
			header_callback_t *header_callback, void *context,
			write_func_t *write_func)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	int last_newline = TRUE, hdr_ret, ret = 0;

	hdr_ctx = message_parse_header_init(input, NULL, FALSE);
	while ((hdr_ret = message_parse_header_next(hdr_ctx, &hdr)) > 0) {
		ret = header_callback(hdr->name, write_func, context);
		if (ret <= 0) {
			if (ret < 0)
				break;
			continue;
		}

		if (!hdr->eoh) {
			if (!hdr->continued) {
				(void)o_stream_send(output, hdr->name,
						    hdr->name_len);
				(void)o_stream_send(output, hdr->middle,
						    hdr->middle_len);
			}
			(void)o_stream_send(output, hdr->value, hdr->value_len);
			if (!hdr->no_newline)
				write_func(output, "\n", 1);
			last_newline = !hdr->no_newline;
		} else {
			last_newline = TRUE;
		}
	}
	i_assert(hdr_ret != 0);

	if (ret >= 0) {
		if (!last_newline) {
			/* don't allow headers that don't terminate with \n */
			write_func(output, "\n", 1);
		}
		if (header_callback(NULL, write_func, context) < 0)
			ret = -1;

		/* end of headers */
		write_func(output, "\n", 1);
	}
	message_parse_header_deinit(hdr_ctx);

	return ret < 0 ? -1 : 0;
}

int mail_storage_save(struct mail_storage *storage, const char *path,
		      struct istream *input, struct ostream *output,
		      int crlf_hdr, int crlf_body,
		      header_callback_t *header_callback, void *context)
{
        write_func_t *write_func;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	int failed;

	if (header_callback != NULL) {
		write_func = crlf_hdr ? write_with_crlf : write_with_lf;
		if (save_headers(input, output, header_callback,
				 context, write_func) < 0)
			return -1;
	}

	write_func = crlf_body ? write_with_crlf : write_with_lf;

	failed = FALSE;
	for (;;) {
		data = i_stream_get_data(input, &size);
		if (!failed) {
			ret = write_func(output, data, size);
			if (ret < 0) {
				set_write_error(storage, output, path);
				failed = TRUE;
			} else {
				size = ret;
			}
		}
		i_stream_skip(input, size);

		ret = i_stream_read(input);
		if (ret < 0) {
			errno = input->stream_errno;
			if (errno == 0) {
				/* EOF */
				if (input->disconnected) {
					/* too early */
					mail_storage_set_error(storage,
						"Unexpected EOF");
					failed = TRUE;
				}
				break;
			} else if (errno == EAGAIN) {
				mail_storage_set_error(storage,
					"Timeout while waiting for input");
			} else {
				mail_storage_set_critical(storage,
					"Error reading mail from client: %m");
			}
			failed = TRUE;
			break;
		}
	}

	return failed ? -1 : 0;
}

int mail_storage_copy(struct mailbox_transaction_context *t, struct mail *mail,
		      struct mail **dest_mail_r)
{
	struct istream *input;

	input = mail->get_stream(mail, NULL, NULL);
	if (input == NULL)
		return -1;

	return mailbox_save(t, mail->get_flags(mail),
			    mail->get_received_date(mail), 0,
			    mail->get_special(mail, MAIL_FETCH_FROM_ENVELOPE),
			    input, dest_mail_r);
}
