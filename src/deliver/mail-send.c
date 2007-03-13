/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hostpid.h"
#include "istream.h"
#include "str-sanitize.h"
#include "message-date.h"
#include "message-size.h"
#include "duplicate.h"
#include "istream-header-filter.h"
#include "smtp-client.h"
#include "deliver.h"
#include "mail-send.h"

#include <sys/wait.h>

#define MAIL_REJECTION_HUMAN_REASON \
"Your message was automatically rejected by Dovecot Mail Delivery Agent.\r\n" \
"\r\n" \
"The following reason was given:\r\n" \
"%s\r\n"

int global_outgoing_count = 0;

int mail_send_rejection(struct mail *mail, const char *recipient,
			const char *reason)
{
    struct istream *input;
    struct smtp_client *smtp_client;
    FILE *f;
    struct message_size hdr_size;
    const char *return_addr, *str;
    const unsigned char *data;
    const char *msgid, *orig_msgid, *boundary;
    size_t size;
    int ret;

    orig_msgid = mail_get_first_header(mail, "Message-ID");
    return_addr = deliver_get_return_address(mail);
    if (return_addr == NULL) {
	    i_info("msgid=%s: Return-Path missing, rejection reason: %s",
		   orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80),
		   str_sanitize(reason, 512));
	    return -1;
    }

    smtp_client = smtp_client_open(return_addr, NULL, &f);

    msgid = deliver_get_new_message_id();
    boundary = t_strdup_printf("%s/%s", my_pid, deliver_set->hostname);

    fprintf(f, "Message-ID: %s\r\n", msgid);
    fprintf(f, "Date: %s\r\n", message_date_create(ioloop_time));
    fprintf(f, "From: Mail Delivery Subsystem <%s>\r\n",
	    deliver_set->postmaster_address);
    fprintf(f, "To: <%s>\r\n", return_addr);
    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "Content-Type: "
	    "multipart/report; report-type=disposition-notification;\r\n"
	    "\tboundary=\"%s\"\r\n", boundary);
    fprintf(f, "Subject: Automatically rejected mail\r\n");
    fprintf(f, "Auto-Submitted: auto-replied (rejected)\r\n");
    fprintf(f, "Precedence: bulk\r\n");
    fprintf(f, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* human readable status report */
    fprintf(f, "--%s\r\n", boundary);
    fprintf(f, "Content-Type: text/plain; charset=utf-8\r\n");
    fprintf(f, "Content-Disposition: inline\r\n");
    fprintf(f, "Content-Transfer-Encoding: 8bit\r\n\r\n");
    fprintf(f, MAIL_REJECTION_HUMAN_REASON"\r\n", reason);

    /* MDN status report */
    fprintf(f, "--%s\r\n"
	    "Content-Type: message/disposition-notification\r\n\r\n",
	    boundary);
    fprintf(f, "Reporting-UA: %s; Dovecot Mail Delivery Agent\r\n",
	    deliver_set->hostname);
    str = mail_get_first_header(mail, "Original-Recipient");
    if (str != NULL)
	fprintf(f, "Original-Recipient: rfc822; %s\r\n", str);
    fprintf(f, "Final-Recipient: rfc822; %s\r\n", recipient);

    if (orig_msgid != NULL)
	fprintf(f, "Original-Message-ID: %s\r\n", orig_msgid);
    fprintf(f, "Disposition: "
	    "automatic-action/MDN-sent-automatically; deleted\r\n");
    fprintf(f, "\r\n");

    /* original message's headers */
    fprintf(f, "--%s\r\nContent-Type: message/rfc822\r\n\r\n", boundary);

    input = mail_get_stream(mail, &hdr_size, NULL);
    if (input != NULL) {
	    /* Note: If you add more headers, they need to be sorted.
	       We'll drop Content-Type because we're not including the message
	       body, and having a multipart Content-Type may confuse some
	       MIME parsers when they don't see the message boundaries. */
	    static const char *const exclude_headers[] = {
		    "Content-Type"
	    };

	    input = i_stream_create_header_filter(input,
	    		HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR |
			HEADER_FILTER_HIDE_BODY, exclude_headers,
			sizeof(exclude_headers) / sizeof(exclude_headers[0]),
			null_header_filter_callback, NULL);

	    while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
		    if (fwrite(data, size, 1, f) == 0)
			    break;
		    i_stream_skip(input, size);
	    }
	    i_stream_unref(&input);

	    i_assert(ret != 0);
    }

    fprintf(f, "\r\n\r\n--%s--\r\n", boundary);
    return smtp_client_close(smtp_client);
}

int mail_send_forward(struct mail *mail, const char *forwardto)
{
    static const char *hide_headers[] = {
        "Return-Path"
    };
    struct istream *input;
    struct smtp_client *smtp_client;
    FILE *f;
    const unsigned char *data;
    size_t size;
    int ret;

    input = mail_get_stream(mail, NULL, NULL);
    if (input == NULL)
	    return -1;

    smtp_client = smtp_client_open(forwardto,
				   mail_get_first_header(mail, "Return-Path"),
				   &f);

    input = i_stream_create_header_filter(input, HEADER_FILTER_EXCLUDE |
                                          HEADER_FILTER_NO_CR, hide_headers,
                                          sizeof(hide_headers) /
					  sizeof(hide_headers[0]),
					  null_header_filter_callback, NULL);

    while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
	    if (fwrite(data, size, 1, f) == 0)
		    break;
	    i_stream_skip(input, size);
    }

    return smtp_client_close(smtp_client);
}

