/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "str-sanitize.h"
#include "var-expand.h"
#include "message-date.h"
#include "message-size.h"
#include "istream-header-filter.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "lda-settings.h"
#include "mail-deliver.h"
#include "smtp-client.h"
#include "mail-send.h"

#include <stdlib.h>
#include <sys/wait.h>

int global_outgoing_count = 0;

static const struct var_expand_table *
get_var_expand_table(struct mail *mail, const char *reason,
		     const char *recipient)
{
	static struct var_expand_table static_tab[] = {
		{ 'n', NULL, "crlf" },
		{ 'r', NULL, "reason" },
		{ 's', NULL, "subject" },
		{ 't', NULL, "to" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	const char *subject;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = "\r\n";
	tab[1].value = reason;
	if (mail_get_first_header(mail, "Subject", &subject) <= 0)
		subject = "";
	tab[2].value = str_sanitize(subject, 80);
	tab[3].value = recipient;

	return tab;
}

int mail_send_rejection(struct mail_deliver_context *ctx, const char *recipient,
			const char *reason)
{
    struct mail *mail = ctx->src_mail;
    struct istream *input;
    struct smtp_client *smtp_client;
    struct ostream *output;
    const char *return_addr, *hdr;
    const char *value, *msgid, *orig_msgid, *boundary;
    string_t *str;
    int ret;

    if (mail_get_first_header(mail, "Message-ID", &orig_msgid) < 0)
	    orig_msgid = NULL;

    if (mail_get_first_header(mail, "Auto-Submitted", &value) > 0 &&
	strcasecmp(value, "no") != 0) {
	    i_info("msgid=%s: Auto-submitted message discarded: %s",
		   orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80),
		   str_sanitize(reason, 512));
	    return 0;
    }

    return_addr = mail_deliver_get_return_address(ctx);
    if (return_addr == NULL) {
	    i_info("msgid=%s: Return-Path missing, rejection reason: %s",
		   orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80),
		   str_sanitize(reason, 512));
	    return 0;
    }

    if (mailbox_get_settings(mail->box)->mail_debug) {
	    i_debug("Sending a rejection to %s: %s", recipient,
		    str_sanitize(reason, 512));
    }

    smtp_client = smtp_client_open(ctx->set, return_addr, NULL, &output);

    msgid = mail_deliver_get_new_message_id(ctx);
    boundary = t_strdup_printf("%s/%s", my_pid, ctx->set->hostname);

    str = t_str_new(512);
    str_printfa(str, "Message-ID: %s\r\n", msgid);
    str_printfa(str, "Date: %s\r\n", message_date_create(ioloop_time));
    str_printfa(str, "From: Mail Delivery Subsystem <%s>\r\n",
		ctx->set->postmaster_address);
    str_printfa(str, "To: <%s>\r\n", return_addr);
    str_append(str, "MIME-Version: 1.0\r\n");
    str_printfa(str, "Content-Type: "
		"multipart/report; report-type=%s;\r\n"
		"\tboundary=\"%s\"\r\n",
		ctx->dsn ? "delivery-status" : "disposition-notification",
		boundary);
    str_append(str, "Subject: ");
    var_expand(str, ctx->set->rejection_subject,
	       get_var_expand_table(mail, reason, recipient));
    str_append(str, "\r\n");

    str_append(str, "Auto-Submitted: auto-replied (rejected)\r\n");
    str_append(str, "Precedence: bulk\r\n");
    str_append(str, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* human readable status report */
    str_printfa(str, "--%s\r\n", boundary);
    str_append(str, "Content-Type: text/plain; charset=utf-8\r\n");
    str_append(str, "Content-Disposition: inline\r\n");
    str_append(str, "Content-Transfer-Encoding: 8bit\r\n\r\n");

    var_expand(str, ctx->set->rejection_reason,
	       get_var_expand_table(mail, reason, recipient));
    str_append(str, "\r\n");

    if (ctx->dsn) {
	    /* DSN status report: For LDA rejects. currently only used when
	       user is out of quota */
	    str_printfa(str, "--%s\r\n"
			"Content-Type: message/delivery-status\r\n\r\n",
			boundary);
	    str_printfa(str, "Reporting-MTA: dns; %s\r\n", ctx->set->hostname);
	    if (mail_get_first_header(mail, "Original-Recipient", &hdr) > 0)
		    str_printfa(str, "Original-Recipient: rfc822; %s\r\n", hdr);
	    str_printfa(str, "Final-Recipient: rfc822; %s\r\n", recipient);
	    str_append(str, "Action: failed\r\n");
	    str_printfa(str, "Status: %s\r\n", ctx->mailbox_full ? "5.2.2" : "5.2.0");
    } else {
	    /* MDN status report: For Sieve "reject" */
	    str_printfa(str, "--%s\r\n"
			"Content-Type: message/disposition-notification\r\n\r\n",
			boundary);
	    str_printfa(str, "Reporting-UA: %s; Dovecot Mail Delivery Agent\r\n",
			ctx->set->hostname);
	    if (mail_get_first_header(mail, "Original-Recipient", &hdr) > 0)
		    str_printfa(str, "Original-Recipient: rfc822; %s\r\n", hdr);
	    str_printfa(str, "Final-Recipient: rfc822; %s\r\n", recipient);

	    if (orig_msgid != NULL)
		    str_printfa(str, "Original-Message-ID: %s\r\n", orig_msgid);
	    str_append(str, "Disposition: "
		       "automatic-action/MDN-sent-automatically; deleted\r\n");
    }
    str_append(str, "\r\n");

    /* original message's headers */
    str_printfa(str, "--%s\r\nContent-Type: message/rfc822\r\n\r\n", boundary);
    o_stream_nsend(output, str_data(str), str_len(str));

    if (mail_get_hdr_stream(mail, NULL, &input) == 0) {
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
			N_ELEMENTS(exclude_headers),
			*null_header_filter_callback, (void *)NULL);

	    ret = o_stream_send_istream(output, input);
	    i_stream_unref(&input);

	    i_assert(ret != 0);
    }

    str_truncate(str, 0);
    str_printfa(str, "\r\n\r\n--%s--\r\n", boundary);
    o_stream_nsend(output, str_data(str), str_len(str));
    return smtp_client_close(smtp_client);
}

int mail_send_forward(struct mail_deliver_context *ctx, const char *forwardto)
{
    static const char *hide_headers[] = {
        "Return-Path"
    };
    struct istream *input;
    struct ostream *output;
    struct smtp_client *smtp_client;
    const char *return_path;

    if (mail_get_stream(ctx->src_mail, NULL, NULL, &input) < 0)
	    return -1;

    return_path = mail_deliver_get_return_address(ctx);
    if (mailbox_get_settings(ctx->src_mail->box)->mail_debug) {
	    i_debug("Sending a forward to <%s> with return path <%s>",
		    forwardto, return_path);
    }

    smtp_client = smtp_client_open(ctx->set, forwardto, return_path, &output);

    input = i_stream_create_header_filter(input, HEADER_FILTER_EXCLUDE |
                                          HEADER_FILTER_NO_CR, hide_headers,
                                          N_ELEMENTS(hide_headers),
					  *null_header_filter_callback,
					  (void *)NULL);

    (void)o_stream_send_istream(output, input);
    i_stream_unref(&input);

    return smtp_client_close(smtp_client);
}
