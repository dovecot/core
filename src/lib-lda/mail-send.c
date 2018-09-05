/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

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
#include "message-address.h"
#include "istream-header-filter.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "iostream-ssl.h"
#include "lda-settings.h"
#include "mail-deliver.h"
#include "smtp-address.h"
#include "smtp-submit.h"
#include "mail-send.h"

#include <sys/wait.h>

static const struct var_expand_table *
get_var_expand_table(struct mail *mail,
		     const struct smtp_address *recipient,
		     const char *reason)
{
	const char *subject;
	if (mail_get_first_header(mail, "Subject", &subject) <= 0)
		subject = "";

	const struct var_expand_table stack_tab[] = {
		{ 'n', "\r\n", "crlf" },
		{ 'r', reason, "reason" },
		{ 's', str_sanitize(subject, 80), "subject" },
		{ 't', smtp_address_encode(recipient), "to" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc_no0(sizeof(stack_tab));
	memcpy(tab, stack_tab, sizeof(stack_tab));
	return tab;
}

int mail_send_rejection(struct mail_deliver_context *ctx,
			const struct smtp_address *recipient,
			const char *reason)
{
	struct mail_user *user = ctx->rcpt_user;
	struct ssl_iostream_settings ssl_set;
	struct mail *mail = ctx->src_mail;
	struct istream *input;
	struct smtp_submit *smtp_submit;
	struct ostream *output;
	const struct message_address *postmaster_addr;
	const struct smtp_address *return_addr;
	const char *hdr, *value, *msgid, *orig_msgid, *boundary, *error;
	const struct var_expand_table *vtable;
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
	if (smtp_address_isnull(return_addr)) {
		i_info("msgid=%s: Return-Path missing, rejection reason: %s",
			orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80),
			str_sanitize(reason, 512));
		return 0;
	}

	if (!mail_user_set_get_postmaster_address(user->set, &postmaster_addr,
						  &error)) {
		i_error("msgid=%s: Invalid postmaster_address - can't send rejection: %s",
			orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80), error);
		return -1;
	}

	e_debug(mail->event, "Sending a rejection to <%s>: %s",
		smtp_address_encode(return_addr),
		str_sanitize(reason, 512));

	vtable = get_var_expand_table(mail, recipient, reason);

	i_zero(&ssl_set);
	mail_user_init_ssl_client_settings(user, &ssl_set);

	smtp_submit = smtp_submit_init_simple(ctx->smtp_set, &ssl_set, NULL);
	smtp_submit_add_rcpt(smtp_submit, return_addr);
	output = smtp_submit_send(smtp_submit);

	msgid = mail_deliver_get_new_message_id(ctx);
	boundary = t_strdup_printf("%s/%s", my_pid, user->set->hostname);

	str = t_str_new(512);
	str_printfa(str, "Message-ID: %s\r\n", msgid);
	str_printfa(str, "Date: %s\r\n", message_date_create(ioloop_time));
	str_append(str, "From: ");
	message_address_write(str, postmaster_addr);
	str_append(str, "\r\n");
	str_printfa(str, "To: <%s>\r\n", smtp_address_encode(return_addr));
	str_append(str, "MIME-Version: 1.0\r\n");
	str_printfa(str, "Content-Type: "
		"multipart/report; report-type=%s;\r\n"
		"\tboundary=\"%s\"\r\n",
		ctx->dsn ? "delivery-status" : "disposition-notification",
		boundary);
	str_append(str, "Subject: ");
	if (var_expand(str, ctx->set->rejection_subject,
		vtable, &error) <= 0) {
		i_error("Failed to expand rejection_subject=%s: %s",
			ctx->set->rejection_subject, error);
	}
	str_append(str, "\r\n");

	str_append(str, "Auto-Submitted: auto-replied (rejected)\r\n");
	str_append(str, "Precedence: bulk\r\n");
	str_append(str, "\r\nThis is a MIME-encapsulated message\r\n\r\n");

	/* human readable status report */
	str_printfa(str, "--%s\r\n", boundary);
	str_append(str, "Content-Type: text/plain; charset=utf-8\r\n");
	str_append(str, "Content-Disposition: inline\r\n");
	str_append(str, "Content-Transfer-Encoding: 8bit\r\n\r\n");

	if (var_expand(str, ctx->set->rejection_reason,
		vtable, &error) <= 0) {
		i_error("Failed to expand rejection_reason=%s: %s",
			ctx->set->rejection_reason, error);
	}
	str_append(str, "\r\n");

	if (ctx->dsn) {
		/* DSN status report: For LDA rejects. currently only used when
		   user is out of quota */
		str_printfa(str, "--%s\r\n"
			"Content-Type: message/delivery-status\r\n\r\n",
			boundary);
		str_printfa(str, "Reporting-MTA: dns; %s\r\n", user->set->hostname);
		if (mail_get_first_header(mail, "Original-Recipient", &hdr) > 0)
			str_printfa(str, "Original-Recipient: rfc822; %s\r\n", hdr);
		str_printfa(str, "Final-Recipient: rfc822; %s\r\n",
			smtp_address_encode(recipient));
		str_append(str, "Action: failed\r\n");
		str_printfa(str, "Status: %s\r\n", ctx->mailbox_full ? "5.2.2" : "5.2.0");
	} else {
		/* MDN status report: For Sieve "reject" */
		str_printfa(str, "--%s\r\n"
			"Content-Type: message/disposition-notification\r\n\r\n",
			boundary);
		str_printfa(str, "Reporting-UA: %s; Dovecot Mail Delivery Agent\r\n",
			user->set->hostname);
		if (mail_get_first_header(mail, "Original-Recipient", &hdr) > 0)
			str_printfa(str, "Original-Recipient: rfc822; %s\r\n", hdr);
		str_printfa(str, "Final-Recipient: rfc822; %s\r\n",
			smtp_address_encode(recipient));

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
			*null_header_filter_callback, NULL);

		o_stream_nsend_istream(output, input);
		i_stream_unref(&input);
	}

	str_truncate(str, 0);
	str_printfa(str, "\r\n\r\n--%s--\r\n", boundary);
	o_stream_nsend(output, str_data(str), str_len(str));
	if ((ret = smtp_submit_run(smtp_submit, &error)) < 0) {
		i_error("msgid=%s: Temporarily failed to send rejection: %s",
			orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80),
			str_sanitize(error, 512));
	} else if (ret == 0) {
		i_info("msgid=%s: Permanently failed to send rejection: %s",
			orig_msgid == NULL ? "" : str_sanitize(orig_msgid, 80),
			str_sanitize(error, 512));
	}
	smtp_submit_deinit(&smtp_submit);
	return ret < 0 ? -1 : 0;
}
