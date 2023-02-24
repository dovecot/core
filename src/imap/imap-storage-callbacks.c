/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "time-util.h"
#include "imap-common.h"
#include "imap-quote.h"
#include "ostream.h"
#include "imap-storage-callbacks.h"

static void notify_ok(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_BEGIN {
		const char *str;

		str = t_strconcat("* OK ", text, "\r\n", NULL);
		o_stream_nsend_str(client->output, str);
		(void)o_stream_flush(client->output);
	} T_END;
}

static void notify_no(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_BEGIN {
		const char *str;

		str = t_strconcat("* NO ", text, "\r\n", NULL);
		o_stream_nsend_str(client->output, str);
		(void)o_stream_flush(client->output);
	} T_END;
}

static const char *find_cmd_tag(struct event *event)
{
	const struct event_field *field =
		event_find_field_recursive(event, "cmd_tag");
	return field != NULL && field->value_type == EVENT_FIELD_VALUE_TYPE_STR ?
	       field->value.str : NULL;
}

const char *
imap_storage_callback_line(const struct mail_storage_progress_details *dtl,
			   const char *tag)
{
	const char *verb = dtl->verb;
	unsigned int total = dtl->total;
	unsigned int processed = dtl->processed;

	if (verb == NULL || *verb == '\0')
		verb = "Processed";

	if (total > 0 && processed >= total)
		processed = total - 1;

	/* The "]" character is totally legit in command tags, but it is
	   problematic inside IMAP resp-text-code(s), which are terminated
	   with "]". If the caracter appears inside the tag, we avoid
	   emitting the tag and replace it with NIL. */
	bool has_tag = tag != NULL && *tag != '\0' && strchr(tag, ']') == NULL;

	string_t *str = t_str_new(128);
	str_append(str, "* OK [INPROGRESS");
	if (has_tag || processed > 0 || total > 0) {
		str_append(str, " (");
		if (has_tag)
			imap_append_quoted(str, tag);
		else
			str_append(str, "NIL");

		if (processed > 0 || total > 0)
			str_printfa(str, " %u", processed);
		else
			str_append(str, " NIL");

		if (total > 0)
			str_printfa(str, " %u", total);
		else
			str_append(str, " NIL");

		str_append_c(str, ')');
	}
	str_append(str, "] ");

	if (total > 0) {
		float percentage = processed * 100.0 / total;
		str_printfa(str, "%s %d%% of the mailbox", verb, (int)percentage);

		unsigned int elapsed_ms = timeval_diff_msecs(&dtl->now,
							     &dtl->start_time);
		if (percentage > 0 && elapsed_ms > 0) {
			int eta_secs = elapsed_ms * (100 - percentage) /
					    (1000 * percentage);

			str_printfa(str, ", ETA %d:%02d",
				    eta_secs / 60, eta_secs % 60);
		}
	} else if (processed > 0)
		str_printfa(str, "%s %u item(s)", verb, processed);
	else
		str_append(str, "Hang in there..");

	return str_c(str);
}

int imap_notify_progress(const struct mail_storage_progress_details *dtl,
			 struct client *client)
{
	int ret;
	T_BEGIN {
		bool corked = o_stream_is_corked(client->output);
		const char *tag = find_cmd_tag(event_get_global());
		const char *line = imap_storage_callback_line(dtl, tag);

		client_send_line(client, line);
		ret = o_stream_uncork_flush(client->output);
		if (corked)
			o_stream_cork(client->output);
	} T_END;
	return ret;
}

static void notify_progress(struct mailbox *mailbox ATTR_UNUSED,
			    const struct mail_storage_progress_details *dtl,
			    void *context)
{
	struct client *client = context;
	(void)imap_notify_progress(dtl, client);
}

struct mail_storage_callbacks imap_storage_callbacks = {
	.notify_ok = notify_ok,
	.notify_no = notify_no,
	.notify_progress = notify_progress
};
