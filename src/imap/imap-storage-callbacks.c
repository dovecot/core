/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-common.h"
#include "imap-quote.h"
#include "imap-utf7.h"
#include "ostream.h"
#include "imap-feature.h"
#include "imap-progress.h"
#include "imap-storage-callbacks.h"

static void notify_status(struct mailbox *mailbox ATTR_UNUSED,
			  const char *status,
		      	  const char *text, void *context)
{
	struct client *client = context;

	if (o_stream_get_buffer_used_size(client->output) != 0)
		return;

	T_BEGIN {
		const char *str = t_strdup_printf("* %s %s\r\n", status, text);
		o_stream_nsend_str(client->output, str);
		(void)o_stream_flush(client->output);
	} T_END;
}

static void notify_ok(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	notify_status(mailbox, "OK", text, context);
}

static void notify_no(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	notify_status(mailbox, "NO", text, context);
}

static void notify_bad(struct mailbox *mailbox ATTR_UNUSED,
		      const char *text, void *context)
{
	notify_status(mailbox, "BAD", text, context);
}

static const char *find_cmd_tag(struct event *event)
{
	const struct event_field *field = event == NULL ? NULL :
		event_find_field_recursive(event, "cmd_tag");
	return field != NULL && field->value_type == EVENT_FIELD_VALUE_TYPE_STR ?
	       field->value.str : NULL;
}

int imap_notify_progress(const struct mail_storage_progress_details *dtl,
			 struct client *client)
{
	int ret;
	T_BEGIN {
		bool corked = o_stream_is_corked(client->output);
		const char *tag = find_cmd_tag(event_get_global());
		const char *line = imap_progress_line(dtl, tag);

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

static const char *
notify_mailbox_implicit_rename_line(struct client *client,
				    struct mailbox *mailbox,
				    const char *old_vname)
{
	string_t *str = t_str_new(256);
	struct mail_namespace *ns = mailbox_get_namespace(mailbox);
	char ns_sep = mail_namespace_get_sep(ns);
	bool utf8 = client_has_enabled(client, imap_feature_utf8accept);

	str_append(str, "* LIST () \"");
	if (ns_sep == '\\')
		str_append_c(str, '\\');
	str_append_c(str, ns_sep);
	str_append(str, "\" ");

	const char *vname = mailbox_get_vname(mailbox);
	string_t *mutf7_vname = NULL;

	if (!utf8) {
		mutf7_vname = t_str_new(128);
		if (imap_utf8_to_utf7(vname, mutf7_vname) < 0)
			i_panic("Mailbox name not UTF-8: %s", vname);
		vname = str_c(mutf7_vname);
	}
	imap_append_astring(str, vname, utf8);

	if (old_vname != NULL) {
		if (!utf8) {
			str_truncate(mutf7_vname, 0);
			if (imap_utf8_to_utf7(old_vname, mutf7_vname) < 0) {
				i_panic("Mailbox name not UTF-8: %s",
					old_vname);
			}
			old_vname = str_c(mutf7_vname);
		}

		str_append(str, " (\"OLDNAME\" (");
		imap_append_astring(str, old_vname, utf8);
		str_append(str, "))");
	}

	return str_c(str);
}

static void
notify_mailbox_implicit_rename(struct mailbox *mailbox, const char *old_vname,
			       void *context)
{
	struct client *client = context;

	T_BEGIN {
		bool corked = o_stream_is_corked(client->output);
		const char *line =
			notify_mailbox_implicit_rename_line(client, mailbox,
							    old_vname);

		client_send_line(client, line);
		(void)o_stream_uncork_flush(client->output);
		if (corked)
			o_stream_cork(client->output);
	} T_END;
}

struct mail_storage_callbacks imap_storage_callbacks = {
	.notify_ok = notify_ok,
	.notify_no = notify_no,
	.notify_bad = notify_bad,
	.notify_progress = notify_progress,
	.notify_mailbox_implicit_rename = notify_mailbox_implicit_rename,
};
