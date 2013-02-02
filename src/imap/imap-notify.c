/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-quote.h"
#include "mailbox-list-iter.h"
#include "mailbox-list-notify.h"
#include "mail-search.h"
#include "mail-search-build.h"
#include "imap-commands.h"
#include "imap-fetch.h"
#include "imap-list.h"
#include "imap-status.h"
#include "imap-notify.h"

#define IMAP_NOTIFY_WATCH_ADD_DELAY_MSECS 1000

static bool notify_hook_registered;

static int imap_notify_list(struct imap_notify_namespace *notify_ns,
			    const struct mailbox_list_notify_rec *rec,
			    enum mailbox_info_flags flags)
{
	string_t *str = t_str_new(128);
	char ns_sep = mail_namespace_get_sep(notify_ns->ns);

	str_append(str, "* LIST (");
	imap_mailbox_flags2str(str, flags);
	str_append(str, ") \"");
	if (ns_sep == '\\')
		str_append_c(str, '\\');
	str_append_c(str, ns_sep);
	str_append(str, "\" ");

	imap_append_astring(str, rec->vname);
	if (rec->old_vname != NULL) {
		str_append(str, " (\"OLDNAME\" (");
		imap_append_astring(str, rec->old_vname);
		str_append(str, "))");
	}
	return client_send_line_next(notify_ns->ctx->client, str_c(str));
}

static int imap_notify_status(struct imap_notify_namespace *notify_ns,
			      const struct mailbox_list_notify_rec *rec)
{
	struct client *client = notify_ns->ctx->client;
	struct mailbox *box;
	struct imap_status_items items;
	struct imap_status_result result;
	enum mail_error error;
	int ret = 1;

	memset(&items, 0, sizeof(items));
	if ((client->enabled_features & MAILBOX_FEATURE_CONDSTORE) != 0)
		items.status |= STATUS_HIGHESTMODSEQ;

	box = mailbox_alloc(notify_ns->ns->list, rec->vname, 0);
	switch (rec->event) {
	case MAILBOX_LIST_NOTIFY_UIDVALIDITY:
		items.status |= STATUS_UIDVALIDITY | STATUS_UIDNEXT |
			STATUS_MESSAGES | STATUS_UNSEEN;
		break;
	case MAILBOX_LIST_NOTIFY_APPENDS:
	case MAILBOX_LIST_NOTIFY_EXPUNGES:
		items.status |= STATUS_UIDNEXT | STATUS_MESSAGES | STATUS_UNSEEN;
		break;
	case MAILBOX_LIST_NOTIFY_SEEN_CHANGES:
		items.status |= STATUS_UNSEEN;
		break;
	case MAILBOX_LIST_NOTIFY_MODSEQ_CHANGES:
		/* if HIGHESTMODSEQ isn't being sent, don't send anything */
		break;
	case MAILBOX_LIST_NOTIFY_CREATE:
	case MAILBOX_LIST_NOTIFY_DELETE:
	case MAILBOX_LIST_NOTIFY_RENAME:
	case MAILBOX_LIST_NOTIFY_SUBSCRIBE:
	case MAILBOX_LIST_NOTIFY_UNSUBSCRIBE:
		i_unreached();
	}
	if (items.status == 0) {
		/* don't send anything */
	} else if (mailbox_get_status(box, items.status, &result.status) < 0) {
		/* hide permission errors from client. we don't want to leak
		   information about existence of mailboxes where user doesn't
		   have access to */
		(void)mailbox_get_last_error(box, &error);
		if (error != MAIL_ERROR_PERM)
			ret = -1;
	} else {
		ret = imap_status_send(client, rec->vname, &items, &result);
	}
	mailbox_free(&box);
	return ret;
}

static int
imap_notify_next(struct imap_notify_namespace *notify_ns,
		 const struct mailbox_list_notify_rec *rec)
{
	enum mailbox_info_flags mailbox_flags;
	int ret = 1;

	switch (rec->event) {
	case MAILBOX_LIST_NOTIFY_CREATE:
		if (mailbox_list_mailbox(notify_ns->ns->list, rec->storage_name,
					 &mailbox_flags) < 0)
			mailbox_flags = 0;
		ret = imap_notify_list(notify_ns, rec, mailbox_flags);
		break;
	case MAILBOX_LIST_NOTIFY_DELETE:
		ret = imap_notify_list(notify_ns, rec, MAILBOX_NONEXISTENT);
		break;
	case MAILBOX_LIST_NOTIFY_RENAME:
		if (mailbox_list_mailbox(notify_ns->ns->list, rec->storage_name,
					 &mailbox_flags) < 0)
			mailbox_flags = 0;
		ret = imap_notify_list(notify_ns, rec, mailbox_flags);
		break;
	case MAILBOX_LIST_NOTIFY_SUBSCRIBE:
		if (mailbox_list_mailbox(notify_ns->ns->list, rec->storage_name,
					 &mailbox_flags) < 0)
			mailbox_flags = 0;
		ret = imap_notify_list(notify_ns, rec,
				       mailbox_flags | MAILBOX_SUBSCRIBED);
		break;
	case MAILBOX_LIST_NOTIFY_UNSUBSCRIBE:
		if (mailbox_list_mailbox(notify_ns->ns->list, rec->storage_name,
					 &mailbox_flags) < 0)
			mailbox_flags = 0;
		ret = imap_notify_list(notify_ns, rec, mailbox_flags);
		break;
	case MAILBOX_LIST_NOTIFY_UIDVALIDITY:
	case MAILBOX_LIST_NOTIFY_APPENDS:
	case MAILBOX_LIST_NOTIFY_EXPUNGES:
	case MAILBOX_LIST_NOTIFY_SEEN_CHANGES:
	case MAILBOX_LIST_NOTIFY_MODSEQ_CHANGES:
		ret = imap_notify_status(notify_ns, rec);
		break;
	}
	return ret;
}

static bool
imap_notify_match_event(struct imap_notify_namespace *notify_ns,
			const struct imap_notify_mailboxes *notify_boxes,
			const struct mailbox_list_notify_rec *rec)
{
	enum imap_notify_event wanted_events = notify_boxes->events;
	struct mailbox *box;
	bool mailbox_event = FALSE;

	switch (rec->event) {
	case MAILBOX_LIST_NOTIFY_CREATE:
	case MAILBOX_LIST_NOTIFY_DELETE:
	case MAILBOX_LIST_NOTIFY_RENAME:
		if ((wanted_events & IMAP_NOTIFY_EVENT_MAILBOX_NAME) == 0)
			return FALSE;
		break;
	case MAILBOX_LIST_NOTIFY_SUBSCRIBE:
	case MAILBOX_LIST_NOTIFY_UNSUBSCRIBE:
		if ((wanted_events & IMAP_NOTIFY_EVENT_SUBSCRIPTION_CHANGE) == 0)
			return FALSE;
		break;
	case MAILBOX_LIST_NOTIFY_UIDVALIDITY:
		if ((wanted_events & (IMAP_NOTIFY_EVENT_MESSAGE_NEW |
				      IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE |
				      IMAP_NOTIFY_EVENT_FLAG_CHANGE)) == 0)
			return FALSE;
		mailbox_event = TRUE;
		break;
	case MAILBOX_LIST_NOTIFY_APPENDS:
		if ((wanted_events & IMAP_NOTIFY_EVENT_MESSAGE_NEW) == 0)
			return FALSE;
		mailbox_event = TRUE;
		break;
	case MAILBOX_LIST_NOTIFY_EXPUNGES:
		if ((wanted_events & IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE) == 0)
			return FALSE;
		mailbox_event = TRUE;
		break;
	case MAILBOX_LIST_NOTIFY_SEEN_CHANGES:
	case MAILBOX_LIST_NOTIFY_MODSEQ_CHANGES:
		if ((wanted_events & IMAP_NOTIFY_EVENT_FLAG_CHANGE) == 0)
			return FALSE;
		mailbox_event = TRUE;
		break;
	}

	if (mailbox_event) {
		/* if this is an even for selected mailbox, ignore it */
		box = notify_ns->ctx->client->mailbox;
		if (box != NULL &&
		    mailbox_equals(box, notify_ns->ns, rec->vname))
			return FALSE;
	}
	return TRUE;
}

bool imap_notify_match_mailbox(struct imap_notify_namespace *notify_ns,
			       const struct imap_notify_mailboxes *notify_boxes,
			       const char *vname)
{
	struct mailbox *box;
	const char *const *namep;
	unsigned int name_len;
	char ns_sep;
	bool ret;

	switch (notify_boxes->type) {
	case IMAP_NOTIFY_TYPE_SUBSCRIBED:
		box = mailbox_alloc(notify_ns->ns->list, vname, 0);
		ret = mailbox_is_subscribed(box);
		mailbox_free(&box);
		return ret;
	case IMAP_NOTIFY_TYPE_SUBTREE:
		ns_sep = mail_namespace_get_sep(notify_ns->ns);
		array_foreach(&notify_boxes->names, namep) {
			name_len = strlen(*namep);
			if (name_len == 0) {
				/* everything under root. NOTIFY spec itself
				   doesn't define this, but we use it for
				   implementing "personal" */
				return TRUE;
			}
			if (strncmp(*namep, vname, name_len) == 0 &&
			    (vname[name_len] == '\0' ||
			     vname[name_len] == ns_sep))
				return TRUE;
		}
		break;
	case IMAP_NOTIFY_TYPE_MAILBOX:
		array_foreach(&notify_boxes->names, namep) {
			if (strcmp(*namep, vname) == 0)
				return TRUE;
		}
		break;
	}
	return FALSE;
}

static bool
imap_notify_match(struct imap_notify_namespace *notify_ns,
		  const struct mailbox_list_notify_rec *rec)
{
	const struct imap_notify_mailboxes *notify_boxes;

	array_foreach(&notify_ns->mailboxes, notify_boxes) {
		if (imap_notify_match_event(notify_ns, notify_boxes, rec) &&
		    imap_notify_match_mailbox(notify_ns, notify_boxes, rec->vname))
			return TRUE;
	}
	return FALSE;
}

static int imap_client_notify_ns(struct imap_notify_namespace *notify_ns)
{
	const struct mailbox_list_notify_rec *rec;
	int ret, ret2 = 1;

	while ((ret = mailbox_list_notify_next(notify_ns->notify, &rec)) > 0) {
		if (imap_notify_match(notify_ns, rec)) T_BEGIN {
			ret2 = imap_notify_next(notify_ns, rec);
		} T_END;
		if (ret2 <= 0)
			break;
	}
	if (ret < 0) {
		/* failed to get some notifications */
		return -1;
	}
	return ret2;
}

static int
imap_client_notify_selected(struct client *client)
{
	struct imap_fetch_context *fetch_ctx = client->notify_ctx->fetch_ctx;
	int ret;

	if (!fetch_ctx->state.fetching)
		return 1;

	if ((ret = imap_fetch_more_no_lock_update(fetch_ctx)) <= 0)
		return ret;
	/* finished the FETCH */
	if (imap_fetch_end(fetch_ctx) < 0)
		return -1;
	return 1;
}

static int imap_client_notify_more(struct client *client)
{
	struct imap_notify_namespace *notify_ns;
	int ret = 1;

	/* send notifications for selected mailbox first. note that it may
	   leave the client's output stream in the middle of a FETCH reply. */
	if (client->notify_ctx->fetch_ctx != NULL) {
		if ((ret = imap_client_notify_selected(client)) < 0) {
			client->notify_ctx->fetch_ctx->state.failed = FALSE;
			ret = -1;
		}
	}

	/* send notifications for non-selected mailboxes */
	array_foreach_modifiable(&client->notify_ctx->namespaces, notify_ns) {
		if (ret == 0)
			break;
		if (imap_client_notify_ns(notify_ns) < 0)
			ret = -1;
	}

	if (ret < 0) {
		client_send_line(notify_ns->ctx->client,
			"* NO NOTIFY error, some events may have got lost");
	}
	return ret;
}

int imap_client_notify_newmails(struct client *client)
{
	struct imap_fetch_context *fetch_ctx = client->notify_ctx->fetch_ctx;
	struct mailbox_status status;
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;

	i_assert(client->mailbox != NULL);

	if (fetch_ctx == NULL) {
		/* FETCH notifications not enabled in this session */
		return 1;
	}
	if (client->notify_ctx->notifying)
		return imap_client_notify_more(client);
	client->notify_ctx->notifying = TRUE;

	i_assert(!fetch_ctx->state.fetching);

	mailbox_get_open_status(client->mailbox, STATUS_UIDNEXT, &status);

	search_args = mail_search_build_init();
	arg = mail_search_build_add(search_args, SEARCH_UIDSET);
	p_array_init(&arg->value.seqset, search_args->pool, 1);
	seq_range_array_add_range(&arg->value.seqset,
				  client->notify_uidnext, status.uidnext-1);
	client->notify_uidnext = status.uidnext;

	imap_fetch_begin(fetch_ctx, client->mailbox, search_args);
	mail_search_args_unref(&search_args);

	return imap_client_notify_more(client);
}

void imap_client_notify_finished(struct client *client)
{
	if (client->notify_ctx != NULL)
		client->notify_ctx->notifying = FALSE;
}

static void notify_callback(void *context)
{
	struct imap_notify_namespace *notify_ns = context;

	o_stream_cork(notify_ns->ctx->client->output);
	imap_client_notify_ns(notify_ns);
	o_stream_uncork(notify_ns->ctx->client->output);
}

static enum mailbox_list_notify_event
imap_events_to_notify(enum imap_notify_event events)
{
	enum mailbox_list_notify_event ret = 0;

	if ((events & IMAP_NOTIFY_EVENT_MESSAGE_NEW) != 0) {
		ret |= MAILBOX_LIST_NOTIFY_APPENDS |
			MAILBOX_LIST_NOTIFY_UIDVALIDITY;
	}
	if ((events & IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE) != 0) {
		ret |= MAILBOX_LIST_NOTIFY_EXPUNGES |
			MAILBOX_LIST_NOTIFY_UIDVALIDITY;
	}
	if ((events & IMAP_NOTIFY_EVENT_FLAG_CHANGE) != 0) {
		ret |= MAILBOX_LIST_NOTIFY_SEEN_CHANGES |
			MAILBOX_LIST_NOTIFY_MODSEQ_CHANGES |
			MAILBOX_LIST_NOTIFY_UIDVALIDITY;
	}
	if ((events & IMAP_NOTIFY_EVENT_MAILBOX_NAME) != 0) {
		ret |= MAILBOX_LIST_NOTIFY_CREATE |
			MAILBOX_LIST_NOTIFY_DELETE |
			MAILBOX_LIST_NOTIFY_RENAME;
	}
	if ((events & IMAP_NOTIFY_EVENT_SUBSCRIPTION_CHANGE) != 0) {
		ret |= MAILBOX_LIST_NOTIFY_SUBSCRIBE |
			MAILBOX_LIST_NOTIFY_UNSUBSCRIBE;
	}
	return ret;
}

static void imap_notify_callback(struct mailbox *box, struct client *client)
{
	struct client_command_context *cmd;
	enum mailbox_sync_flags sync_flags = 0;

	i_assert(client->command_queue_size == 0);
	i_assert(box == client->mailbox);

	/* create a fake command to handle this */
	cmd = client_command_alloc(client);
	cmd->tag = "*";
	cmd->name = "NOTIFY-CALLBACK";

	if (!client->notify_ctx->selected_immediate_expunges)
		sync_flags |= MAILBOX_SYNC_FLAG_NO_EXPUNGES;
	if (cmd_sync(cmd, sync_flags, 0, NULL))
		i_unreached();
	(void)cmd_sync_delayed(client);
}

static void imap_notify_watch_selected_mailbox(struct client *client)
{
	if (client->command_queue_size > 0) {
		/* don't add it until all commands are finished */
		return;
	}
	if (client->mailbox == NULL) {
		/* mailbox not selected */
		return;
	}
	if (client->notify_ctx == NULL || !client->notify_ctx->selected_set) {
		/* client doesn't want selected mailbox notifications */
		return;

	}
	mailbox_notify_changes(client->mailbox, imap_notify_callback, client);
	client->notify_ctx->watching_mailbox = TRUE;
}

static void imap_notify_watch_timeout(struct client *client)
{
	timeout_remove(&client->notify_ctx->to_watch);
	imap_notify_watch_selected_mailbox(client);
}

void imap_client_notify_command_freed(struct client *client)
{
	imap_notify_watch_selected_mailbox(client);
}

static void imap_notify_cmd_hook_pre(struct client_command_context *cmd)
{
	struct imap_notify_context *ctx = cmd->client->notify_ctx;

	if (ctx == NULL)
		return;

	/* remove mailbox watcher before starting any commands */
	if (ctx->watching_mailbox) {
		mailbox_notify_changes_stop(cmd->client->mailbox);
		ctx->watching_mailbox = FALSE;
	}
	if (ctx->to_watch != NULL)
		timeout_remove(&ctx->to_watch);
}

static void imap_notify_cmd_hook_post(struct client_command_context *cmd)
{
	struct imap_notify_context *ctx = cmd->client->notify_ctx;

	if (ctx == NULL)
		return;

	/* add mailbox watched back after a small delay */
	if (ctx->to_watch != NULL)
		timeout_reset(ctx->to_watch);
	else {
		ctx->to_watch = timeout_add(IMAP_NOTIFY_WATCH_ADD_DELAY_MSECS,
					    imap_notify_watch_timeout,
					    cmd->client);
	}
}

int imap_notify_begin(struct imap_notify_context *ctx)
{
	struct imap_notify_namespace *notify_ns;
	const struct imap_notify_mailboxes *notify_boxes;
	enum mailbox_list_notify_event notify_events;
	int ret = -1;

	if (!notify_hook_registered) {
		notify_hook_registered = TRUE;
		command_hook_register(imap_notify_cmd_hook_pre,
				      imap_notify_cmd_hook_post);
	}

	array_foreach_modifiable(&ctx->namespaces, notify_ns) {
		notify_events = 0;
		array_foreach(&notify_ns->mailboxes, notify_boxes) {
			notify_events |=
				imap_events_to_notify(notify_boxes->events);
		}
		if (mailbox_list_notify_init(notify_ns->ns->list, notify_events,
					     &notify_ns->notify) < 0) {
			/* notifications not supported */
		} else {
			ret = 0;
			mailbox_list_notify_wait(notify_ns->notify,
						 notify_callback, notify_ns);
		}
	}
	/* enable NOTIFY as long as even one namespace supports it,
	   ignore the rest */
	return ret;
}

void imap_notify_deinit(struct imap_notify_context **_ctx)
{
	struct imap_notify_context *ctx = *_ctx;
	struct imap_notify_namespace *notify_ns;

	*_ctx = NULL;

	array_foreach_modifiable(&ctx->namespaces, notify_ns) {
		if (notify_ns->notify != NULL)
			mailbox_list_notify_deinit(&notify_ns->notify);
	}
	if (ctx->to_watch != NULL)
		timeout_remove(&ctx->to_watch);
	if (ctx->fetch_ctx != NULL)
		imap_fetch_free(&ctx->fetch_ctx);
	pool_unref(&ctx->pool);
}
