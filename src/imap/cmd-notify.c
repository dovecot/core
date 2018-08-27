/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "mailbox-list-iter.h"
#include "imap-quote.h"
#include "imap-commands.h"
#include "imap-fetch.h"
#include "imap-list.h"
#include "imap-status.h"
#include "imap-notify.h"

#define IMAP_NOTIFY_MAX_NAMES_PER_NS 100

static const char *imap_notify_event_names[] = {
	"MessageNew", "MessageExpunge", "FlagChange", "AnnotationChange",
	"MailboxName", "SubscriptionChange", "MailboxMetadataChange",
	"ServerMetadataChange"
};

static int
cmd_notify_parse_event(const struct imap_arg *arg,
		       enum imap_notify_event *event_r)
{
	const char *str;
	unsigned int i;

	if (!imap_arg_get_atom(arg, &str))
		return -1;

	for (i = 0; i < N_ELEMENTS(imap_notify_event_names); i++) {
		if (strcasecmp(str, imap_notify_event_names[i]) == 0) {
			*event_r = (enum imap_notify_event)(1 << i);
			return 0;
		}
	}
	return -1;
}

static int
cmd_notify_parse_fetch(struct imap_notify_context *ctx,
		       const struct imap_arg *list)
{
	if (list->type == IMAP_ARG_EOL)
		return -1; /* at least one attribute must be set */
	return imap_fetch_att_list_parse(ctx->client, ctx->pool, list,
					 &ctx->fetch_ctx, &ctx->error);
}

static int
cmd_notify_set_selected(struct imap_notify_context *ctx,
			const struct imap_arg *events)
{
#define EV_NEW_OR_EXPUNGE \
	(IMAP_NOTIFY_EVENT_MESSAGE_NEW | IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE)
	const struct imap_arg *list, *fetch_att_list;
	const char *str;
	enum imap_notify_event event;

	if (imap_arg_get_atom(events, &str) &&
	    strcasecmp(str, "NONE") == 0) {
		/* no events for selected mailbox. this is also the default
		   when NOTIFY command doesn't specify it explicitly */
		if (events[1].type != IMAP_ARG_EOL)
			return -1; /* no extra parameters */
		return 0;
	}

	if (!imap_arg_get_list(events, &list))
		return -1;
	if (events[1].type != IMAP_ARG_EOL)
		return -1; /* no extra parameters */
	if (list->type == IMAP_ARG_EOL)
		return -1; /* at least one event */

	for (; list->type != IMAP_ARG_EOL; list++) {
		if (cmd_notify_parse_event(list, &event) < 0)
			return -1;
		ctx->selected_events |= event;
		ctx->global_used_events |= event;

		if (event == IMAP_NOTIFY_EVENT_MESSAGE_NEW &&
		    imap_arg_get_list(&list[1], &fetch_att_list)) {
			/* MessageNew: list of fetch-att */
			if (cmd_notify_parse_fetch(ctx, fetch_att_list) < 0)
				return -1;
			list++;
		}
	}

	/* if MessageNew or MessageExpunge is specified, both of them must */
	if ((ctx->selected_events & EV_NEW_OR_EXPUNGE) != 0 &&
	    (ctx->selected_events & EV_NEW_OR_EXPUNGE) != EV_NEW_OR_EXPUNGE) {
		ctx->error = "MessageNew and MessageExpunge must be together";
		return -1;
	}

	/* if FlagChange or AnnotationChange is specified,
	   MessageNew and MessageExpunge must also be specified */
	if ((ctx->selected_events &
	     (IMAP_NOTIFY_EVENT_FLAG_CHANGE |
	      IMAP_NOTIFY_EVENT_ANNOTATION_CHANGE)) != 0 &&
	    (ctx->selected_events & IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE) == 0) {
		ctx->error = "FlagChange requires MessageNew and MessageExpunge";
		return -1;
	}
	return 0;
}

static struct imap_notify_namespace *
imap_notify_namespace_get(struct imap_notify_context *ctx,
			  struct mail_namespace *ns)
{
	struct imap_notify_namespace *notify_ns;

	array_foreach_modifiable(&ctx->namespaces, notify_ns) {
		if (notify_ns->ns == ns)
			return notify_ns;
	}
	notify_ns = array_append_space(&ctx->namespaces);
	notify_ns->ctx = ctx;
	notify_ns->ns = ns;
	p_array_init(&notify_ns->mailboxes, ctx->pool, 4);
	return notify_ns;
}

static struct imap_notify_mailboxes *
imap_notify_mailboxes_get(struct imap_notify_namespace *notify_ns,
			  enum imap_notify_type type,
			  enum imap_notify_event events)
{
	struct imap_notify_mailboxes *notify_boxes;

	array_foreach_modifiable(&notify_ns->mailboxes, notify_boxes) {
		if (notify_boxes->type == type &&
		    notify_boxes->events == events)
			return notify_boxes;
	}
	notify_boxes = array_append_space(&notify_ns->mailboxes);
	notify_boxes->type = type;
	notify_boxes->events = events;
	p_array_init(&notify_boxes->names, notify_ns->ctx->pool, 4);
	return notify_boxes;
}

static void
cmd_notify_add_mailbox(struct imap_notify_context *ctx,
		       struct mail_namespace *ns, const char *name,
		       enum imap_notify_type type,
		       enum imap_notify_event events)
{
	struct imap_notify_namespace *notify_ns;
	struct imap_notify_mailboxes *notify_boxes;
	const char *const *names;
	unsigned int i, count;
	size_t cur_len, name_len = strlen(name);
	char ns_sep = mail_namespace_get_sep(ns);

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    !str_begins(name, "INBOX") &&
	    strncasecmp(name, "INBOX", 5) == 0 &&
	    (name[5] == '\0' || name[5] == ns_sep)) {
		/* we'll do only case-sensitive comparisons later,
		   so sanitize INBOX to be uppercase */
		name = t_strconcat("INBOX", name + 5, NULL);
	}

	notify_ns = imap_notify_namespace_get(ctx, ns);
	notify_boxes = imap_notify_mailboxes_get(notify_ns, type, events);

	names = array_get(&notify_boxes->names, &count);
	for (i = 0; i < count; ) {
		if (strcmp(names[i], name) == 0) {
			/* exact duplicate, already added */
			return;
		}
		if (type != IMAP_NOTIFY_TYPE_SUBTREE)
			i++;
		else {
			/* see if one is a subtree of the other */
			cur_len = strlen(names[i]);
			if (str_begins(name, names[i]) &&
			    names[i][cur_len] == ns_sep) {
				/* already matched in this subtree */
				return;
			}
			if (strncmp(names[i], name, name_len) == 0 &&
			    names[i][name_len] == ns_sep) {
				/* we're adding a parent, remove the child */
				array_delete(&notify_boxes->names, i, 1);
				names = array_get(&notify_boxes->names, &count);
			} else {
				i++;
			}
		}
	}
	name = p_strdup(ctx->pool, name);
	array_push_back(&notify_boxes->names, &name);

	ctx->global_max_mailbox_names =
		I_MAX(ctx->global_max_mailbox_names,
		      array_count(&notify_boxes->names));
}

static void cmd_notify_add_personal(struct imap_notify_context *ctx,
				    enum imap_notify_event events)
{
	struct mail_namespace *ns;

	for (ns = ctx->client->user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type == MAIL_NAMESPACE_TYPE_PRIVATE) {
			cmd_notify_add_mailbox(ctx, ns, "",
				IMAP_NOTIFY_TYPE_SUBTREE, events);
		}
	}
}

static int
imap_notify_refresh_subscriptions(struct client_command_context *cmd,
				  struct imap_notify_context *ctx)
{
	struct mailbox_list_iterate_context *iter;
	struct mail_namespace *ns;

	if (!ctx->have_subscriptions)
		return 0;

	/* make sure subscriptions are refreshed at least once */
	for (ns = ctx->client->user->namespaces; ns != NULL; ns = ns->next) {
		iter = mailbox_list_iter_init(ns->list, "*", MAILBOX_LIST_ITER_SELECT_SUBSCRIBED);
		(void)mailbox_list_iter_next(iter);
		if (mailbox_list_iter_deinit(&iter) < 0) {
			client_send_list_error(cmd, ns->list);
			return -1;
		}
	}
	return 0;
}

static void cmd_notify_add_subscribed(struct imap_notify_context *ctx,
				      enum imap_notify_event events)
{
	struct mail_namespace *ns;

	ctx->have_subscriptions = TRUE;
	for (ns = ctx->client->user->namespaces; ns != NULL; ns = ns->next) {
		cmd_notify_add_mailbox(ctx, ns, "",
				       IMAP_NOTIFY_TYPE_SUBSCRIBED, events);
	}
}

static void
cmd_notify_add_mailbox_namespaces(struct imap_notify_context *ctx,
				  const char *name,
				  enum imap_notify_type type,
				  enum imap_notify_event events)
{
	struct mail_namespace *ns;

	ns = mail_namespace_find(ctx->client->user->namespaces, name);
	cmd_notify_add_mailbox(ctx, ns, name, type, events);
}

static int
cmd_notify_add_mailboxes(struct imap_notify_context *ctx,
			 const struct imap_arg *arg,
			 enum imap_notify_type type,
			 enum imap_notify_event events)
{
	const struct imap_arg *list;
	const char *name;

	if (imap_arg_get_astring(arg, &name)) {
		cmd_notify_add_mailbox_namespaces(ctx, name, type, events);
		return 0;
	}
	if (!imap_arg_get_list(arg, &list))
		return -1;

	for (; list->type != IMAP_ARG_EOL; list++) {
		if (!imap_arg_get_astring(list, &name))
			return -1;

		cmd_notify_add_mailbox_namespaces(ctx, name, type, events);
	}
	return 0;
}

static int
cmd_notify_set(struct imap_notify_context *ctx, const struct imap_arg *args)
{
	const struct imap_arg *event_group, *mailboxes, *list;
	const char *str, *filter_mailboxes;
	enum imap_notify_event event, event_mask;

	if (imap_arg_get_atom(args, &str) &&
	    strcasecmp(str, "STATUS") == 0) {
		/* send STATUS replies for all matched mailboxes before
		   NOTIFY's OK reply */
		ctx->send_immediate_status = TRUE;
		args++;
	}
	for (; args->type != IMAP_ARG_EOL; args++) {
		if (!imap_arg_get_list(args, &event_group))
			return -1;

		/* filter-mailboxes */
		if (!imap_arg_get_atom(event_group, &filter_mailboxes))
			return -1;
		event_group++;

		if (strcasecmp(filter_mailboxes, "selected") == 0 ||
		    strcasecmp(filter_mailboxes, "selected-delayed") == 0) {
			/* setting events for selected mailbox.
			   handle specially. */
			if (ctx->selected_set) {
				ctx->error = "Duplicate selected filter";
				return -1;
			}
			ctx->selected_set = TRUE;
			if (strcasecmp(filter_mailboxes, "selected") == 0)
				ctx->selected_immediate_expunges = TRUE;
			if (cmd_notify_set_selected(ctx, event_group) < 0)
				return -1;
			continue;
		}

		if (strcasecmp(filter_mailboxes, "subtree") == 0 ||
		    strcasecmp(filter_mailboxes, "mailboxes") == 0) {
			if (event_group->type == IMAP_ARG_EOL)
				return -1;
			mailboxes = event_group++;
			/* check that the mailboxes parameter is valid */
			if (IMAP_ARG_IS_ASTRING(mailboxes))
				;
			else if (!imap_arg_get_list(mailboxes, &list))
				return -1;
			else if (list->type == IMAP_ARG_EOL) {
				/* should have at least one mailbox */
				return -1;
			}
		} else {
			mailboxes = NULL;
		}

		/* parse events */
		if (imap_arg_get_atom(event_group, &str) &&
		    strcasecmp(str, "NONE") == 0) {
			/* NONE is the default, ignore this */
			continue;
		}
		if (!imap_arg_get_list(event_group, &list) ||
		    list[0].type == IMAP_ARG_EOL)
			return -1;

		event_mask = 0;
		for (; list->type != IMAP_ARG_EOL; list++) {
			if (cmd_notify_parse_event(list, &event) < 0)
				return -1;
			event_mask |= event;
			ctx->global_used_events |= event;
		}

		/* we can't currently know inboxes, so treat it the
		   same as personal */
		if (strcasecmp(filter_mailboxes, "inboxes") == 0 ||
		    strcasecmp(filter_mailboxes, "personal") == 0)
			cmd_notify_add_personal(ctx, event_mask);
		else if (strcasecmp(filter_mailboxes, "subscribed") == 0)
			cmd_notify_add_subscribed(ctx, event_mask);
		else if (strcasecmp(filter_mailboxes, "subtree") == 0) {
			if (cmd_notify_add_mailboxes(ctx, mailboxes,
						     IMAP_NOTIFY_TYPE_SUBTREE,
						     event_mask) < 0)
				return -1;
		} else if (strcasecmp(filter_mailboxes, "mailboxes") == 0) {
			if (cmd_notify_add_mailboxes(ctx, mailboxes,
						     IMAP_NOTIFY_TYPE_MAILBOX,
						     event_mask) < 0)
				return -1;
		} else {
			return -1;
		}
	}
	return 0;
}

static void
imap_notify_box_list_noperm(struct client *client, struct mailbox *box)
{
	string_t *str = t_str_new(128);
	char ns_sep = mail_namespace_get_sep(mailbox_get_namespace(box));
	enum mailbox_info_flags mailbox_flags;

	if (mailbox_list_mailbox(mailbox_get_namespace(box)->list,
				 mailbox_get_name(box), &mailbox_flags) < 0)
		mailbox_flags = 0;

	str_append(str, "* LIST (");
	if (imap_mailbox_flags2str(str, mailbox_flags))
		str_append_c(str, ' ');
	str_append(str, "\\NoAccess) \"");
	if (ns_sep == '\\')
		str_append_c(str, '\\');
	str_append_c(str, ns_sep);
	str_append(str, "\" ");

	imap_append_astring(str, mailbox_get_vname(box));
	client_send_line(client, str_c(str));
}

static void
imap_notify_box_send_status(struct client_command_context *cmd,
			    struct imap_notify_context *ctx,
			    const struct mailbox_info *info)
{
	struct mailbox *box;
	struct imap_status_items items;
	struct imap_status_result result;

	if ((info->flags & (MAILBOX_NONEXISTENT | MAILBOX_NOSELECT)) != 0)
		return;

	/* don't send STATUS to selected mailbox */
	if (cmd->client->mailbox != NULL &&
	    mailbox_equals(cmd->client->mailbox, info->ns, info->vname))
		return;

	i_zero(&items);
	i_zero(&result);

	items.flags = IMAP_STATUS_ITEM_UIDVALIDITY | IMAP_STATUS_ITEM_UIDNEXT |
		IMAP_STATUS_ITEM_MESSAGES | IMAP_STATUS_ITEM_UNSEEN;
	if ((ctx->global_used_events & (IMAP_NOTIFY_EVENT_FLAG_CHANGE |
					IMAP_NOTIFY_EVENT_ANNOTATION_CHANGE)) != 0)
		items.flags |= IMAP_STATUS_ITEM_HIGHESTMODSEQ;

	box = mailbox_alloc(info->ns->list, info->vname, MAILBOX_FLAG_READONLY);
	mailbox_set_reason(box, "NOTIFY send STATUS");
	(void)mailbox_enable(box, client_enabled_mailbox_features(ctx->client));

	if (imap_status_get(cmd, info->ns, info->vname, &items, &result) < 0) {
		if (result.error == MAIL_ERROR_PERM)
			imap_notify_box_list_noperm(ctx->client, box);
		else if (result.error != MAIL_ERROR_NOTFOUND) {
			client_send_line(ctx->client,
				t_strconcat("* ", result.errstr, NULL));
		}
	} else {
		imap_status_send(ctx->client, info->vname, &items, &result);
	}
	mailbox_free(&box);
}

static bool imap_notify_ns_want_status(struct imap_notify_namespace *notify_ns)
{
	const struct imap_notify_mailboxes *notify_boxes;

	array_foreach(&notify_ns->mailboxes, notify_boxes) {
		if ((notify_boxes->events &
		     (IMAP_NOTIFY_EVENT_MESSAGE_NEW |
		      IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE |
		      IMAP_NOTIFY_EVENT_ANNOTATION_CHANGE |
		      IMAP_NOTIFY_EVENT_FLAG_CHANGE)) != 0)
			return TRUE;
	}
	return FALSE;
}

static void
imap_notify_ns_send_status(struct client_command_context *cmd,
			   struct imap_notify_context *ctx,
			   struct imap_notify_namespace *notify_ns)
{
	struct mailbox_list_iterate_context *iter;
	const struct imap_notify_mailboxes *notify_boxes;
	const struct mailbox_info *info;

	if (!imap_notify_ns_want_status(notify_ns))
		return;

	/* set _RETURN_SUBSCRIBED flag just in case IMAP_NOTIFY_TYPE_SUBSCRIBED
	   is used, which requires refreshing subscriptions */
	iter = mailbox_list_iter_init(notify_ns->ns->list, "*",
				      MAILBOX_LIST_ITER_RETURN_SUBSCRIBED |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		array_foreach(&notify_ns->mailboxes, notify_boxes) {
			if (imap_notify_match_mailbox(notify_ns, notify_boxes,
						      info->vname)) {
				imap_notify_box_send_status(cmd, ctx, info);
				break;
			}
		}
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		client_send_line(notify_ns->ctx->client,
				 "* NO Mailbox listing failed");
	}
}

static void cmd_notify_send_status(struct client_command_context *cmd,
				   struct imap_notify_context *ctx)
{
	struct imap_notify_namespace *notify_ns;

	array_foreach_modifiable(&ctx->namespaces, notify_ns)
		imap_notify_ns_send_status(cmd, ctx, notify_ns);
}

bool cmd_notify(struct client_command_context *cmd)
{
	struct imap_notify_context *ctx;
	const struct imap_arg *args;
	const char *str;
	int ret = 0;
	pool_t pool;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	pool = pool_alloconly_create("imap notify context", 1024);
	ctx = p_new(pool, struct imap_notify_context, 1);
	ctx->pool = pool;
	ctx->client = cmd->client;
	p_array_init(&ctx->namespaces, pool, 4);

	if (!imap_arg_get_atom(&args[0], &str))
		ret = -1;
	else if (strcasecmp(str, "NONE") == 0)
		;
	else if (strcasecmp(str, "SET") == 0)
		ret = cmd_notify_set(ctx, args+1);
	else
		ret = -1;

	if (ret < 0) {
		client_send_command_error(cmd, ctx->error != NULL ? ctx->error :
					  "Invalid arguments.");
		pool_unref(&pool);
		return TRUE;
	}

	if ((ctx->global_used_events & UNSUPPORTED_EVENTS) != 0) {
		string_t *client_error = t_str_new(128);
		unsigned int i;

		str_append(client_error, "NO [BADEVENT");
		for (i = 0; i < N_ELEMENTS(imap_notify_event_names); i++) {
			if ((ctx->global_used_events & (1 << i)) != 0 &&
			    ((1 << i) & UNSUPPORTED_EVENTS) != 0) {
				str_append_c(client_error, ' ');
				str_append(client_error, imap_notify_event_names[i]);
			}
		}
		str_append(client_error, "] Unsupported NOTIFY events.");
		client_send_tagline(cmd, str_c(client_error));
		pool_unref(&pool);
		return TRUE;
	}

	if (array_count(&ctx->namespaces) == 0) {
		/* selected mailbox only */
	} else if (ctx->global_max_mailbox_names > IMAP_NOTIFY_MAX_NAMES_PER_NS) {
		client_send_tagline(cmd,
			"NO [NOTIFICATIONOVERFLOW] Too many mailbox names");
		pool_unref(&pool);
		return TRUE;
	} else if (imap_notify_refresh_subscriptions(cmd, ctx) < 0) {
		/* tagline already sent */
		pool_unref(&pool);
		return TRUE;
	} else if (imap_notify_begin(ctx) < 0) {
		client_send_tagline(cmd,
			"NO [NOTIFICATIONOVERFLOW] NOTIFY not supported for these mailboxes.");
		pool_unref(&pool);
		return TRUE;
	}
	if (cmd->client->notify_ctx != NULL)
		imap_notify_deinit(&cmd->client->notify_ctx);

	if (ctx->send_immediate_status)
		cmd_notify_send_status(cmd, ctx);
	cmd->client->notify_immediate_expunges =
		ctx->selected_immediate_expunges;
	cmd->client->notify_count_changes =
		(ctx->selected_events & IMAP_NOTIFY_EVENT_MESSAGE_NEW) != 0;
	cmd->client->notify_flag_changes =
		(ctx->selected_events & IMAP_NOTIFY_EVENT_FLAG_CHANGE) != 0;

	cmd->client->notify_ctx = ctx;
	return cmd_sync(cmd, 0, IMAP_SYNC_FLAG_SAFE, "OK NOTIFY completed.");
}
