/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage.h"
#include "mail-types.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-flagsset.h"
#include "push-notification-txn-msg.h"


#define EVENT_NAME "FlagsSet"

static struct push_notification_event_flagsset_config default_config;


static void *push_notification_event_flagsset_default_config(void)
{
	i_zero(&default_config);

	return &default_config;
}

static void
push_notification_event_flagsset_debug_msg(
	struct push_notification_txn_event *event)
{
	struct push_notification_event_flagsset_data *data = event->data;
	const char *const *keyword;

	if ((data->flags_set & MAIL_ANSWERED) != 0)
		i_debug("%s: Answered flag set", EVENT_NAME);
	if ((data->flags_set & MAIL_FLAGGED) != 0)
		i_debug("%s: Flagged flag set", EVENT_NAME);
	if ((data->flags_set & MAIL_DELETED) != 0)
		i_debug("%s: Deleted flag set", EVENT_NAME);
	if ((data->flags_set & MAIL_SEEN) != 0)
		i_debug("%s: Seen flag set", EVENT_NAME);
	if ((data->flags_set & MAIL_DRAFT) != 0)
		i_debug("%s: Draft flag set", EVENT_NAME);

	array_foreach(&data->keywords_set, keyword)
		i_debug("%s: Keyword set [%s]", EVENT_NAME, *keyword);
}

static struct push_notification_event_flagsset_data *
push_notification_event_flagsset_get_data(
	struct push_notification_txn *ptxn,
	struct push_notification_txn_msg *msg,
	struct push_notification_event_config *ec)
{
	struct push_notification_event_flagsset_data *data;

	data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
	if (data == NULL) {
		data = p_new(ptxn->pool,
			     struct push_notification_event_flagsset_data, 1);
		data->flags_set = 0;
		p_array_init(&data->keywords_set, ptxn->pool, 4);

		push_notification_txn_msg_set_eventdata(ptxn, msg, ec, data);
	}

	return data;
}

static void
push_notification_event_flagsset_flags_event(
	struct push_notification_txn *ptxn,
	struct push_notification_event_config *ec,
	struct push_notification_txn_msg *msg, struct mail *mail,
	enum mail_flags old_flags)
{
	struct push_notification_event_flagsset_config *config =
		(struct push_notification_event_flagsset_config *)ec->config;
	struct push_notification_event_flagsset_data *data;
	enum mail_flags flag_check_always[] = {
		MAIL_ANSWERED,
		MAIL_DRAFT,
		MAIL_FLAGGED
	};
	enum mail_flags flags, flags_set = 0;
	unsigned int i;

	flags = mail_get_flags(mail);

	for (i = 0; i < N_ELEMENTS(flag_check_always); i++) {
		if ((flags & flag_check_always[i]) != 0 &&
		    (old_flags & flag_check_always[i]) == 0)
			flags_set |= flag_check_always[i];
	}

	if (!config->hide_deleted && (flags & MAIL_DELETED) != 0 &&
	    (old_flags & MAIL_DELETED) == 0) {
		flags_set |= MAIL_DELETED;
	}

	if (!config->hide_seen && (flags & MAIL_SEEN) != 0 &&
	    (old_flags & MAIL_SEEN) == 0) {
		flags_set |= MAIL_SEEN;
	}

	/* Only create data element if at least one flag was set. */
	if (flags_set != 0) {
		data = push_notification_event_flagsset_get_data(ptxn, msg, ec);
		data->flags_set |= flags_set;
	}
}

static void
push_notification_event_flagsset_keywords_event(
	struct push_notification_txn *ptxn,
	struct push_notification_event_config *ec,
	struct push_notification_txn_msg *msg, struct mail *mail,
	const char *const *old_keywords)
{
	struct push_notification_event_flagsset_data *data;
	const char *k, *const *keywords, *const *op;

	data = push_notification_event_flagsset_get_data(ptxn, msg, ec);
	keywords = mail_get_keywords(mail);

	for (; *keywords != NULL; keywords++) {
		for (op = old_keywords; *op != NULL; op++) {
			if (strcmp(*keywords, *op) == 0)
				break;
		}

		if (*op == NULL) {
			k = p_strdup(ptxn->pool, *keywords);
			array_push_back(&data->keywords_set, &k);
		}
	}
}

static void
push_notification_event_flagsset_free_msg(
	struct push_notification_txn_event *event)
{
	struct push_notification_event_flagsset_data *data = event->data;

	if (array_is_created(&data->keywords_set))
	   array_free(&data->keywords_set);
}

/* Event definition */

extern struct push_notification_event push_notification_event_flagsset;

struct push_notification_event push_notification_event_flagsset = {
	.name = EVENT_NAME,
	.init = {
		.default_config =
			push_notification_event_flagsset_default_config,
	},
	.msg = {
		.debug_msg = push_notification_event_flagsset_debug_msg,
		.free_msg = push_notification_event_flagsset_free_msg,
	},
	.msg_triggers = {
		.flagchange = push_notification_event_flagsset_flags_event,
		.keywordchange =
			push_notification_event_flagsset_keywords_event,
	},
};
