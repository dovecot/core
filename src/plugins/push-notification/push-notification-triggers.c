/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

#include "mail-storage.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-triggers.h"
#include "push-notification-txn-mbox.h"
#include "push-notification-txn-msg.h"

static void
push_notification_trigger_mbox_common(
	struct push_notification_txn *txn, struct mailbox *box,
	struct push_notification_txn_mbox **mbox,
	enum push_notification_event_trigger trigger)
{
	if (*mbox == NULL) {
		*mbox = push_notification_txn_mbox_create(txn, box);
	}

	txn->trigger |= trigger;
}

void push_notification_trigger_mbox_create(
	struct push_notification_txn *txn, struct mailbox *box,
	struct push_notification_txn_mbox *mbox)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_mbox_common(
		txn, box, &mbox, PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_CREATE);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->mbox_triggers.create != NULL) {
				(*ec)->event->mbox_triggers.create(
					txn, *ec, mbox);
			}
		}
	}
}

void push_notification_trigger_mbox_delete(
	struct push_notification_txn *txn, struct mailbox *box,
	struct push_notification_txn_mbox *mbox)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_mbox_common(
		txn, box, &mbox, PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_DELETE);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->mbox_triggers.delete != NULL) {
				(*ec)->event->mbox_triggers.delete(
					txn, *ec, mbox);
			}
		}
	}
}

void push_notification_trigger_mbox_rename(
	struct push_notification_txn *txn,
	struct mailbox *src, struct mailbox *dest,
	struct push_notification_txn_mbox *mbox)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_mbox_common(
		txn, dest, &mbox, PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_RENAME);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->mbox_triggers.rename != NULL) {
				(*ec)->event->mbox_triggers.rename(
					txn, *ec, mbox, src);
			}
		}
	}
}

void push_notification_trigger_mbox_subscribe(
	struct push_notification_txn *txn, struct mailbox *box, bool subscribed,
	struct push_notification_txn_mbox *mbox)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_mbox_common(
		txn, box, &mbox,
		PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_SUBSCRIBE);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if (subscribed == TRUE) {
				if ((*ec)->event->mbox_triggers.subscribe != NULL) {
					(*ec)->event->mbox_triggers.subscribe(
						txn, *ec, mbox);
				}
			} else {
				if ((*ec)->event->mbox_triggers.unsubscribe != NULL) {
					(*ec)->event->mbox_triggers.unsubscribe(
						txn, *ec, mbox);
				}
			}
		}
	}
}

static void
push_notification_trigger_msg_common(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg **msg,
	enum push_notification_event_trigger trigger)
{
	if (*msg == NULL)
		*msg = push_notification_txn_msg_create(txn, mail);

	txn->trigger |= trigger;
}

void push_notification_trigger_msg_save_new(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_msg_common(
		txn, mail, &msg, PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_SAVE_NEW);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->msg_triggers.save != NULL) {
				(*ec)->event->msg_triggers.save(
					txn, *ec, msg, mail);
			}
		}
	}
}

void push_notification_trigger_msg_save_append(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_msg_common(
		txn, mail, &msg,
		PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_SAVE_APPEND);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->msg_triggers.append != NULL) {
				(*ec)->event->msg_triggers.append(
					txn, *ec, msg, mail);
			}
		}
	}
}

void push_notification_trigger_msg_save_expunge(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_msg_common(
		txn, mail, &msg, PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_EXPUNGE);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->msg_triggers.expunge != NULL) {
				(*ec)->event->msg_triggers.expunge(
					txn, *ec, msg);
			}
		}
	}
}

void push_notification_trigger_msg_flag_change(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg, enum mail_flags old_flags)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_msg_common(
		txn, mail, &msg,
		PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_FLAGCHANGE);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->msg_triggers.flagchange != NULL) {
				(*ec)->event->msg_triggers.flagchange(
					txn, *ec, msg, mail, old_flags);
			}
		}
	}
}

void push_notification_trigger_msg_keyword_change(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg, const char *const *old_keywords)
{
	struct push_notification_event_config **ec;

	push_notification_trigger_msg_common(
		txn, mail, &msg,
		PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_KEYWORDCHANGE);

	if (array_is_created(&txn->events)) {
		array_foreach_modifiable(&txn->events, ec) {
			if ((*ec)->event->msg_triggers.keywordchange != NULL) {
				(*ec)->event->msg_triggers.keywordchange(
					txn, *ec, msg, mail, old_keywords);
			}
		}
	}
}
