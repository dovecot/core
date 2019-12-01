/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_TXN_MBOX_H
#define PUSH_NOTIFICATION_TXN_MBOX_H

struct push_notification_txn_event;

struct push_notification_txn_mbox {
	const char *mailbox;

	ARRAY(struct push_notification_txn_event *) eventdata;
};

struct push_notification_txn_mbox *
push_notification_txn_mbox_create(struct push_notification_txn *txn,
				  struct mailbox *box);
void push_notification_txn_mbox_end(struct push_notification_txn *ptxn);

void *
push_notification_txn_mbox_get_eventdata(
	struct push_notification_txn_mbox *mbox, const char *event_name);
void push_notification_txn_mbox_set_eventdata(
	struct push_notification_txn *txn,
	struct push_notification_txn_mbox *mbox,
	struct push_notification_event_config *event, void *data);
void push_notification_txn_mbox_deinit_eventdata(
	struct push_notification_txn_mbox *mbox);

#endif
