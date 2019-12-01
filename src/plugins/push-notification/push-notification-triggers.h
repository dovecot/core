/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_TRIGGERS_H
#define PUSH_NOTIFICATION_TRIGGERS_H

#include "mail-types.h"

struct mail;
struct mailbox;
struct push_notification_txn;
struct push_notification_txn_mbox;
struct push_notification_txn_msg;

enum push_notification_event_trigger {
	PUSH_NOTIFICATION_EVENT_TRIGGER_NONE,

	/* Mailbox actions */
	PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_CREATE	   = 0x001,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_DELETE	   = 0x002,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_RENAME	   = 0x004,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MBOX_SUBSCRIBE	= 0x008,

	/* Message actions */
	PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_SAVE_NEW	  = 0x010,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_SAVE_APPEND   = 0x020,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_EXPUNGE	   = 0x040,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_FLAGCHANGE	= 0x080,
	PUSH_NOTIFICATION_EVENT_TRIGGER_MSG_KEYWORDCHANGE = 0x100,
};

/* Mailbox actions. */
void push_notification_trigger_mbox_create(
	struct push_notification_txn *txn, struct mailbox *box,
	struct push_notification_txn_mbox *mbox);
void push_notification_trigger_mbox_delete(
	struct push_notification_txn *txn, struct mailbox *box,
	struct push_notification_txn_mbox *mbox);
void push_notification_trigger_mbox_rename(
	struct push_notification_txn *txn,
	struct mailbox *src, struct mailbox *dest,
	struct push_notification_txn_mbox *mbox);
void push_notification_trigger_mbox_subscribe(
	struct push_notification_txn *txn, struct mailbox *box, bool subscribed,
	struct push_notification_txn_mbox *mbox);

/* Message actions. */
void push_notification_trigger_msg_save_new(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg);
void push_notification_trigger_msg_save_append(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg);
void push_notification_trigger_msg_save_expunge(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg);
void push_notification_trigger_msg_flag_change(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg, enum mail_flags old_flags);
void push_notification_trigger_msg_keyword_change(
	struct push_notification_txn *txn, struct mail *mail,
	struct push_notification_txn_msg *msg, const char *const *old_keywords);

#endif

