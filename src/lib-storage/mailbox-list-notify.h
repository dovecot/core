#ifndef MAILBOX_LIST_NOTIFY_H
#define MAILBOX_LIST_NOTIFY_H

#include "guid.h"

struct mailbox_list_notify;

enum mailbox_list_notify_event {
	MAILBOX_LIST_NOTIFY_CREATE		= 0x01,
	MAILBOX_LIST_NOTIFY_DELETE		= 0x02,
	MAILBOX_LIST_NOTIFY_RENAME		= 0x04,
	MAILBOX_LIST_NOTIFY_SUBSCRIBE		= 0x08,
	MAILBOX_LIST_NOTIFY_UNSUBSCRIBE		= 0x10,

	MAILBOX_LIST_NOTIFY_UIDVALIDITY		= 0x20,
	MAILBOX_LIST_NOTIFY_APPENDS		= 0x40,
	MAILBOX_LIST_NOTIFY_EXPUNGES		= 0x80,
	MAILBOX_LIST_NOTIFY_SEEN_CHANGES	= 0x100,
	MAILBOX_LIST_NOTIFY_MODSEQ_CHANGES	= 0x200
#define MAILBOX_LIST_NOTIFY_STATUS \
	(MAILBOX_LIST_NOTIFY_APPENDS | \
	 MAILBOX_LIST_NOTIFY_EXPUNGES | \
	 MAILBOX_LIST_NOTIFY_SEEN_CHANGES | \
	 MAILBOX_LIST_NOTIFY_MODSEQ_CHANGES)
};

struct mailbox_list_notify {
	struct mailbox_list *list;
	enum mailbox_list_notify_event mask;
};

struct mailbox_list_notify_rec {
	/* Each record can contain multiple events */
	enum mailbox_list_notify_event events;

	/* For all events: */
	const char *storage_name, *vname;
	/* For selectable mailboxes: */
	guid_128_t guid;

	/* For rename: */
	const char *old_vname;
};

typedef void mailbox_list_notify_callback_t(void *);

/* Monitor for specified changes in the mailbox list.
   Returns 0 if ok, -1 if notifications aren't supported. */
int mailbox_list_notify_init(struct mailbox_list *list,
			     enum mailbox_list_notify_event mask,
			     struct mailbox_list_notify **notify_r);
void mailbox_list_notify_deinit(struct mailbox_list_notify **notify);

/* Get the next change. Returns 1 if record was returned, 0 if there are no
   more changes currently or -1 if some error occurred */
int mailbox_list_notify_next(struct mailbox_list_notify *notify,
			     const struct mailbox_list_notify_rec **rec_r);
/* Call the specified callback when something changes. */
void mailbox_list_notify_wait(struct mailbox_list_notify *notify,
			      mailbox_list_notify_callback_t *callback, void *context);
#define mailbox_list_notify_wait(notify, callback, context) \
	mailbox_list_notify_wait(notify - CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
				(mailbox_list_notify_callback_t*)callback, context);
/* Flush any delayed notifications now. */
void mailbox_list_notify_flush(struct mailbox_list_notify *notify);

#endif
