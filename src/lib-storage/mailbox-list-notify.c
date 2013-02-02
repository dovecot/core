/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "mailbox-list-notify.h"

int mailbox_list_notify_init(struct mailbox_list *list,
			     enum mailbox_list_notify_event mask,
			     struct mailbox_list_notify **notify_r)
{
	if (list->v.notify_init == NULL)
		return -1;
	return list->v.notify_init(list, mask, notify_r);
}

void mailbox_list_notify_deinit(struct mailbox_list_notify **_notify)
{
	struct mailbox_list_notify *notify = *_notify;

	*_notify = NULL;

	notify->list->v.notify_deinit(notify);
}

int mailbox_list_notify_next(struct mailbox_list_notify *notify,
			     const struct mailbox_list_notify_rec **rec_r)
{
	return notify->list->v.notify_next(notify, rec_r);
}

void mailbox_list_notify_wait(struct mailbox_list_notify *notify,
			      void (*callback)(void *context), void *context)
{
	notify->list->v.notify_wait(notify, callback, context);
}
