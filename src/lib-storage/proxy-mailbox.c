/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "proxy-mailbox.h"

static int _is_readonly(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->is_readonly(p->box);
}

static int _allow_new_custom_flags(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->allow_new_custom_flags(p->box);
}

static int _close(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->close(p->box);
}

static int _lock(struct mailbox *box, enum mailbox_lock_type lock_type)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->lock(p->box, lock_type);
}

static int _get_status(struct mailbox *box, enum mailbox_status_items items,
		       struct mailbox_status *status)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->get_status(p->box, items, status);
}

static int _sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->sync(p->box, flags);
}

static void _auto_sync(struct mailbox *box, enum mailbox_sync_flags flags,
		       unsigned int min_newmail_notify_interval)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	p->box->auto_sync(p->box, flags, min_newmail_notify_interval);
}

static struct mail *_fetch_uid(struct mailbox *box, unsigned int uid,
			       enum mail_fetch_field wanted_fields)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->fetch_uid(p->box, uid, wanted_fields);
}

static struct mail *_fetch_seq(struct mailbox *box, unsigned int seq,
			       enum mail_fetch_field wanted_fields)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->fetch_uid(p->box, seq, wanted_fields);
}

static int _search_get_sorting(struct mailbox *box,
			       enum mail_sort_type *sort_program)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->search_get_sorting(p->box, sort_program);
}

static struct mail_search_context *
_search_init(struct mailbox *box, const char *charset,
	     struct mail_search_arg *args,
	     const enum mail_sort_type *sort_program,
	     enum mail_fetch_field wanted_fields,
	     const char *const wanted_headers[])
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->search_init(p->box, charset, args, sort_program,
				   wanted_fields, wanted_headers);
}

static struct mail_save_context *
_save_init(struct mailbox *box, int transaction)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->save_init(p->box, transaction);
}

static struct mail_copy_context *_copy_init(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->copy_init(p->box);
}

static struct mail_expunge_context *
_expunge_init(struct mailbox *box, enum mail_fetch_field wanted_fields,
	      int expunge_all)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->expunge_init(p->box, wanted_fields, expunge_all);
}

static int _is_inconsistency_error(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->is_inconsistency_error(p->box);
}

void proxy_mailbox_init(struct proxy_mailbox *proxy, struct mailbox *box)
{
	struct mailbox *pb = &proxy->proxy_box;

	proxy->box = box;

	pb->name = box->name;
	pb->storage = box->storage;

	pb->search_deinit = box->search_deinit;
	pb->search_next = box->search_next;
	pb->save_deinit = box->save_deinit;
	pb->save_next = box->save_next;
	pb->copy_deinit = box->copy_deinit;
	pb->expunge_deinit = box->expunge_deinit;
	pb->expunge_fetch_next = box->expunge_fetch_next;

	pb->is_readonly = _is_readonly;
	pb->allow_new_custom_flags = _allow_new_custom_flags;
	pb->close = _close;
	pb->lock = _lock;
	pb->get_status = _get_status;
	pb->sync = _sync;
	pb->auto_sync = _auto_sync;
	pb->fetch_uid = _fetch_uid;
	pb->fetch_seq = _fetch_seq;
	pb->search_get_sorting = _search_get_sorting;
	pb->search_init = _search_init;
	pb->save_init = _save_init;
	pb->copy_init = _copy_init;
	pb->expunge_init = _expunge_init;
	pb->is_inconsistency_error = _is_inconsistency_error;
}
