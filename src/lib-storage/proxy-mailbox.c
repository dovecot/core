/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "proxy-mailbox.h"

#if 0
static int _is_readonly(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->is_readonly(p->box);
}

static int _allow_new_keywords(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->allow_new_keywords(p->box);
}

static int _close(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->close(p->box);
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

static struct mail *_fetch(struct mailbox_transaction_context *t, uint32_t seq,
			   enum mail_fetch_field wanted_fields)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) t->box;

	return box->fetch(t, seq, wanted_fields);
}

static int _get_uids(struct mailbox_transaction_context *t,
		     uint32_t uid1, uint32_t uid2,
		     uint32_t *seq1_r, uint32_t *seq2_r)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) t->box;

	return p->box->get_uids(p->box, uid1, uid2, seq1_r, seq2_r);
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

static struct mailbox_transaction_context *
_transaction_begin(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->transaction_begin(p->box);
}

static int _is_inconsistent(struct mailbox *box)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->is_inconsistent(p->box);
}

void proxy_mailbox_init(struct proxy_mailbox *proxy, struct mailbox *box)
{
	struct mailbox *pb = &proxy->proxy_box;

	proxy->box = box;

	pb->name = box->name;
	pb->storage = box->storage;

	pb->is_readonly = _is_readonly;
	pb->allow_new_keywords = _allow_new_keywords;
	pb->close = _close;
	pb->get_status = _get_status;
	pb->sync = _sync;
	pb->auto_sync = _auto_sync;
	pb->fetch = box->fetch;
	pb->get_uids = box->get_uids;

	pb->search_get_sorting = _search_get_sorting;
	pb->search_init = box->search_init;
	pb->search_next = box->search_next;
	pb->search_deinit = box->search_deinit;

	pb->transaction_begin = _transaction_begin;
	pb->transaction_commit = box->transaction_commit;
	pb->transaction_rollback = box->transaction_rollback;

	pb->save = box->save;
	pb->copy = box->copy;

	pb->is_inconsistent = _is_inconsistent;
}
#endif
