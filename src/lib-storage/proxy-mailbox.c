/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "proxy-mailbox.h"

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

static struct mailbox_sync_context *
_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->sync_init(p->box, flags);
}

static void _notify_changes(struct mailbox *box, unsigned int min_interval,
			    mailbox_notify_callback_t *callback, void *context)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->notify_changes(box, min_interval, callback, context);
}

static struct mail *_fetch(struct mailbox_transaction_context *t, uint32_t seq,
			   enum mail_fetch_field wanted_fields)
{
	struct proxy_mailbox_transaction_context *pt =
		(struct proxy_mailbox_transaction_context *)t;
	struct proxy_mailbox *pbox = (struct proxy_mailbox *)t->box;

	return pbox->box->fetch(pt->ctx, seq, wanted_fields);
}

static int _get_uids(struct mailbox *box, uint32_t uid1, uint32_t uid2,
		     uint32_t *seq1_r, uint32_t *seq2_r)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->get_uids(p->box, uid1, uid2, seq1_r, seq2_r);
}

static struct mailbox_header_lookup_ctx *
_header_lookup_init(struct mailbox *box, const char *const headers[])
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->header_lookup_init(p->box, headers);
}

static int _search_get_sorting(struct mailbox *box,
			       enum mail_sort_type *sort_program)
{
	struct proxy_mailbox *p = (struct proxy_mailbox *) box;

	return p->box->search_get_sorting(p->box, sort_program);
}

static struct mail_search_context *
_search_init(struct mailbox_transaction_context *t,
	     const char *charset, struct mail_search_arg *args,
	     const enum mail_sort_type *sort_program,
	     enum mail_fetch_field wanted_fields,
	     struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct proxy_mailbox_transaction_context *pt =
		(struct proxy_mailbox_transaction_context *)t;
	struct proxy_mailbox *pbox = (struct proxy_mailbox *)t->box;

	return pbox->box->search_init(pt->ctx, charset, args, sort_program,
				      wanted_fields, wanted_headers);
}

static int _transaction_commit(struct mailbox_transaction_context *t)
{
	struct proxy_mailbox_transaction_context *pt =
		(struct proxy_mailbox_transaction_context *)t;
	struct proxy_mailbox *pbox = (struct proxy_mailbox *)t->box;

	return pbox->box->transaction_commit(pt->ctx);
}

static void _transaction_rollback(struct mailbox_transaction_context *t)
{
	struct proxy_mailbox_transaction_context *pt =
		(struct proxy_mailbox_transaction_context *)t;
	struct proxy_mailbox *pbox = (struct proxy_mailbox *)t->box;

	pbox->box->transaction_rollback(pt->ctx);
}

static int _save(struct mailbox_transaction_context *t,
		 const struct mail_full_flags *flags,
		 time_t received_date, int timezone_offset,
		 const char *from_envelope, struct istream *data,
		 struct mail **mail_r)
{
	struct proxy_mailbox_transaction_context *pt =
		(struct proxy_mailbox_transaction_context *)t;
	struct proxy_mailbox *pbox = (struct proxy_mailbox *)t->box;

	return pbox->box->save(pt->ctx, flags, received_date, timezone_offset,
			       from_envelope, data, mail_r);
}

static int _copy(struct mailbox_transaction_context *t, struct mail *mail,
		 struct mail **dest_mail_r)
{
	struct proxy_mailbox_transaction_context *pt =
		(struct proxy_mailbox_transaction_context *)t;
	struct proxy_mailbox *pbox = (struct proxy_mailbox *)t->box;

	return pbox->box->copy(pt->ctx, mail, dest_mail_r);
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
	pb->sync_init = _sync_init;
	pb->sync_next = box->sync_next;
	pb->sync_deinit = box->sync_deinit;
	pb->notify_changes = _notify_changes;
	pb->fetch = _fetch;
	pb->get_uids = _get_uids;
	pb->header_lookup_init = _header_lookup_init;

	pb->search_get_sorting = _search_get_sorting;
	pb->search_init = _search_init;
	pb->search_next = box->search_next;
	pb->search_deinit = box->search_deinit;

	pb->transaction_begin = NULL; /* must be implemented */
	pb->transaction_commit = _transaction_commit;
	pb->transaction_rollback = _transaction_rollback;

	pb->save = _save;
	pb->copy = _copy;

	pb->is_inconsistent = _is_inconsistent;
}

void proxy_transaction_init(struct proxy_mailbox *proxy_box,
			    struct proxy_mailbox_transaction_context *proxy_ctx,
			    struct mailbox_transaction_context *ctx)
{
	proxy_ctx->proxy_ctx.box = &proxy_box->proxy_box;
	proxy_ctx->ctx = ctx;
}
