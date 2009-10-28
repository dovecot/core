/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsync-worker-private.h"

void dsync_worker_deinit(struct dsync_worker **_worker)
{
	struct dsync_worker *worker = *_worker;

	*_worker = NULL;
	worker->v.deinit(worker);
}

void dsync_worker_set_input_callback(struct dsync_worker *worker,
				     io_callback_t *callback, void *context)
{
	worker->input_callback = callback;
	worker->input_context = context;
}

bool dsync_worker_is_output_full(struct dsync_worker *worker)
{
	return worker->v.is_output_full(worker);
}

void dsync_worker_set_output_callback(struct dsync_worker *worker,
				      io_callback_t *callback, void *context)
{
	worker->output_callback = callback;
	worker->output_context = context;
}

int dsync_worker_output_flush(struct dsync_worker *worker)
{
	return worker->v.output_flush(worker);
}

struct dsync_worker_mailbox_iter *
dsync_worker_mailbox_iter_init(struct dsync_worker *worker)
{
	return worker->v.mailbox_iter_init(worker);
}

int dsync_worker_mailbox_iter_next(struct dsync_worker_mailbox_iter *iter,
				   struct dsync_mailbox *dsync_box_r)
{
	return iter->worker->v.mailbox_iter_next(iter, dsync_box_r);
}

int dsync_worker_mailbox_iter_deinit(struct dsync_worker_mailbox_iter **_iter)
{
	struct dsync_worker_mailbox_iter *iter = *_iter;

	*_iter = NULL;
	return iter->worker->v.mailbox_iter_deinit(iter);
}

struct dsync_worker_msg_iter *
dsync_worker_msg_iter_init(struct dsync_worker *worker,
			   const mailbox_guid_t mailboxes[],
			   unsigned int mailbox_count)
{
	return worker->v.msg_iter_init(worker, mailboxes, mailbox_count);
}

int dsync_worker_msg_iter_next(struct dsync_worker_msg_iter *iter,
			       unsigned int *mailbox_idx_r,
			       struct dsync_message *msg_r)
{
	int ret;

	T_BEGIN {
		ret = iter->worker->v.msg_iter_next(iter, mailbox_idx_r, msg_r);
	} T_END;
	return ret;
}

int dsync_worker_msg_iter_deinit(struct dsync_worker_msg_iter **_iter)
{
	struct dsync_worker_msg_iter *iter = *_iter;

	*_iter = NULL;
	return iter->worker->v.msg_iter_deinit(iter);
}

void dsync_worker_create_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box)
{
	i_assert(dsync_box->uid_validity != 0 ||
		 mail_guid_128_is_empty(dsync_box->mailbox_guid.guid));
	worker->v.create_mailbox(worker, dsync_box);
}

void dsync_worker_delete_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox)
{
	worker->v.delete_mailbox(worker, mailbox);
}

void dsync_worker_rename_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox,
				 const char *name)
{
	worker->v.rename_mailbox(worker, mailbox, name);
}

void dsync_worker_update_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box)
{
	T_BEGIN {
		worker->v.update_mailbox(worker, dsync_box);
	} T_END;
}

void dsync_worker_select_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox)
{
	worker->v.select_mailbox(worker, mailbox);
}

void dsync_worker_msg_update_metadata(struct dsync_worker *worker,
				      const struct dsync_message *msg)
{
	if (!worker->failed)
		worker->v.msg_update_metadata(worker, msg);
}

void dsync_worker_msg_update_uid(struct dsync_worker *worker,
				 uint32_t old_uid, uint32_t new_uid)
{
	if (!worker->failed)
		worker->v.msg_update_uid(worker, old_uid, new_uid);
}

void dsync_worker_msg_expunge(struct dsync_worker *worker, uint32_t uid)
{
	if (!worker->failed)
		worker->v.msg_expunge(worker, uid);
}

void dsync_worker_msg_copy(struct dsync_worker *worker,
			   const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			   const struct dsync_message *dest_msg,
			   dsync_worker_copy_callback_t *callback,
			   void *context)
{
	if (!worker->failed) {
		worker->v.msg_copy(worker, src_mailbox, src_uid, dest_msg,
				   callback, context);
	}
}

void dsync_worker_msg_save(struct dsync_worker *worker,
			   const struct dsync_message *msg,
			   const struct dsync_msg_static_data *data)
{
	if (!worker->failed)
		worker->v.msg_save(worker, msg, data);
}

void dsync_worker_msg_save_cancel(struct dsync_worker *worker)
{
	worker->v.msg_save_cancel(worker);
}

void dsync_worker_msg_get(struct dsync_worker *worker,
			  const mailbox_guid_t *mailbox, uint32_t uid,
			  dsync_worker_msg_callback_t *callback, void *context)
{
	i_assert(uid != 0);

	if (!worker->failed)
		worker->v.msg_get(worker, mailbox, uid, callback, context);
}

void dsync_worker_finish(struct dsync_worker *worker,
			 dsync_worker_finish_callback_t *callback,
			 void *context)
{
	worker->v.finish(worker, callback, context);
}

void dsync_worker_set_failure(struct dsync_worker *worker)
{
	worker->failed = TRUE;
}

bool dsync_worker_has_failed(struct dsync_worker *worker)
{
	return worker->failed;
}
