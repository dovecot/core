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

void dsync_worker_set_next_result_tag(struct dsync_worker *worker,
				      uint32_t tag)
{
	i_assert(tag != 0);
	i_assert(worker->next_tag == 0);
	worker->next_tag = tag;
}

void dsync_worker_verify_result_is_clear(struct dsync_worker *worker)
{
	i_assert(worker->next_tag == 0);
}

bool dsync_worker_get_next_result(struct dsync_worker *worker,
				  uint32_t *tag_r, int *result_r)
{
	return worker->v.get_next_result(worker, tag_r, result_r);
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
	return iter->worker->v.msg_iter_next(iter, mailbox_idx_r, msg_r);
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
	worker->v.create_mailbox(worker, dsync_box);
}

void dsync_worker_update_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box)
{
	worker->v.update_mailbox(worker, dsync_box);
}

void dsync_worker_select_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox)
{
	worker->v.select_mailbox(worker, mailbox);
}

void dsync_worker_msg_update_metadata(struct dsync_worker *worker,
				      const struct dsync_message *msg)
{
	worker->v.msg_update_metadata(worker, msg);
}

void dsync_worker_msg_update_uid(struct dsync_worker *worker, uint32_t uid)
{
	worker->v.msg_update_uid(worker, uid);
}

void dsync_worker_msg_expunge(struct dsync_worker *worker, uint32_t uid)
{
	worker->v.msg_expunge(worker, uid);
}

void dsync_worker_msg_copy(struct dsync_worker *worker,
			   const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			   const struct dsync_message *dest_msg)
{
	worker->v.msg_copy(worker, src_mailbox, src_uid, dest_msg);
}

void dsync_worker_msg_save(struct dsync_worker *worker,
			   const struct dsync_message *msg,
			   struct dsync_msg_static_data *data)
{
	worker->v.msg_save(worker, msg, data);
}

int dsync_worker_msg_get(struct dsync_worker *worker, uint32_t uid,
			 struct dsync_msg_static_data *data_r)
{
	return worker->v.msg_get(worker, uid, data_r);
}
