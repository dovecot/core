/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "dsync-worker-private.h"

void dsync_worker_deinit(struct dsync_worker **_worker)
{
	struct dsync_worker *worker = *_worker;

	*_worker = NULL;
	worker->v.deinit(worker);
}

void dsync_worker_set_readonly(struct dsync_worker *worker)
{
	worker->readonly = TRUE;
}

void dsync_worker_set_verbose(struct dsync_worker *worker)
{
	worker->verbose = TRUE;
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
	int ret;

	T_BEGIN {
		ret = iter->worker->v.mailbox_iter_next(iter, dsync_box_r);
	} T_END;
	return ret;
}

int dsync_worker_mailbox_iter_deinit(struct dsync_worker_mailbox_iter **_iter)
{
	struct dsync_worker_mailbox_iter *iter = *_iter;

	*_iter = NULL;
	return iter->worker->v.mailbox_iter_deinit(iter);
}

struct dsync_worker_subs_iter *
dsync_worker_subs_iter_init(struct dsync_worker *worker)
{
	return worker->v.subs_iter_init(worker);
}

int dsync_worker_subs_iter_next(struct dsync_worker_subs_iter *iter,
				struct dsync_worker_subscription *rec_r)
{
	return iter->worker->v.subs_iter_next(iter, rec_r);
}

int dsync_worker_subs_iter_next_un(struct dsync_worker_subs_iter *iter,
				   struct dsync_worker_unsubscription *rec_r)
{
	return iter->worker->v.subs_iter_next_un(iter, rec_r);
}

int dsync_worker_subs_iter_deinit(struct dsync_worker_subs_iter **_iter)
{
	struct dsync_worker_subs_iter *iter = *_iter;

	*_iter = NULL;
	return iter->worker->v.subs_iter_deinit(iter);
}

void dsync_worker_set_subscribed(struct dsync_worker *worker,
				 const char *name, time_t last_change, bool set)
{
	worker->v.set_subscribed(worker, name, last_change, set);
}

struct dsync_worker_msg_iter *
dsync_worker_msg_iter_init(struct dsync_worker *worker,
			   const mailbox_guid_t mailboxes[],
			   unsigned int mailbox_count)
{
	i_assert(mailbox_count > 0);
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
		 dsync_mailbox_is_noselect(dsync_box));

	if (!worker->readonly) T_BEGIN {
		worker->v.create_mailbox(worker, dsync_box);
	} T_END;
}

void dsync_worker_delete_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box)
{
	if (!worker->readonly) T_BEGIN {
		worker->v.delete_mailbox(worker, dsync_box);
	} T_END;
}

void dsync_worker_delete_dir(struct dsync_worker *worker,
			     const struct dsync_mailbox *dsync_box)
{
	if (!worker->readonly) T_BEGIN {
		worker->v.delete_dir(worker, dsync_box);
	} T_END;
}

void dsync_worker_rename_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox,
				 const struct dsync_mailbox *dsync_box)
{
	if (!worker->readonly) T_BEGIN {
		worker->v.rename_mailbox(worker, mailbox, dsync_box);
	} T_END;
}

void dsync_worker_update_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box)
{
	if (!worker->readonly) T_BEGIN {
		worker->v.update_mailbox(worker, dsync_box);
	} T_END;
}

void dsync_worker_select_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *box)
{
	T_BEGIN {
		worker->v.select_mailbox(worker, &box->mailbox_guid,
					 &box->cache_fields);
	} T_END;
}

void dsync_worker_msg_update_metadata(struct dsync_worker *worker,
				      const struct dsync_message *msg)
{
	if (!worker->failed && !worker->readonly)
		worker->v.msg_update_metadata(worker, msg);
}

void dsync_worker_msg_update_uid(struct dsync_worker *worker,
				 uint32_t old_uid, uint32_t new_uid)
{
	if (!worker->failed && !worker->readonly)
		worker->v.msg_update_uid(worker, old_uid, new_uid);
}

void dsync_worker_msg_expunge(struct dsync_worker *worker, uint32_t uid)
{
	if (!worker->failed && !worker->readonly)
		worker->v.msg_expunge(worker, uid);
}

void dsync_worker_msg_copy(struct dsync_worker *worker,
			   const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			   const struct dsync_message *dest_msg,
			   dsync_worker_copy_callback_t *callback,
			   void *context)
{
	if (!worker->failed && !worker->readonly) {
		T_BEGIN {
			worker->v.msg_copy(worker, src_mailbox, src_uid,
					   dest_msg, callback, context);
		} T_END;
	} else {
		callback(FALSE, context);
	}
}

void dsync_worker_msg_save(struct dsync_worker *worker,
			   const struct dsync_message *msg,
			   const struct dsync_msg_static_data *data,
			   dsync_worker_save_callback_t *callback,
			   void *context)
{
	if (!worker->readonly) {
		if (worker->failed)
			callback(context);
		else T_BEGIN {
			worker->v.msg_save(worker, msg, data,
					   callback, context);
		} T_END;
	} else {
		const unsigned char *d;
		size_t size;

		while ((i_stream_read_data(data->input, &d, &size, 0)) > 0)
			i_stream_skip(data->input, size);
		callback(context);
	}
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

	if (worker->failed)
		callback(DSYNC_MSG_GET_RESULT_FAILED, NULL, context);
	else T_BEGIN {
		worker->v.msg_get(worker, mailbox, uid, callback, context);
	} T_END;
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

bool dsync_worker_has_unexpected_changes(struct dsync_worker *worker)
{
	return worker->unexpected_changes;
}
