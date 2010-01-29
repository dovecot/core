/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "hash.h"
#include "dsync-worker.h"
#include "dsync-brain-private.h"

struct dsync_brain_msg_copy_context {
	struct dsync_brain_msg_iter *iter;
	unsigned int msg_idx;
};

struct dsync_brain_msg_save_context {
	struct dsync_brain_msg_iter *iter;
	const struct dsync_message *msg;
	unsigned int mailbox_idx;
};

static void
dsync_brain_msg_sync_add_new_msgs(struct dsync_brain_msg_iter *iter);

static void msg_get_callback(enum dsync_msg_get_result result,
			     const struct dsync_msg_static_data *data,
			     void *context)
{
	struct dsync_brain_msg_save_context *ctx = context;
	const struct dsync_brain_mailbox *mailbox;
	struct istream *input;

	mailbox = array_idx(&ctx->iter->sync->mailboxes, ctx->mailbox_idx);
	switch (result) {
	case DSYNC_MSG_GET_RESULT_SUCCESS:
		/* the mailbox may have changed, make sure we've the
		   right one */
		dsync_worker_select_mailbox(ctx->iter->worker, &mailbox->box);

		input = data->input;
		dsync_worker_msg_save(ctx->iter->worker, ctx->msg, data);
		i_stream_unref(&input);
		break;
	case DSYNC_MSG_GET_RESULT_EXPUNGED:
		/* mail got expunged during sync. just skip this. */
		break;
	case DSYNC_MSG_GET_RESULT_FAILED:
		i_error("msg-get failed: box=%s uid=%u guid=%s",
			mailbox->box.name, ctx->msg->uid, ctx->msg->guid);
		dsync_brain_fail(ctx->iter->sync->brain);
		break;
	}
	if (--ctx->iter->save_results_left == 0 && !ctx->iter->adding_msgs)
		dsync_brain_msg_sync_add_new_msgs(ctx->iter);
}

static void dsync_brain_copy_callback(bool success, void *context)
{
	struct dsync_brain_msg_copy_context *ctx = context;
	const struct dsync_brain_new_msg *msg;
	struct dsync_brain_guid_instance *inst;

	if (!success) {
		/* mark the guid instance invalid and try again later */
		msg = array_idx(&ctx->iter->new_msgs, ctx->msg_idx);
		inst = hash_table_lookup(ctx->iter->guid_hash, msg->msg->guid);
		inst->failed = TRUE;
		array_append(&ctx->iter->copy_retry_indexes, &ctx->msg_idx, 1);
	}

	if (--ctx->iter->copy_results_left == 0 && !ctx->iter->adding_msgs)
		dsync_brain_msg_sync_add_new_msgs(ctx->iter);
}

static int
dsync_brain_msg_sync_add_new_msg(struct dsync_brain_msg_iter *dest_iter,
				 const mailbox_guid_t *src_mailbox,
				 unsigned int msg_idx,
				 const struct dsync_brain_new_msg *msg)
{
	struct dsync_brain_msg_save_context *save_ctx;
	struct dsync_brain_msg_copy_context *copy_ctx;
	struct dsync_brain_msg_iter *src_iter;
	const struct dsync_brain_guid_instance *inst;
	const struct dsync_brain_mailbox *inst_box;

	inst = hash_table_lookup(dest_iter->guid_hash, msg->msg->guid);
	if (inst != NULL) {
		/* we can save this by copying an existing message */
		inst_box = array_idx(&dest_iter->sync->mailboxes,
				     inst->mailbox_idx);

		copy_ctx = p_new(dest_iter->sync->pool,
				 struct dsync_brain_msg_copy_context, 1);
		copy_ctx->iter = dest_iter;
		copy_ctx->msg_idx = msg_idx;

		dsync_worker_msg_copy(dest_iter->worker,
				      &inst_box->box.mailbox_guid,
				      inst->uid, msg->msg,
				      dsync_brain_copy_callback, copy_ctx);
		dest_iter->copy_results_left++;
	} else {
		src_iter = dest_iter == dest_iter->sync->dest_msg_iter ?
			dest_iter->sync->src_msg_iter :
			dest_iter->sync->dest_msg_iter;

		save_ctx = p_new(src_iter->sync->pool,
				 struct dsync_brain_msg_save_context, 1);
		save_ctx->iter = dest_iter;
		save_ctx->msg = dsync_message_dup(src_iter->sync->pool,
						  msg->msg);
		save_ctx->mailbox_idx = dest_iter->mailbox_idx;

		dest_iter->adding_msgs = TRUE;
		dest_iter->save_results_left++;
		dsync_worker_msg_get(src_iter->worker, src_mailbox,
				     msg->orig_uid, msg_get_callback, save_ctx);
		dest_iter->adding_msgs = FALSE;
		if (dsync_worker_output_flush(src_iter->worker) < 0)
			return -1;
	}
	return dsync_worker_is_output_full(dest_iter->worker) ? 0 : 1;
}

static bool
dsync_brain_mailbox_add_new_msgs(struct dsync_brain_msg_iter *iter,
				 const mailbox_guid_t *mailbox_guid)
{
	const struct dsync_brain_new_msg *msgs;
	unsigned int i, msg_count;
	bool ret = TRUE;

	msgs = array_get(&iter->new_msgs, &msg_count);
	for (i = iter->next_new_msg; i < msg_count; i++) {
		if (msgs[i].mailbox_idx != iter->mailbox_idx) {
			i_assert(msgs[i].mailbox_idx > iter->mailbox_idx);
			ret = FALSE;
			break;
		}
		if (dsync_brain_msg_sync_add_new_msg(iter, mailbox_guid,
						     i, &msgs[i]) <= 0) {
			/* failed / continue later */
			i++;
			break;
		}
	}
	iter->next_new_msg = i;
	if (i == msg_count)
		ret = FALSE;

	/* flush copy commands */
	if (dsync_worker_output_flush(iter->worker) > 0 && ret) {
		/* we have more space again, continue */
		return dsync_brain_mailbox_add_new_msgs(iter, mailbox_guid);
	} else {
		return ret;
	}
}

static void
dsync_brain_mailbox_save_conflicts(struct dsync_brain_msg_iter *iter)
{
	const struct dsync_brain_uid_conflict *conflicts;
	unsigned int i, count;

	conflicts = array_get(&iter->uid_conflicts, &count);
	for (i = iter->next_conflict; i < count; i++) {
		if (conflicts[i].mailbox_idx != iter->mailbox_idx)
			break;

		dsync_worker_msg_update_uid(iter->worker, conflicts[i].old_uid,
					    conflicts[i].new_uid);
	}
	iter->next_conflict = i;
}

static void
dsync_brain_mailbox_retry_copies(struct dsync_brain_msg_iter *iter,
				 const mailbox_guid_t *mailbox_guid)
{
	const uint32_t *indexes;
	const struct dsync_brain_new_msg *msgs;
	unsigned int i, msg_idx, idx_count, msg_count;
	struct dsync_brain_guid_instance *inst;
	const char *guid_str;
	void *orig_key, *orig_value;

	/* first remove GUID instances that had failed. */
	msgs = array_get(&iter->new_msgs, &msg_count);
	indexes = array_get(&iter->copy_retry_indexes, &idx_count);
	for (i = 0; i < idx_count; i++) {
		guid_str = msgs[indexes[i]].msg->guid;
		if (hash_table_lookup_full(iter->guid_hash, guid_str,
					   &orig_key, &orig_value))
			inst = orig_value;
		else
			inst = NULL;
		if (inst != NULL && inst->failed) {
			inst = inst->next;
			if (inst == NULL)
				hash_table_remove(iter->guid_hash, guid_str);
			else {
				hash_table_update(iter->guid_hash, orig_key,
						  inst);
			}
		}
	}

	/* try saving again. there probably weren't many of them, so don't
	   worry about filling output buffer. */
	for (i = 0; i < idx_count; i++) {
		msg_idx = indexes[i];
		// FIXME: if buffer fills, we assert-crash
		(void)dsync_brain_msg_sync_add_new_msg(iter, mailbox_guid,
						       msg_idx, &msgs[msg_idx]);
	}

	/* if we copied anything, we'll again have to wait for the results */
	array_clear(&iter->copy_retry_indexes);
}

static void
dsync_brain_msg_sync_add_new_msgs(struct dsync_brain_msg_iter *iter)
{
	const struct dsync_brain_mailbox *mailbox;
	const mailbox_guid_t *mailbox_guid;

	while (iter->mailbox_idx < array_count(&iter->sync->mailboxes)) {
		mailbox = array_idx(&iter->sync->mailboxes, iter->mailbox_idx);
		mailbox_guid = &mailbox->box.mailbox_guid;

		if (array_count(&iter->new_msgs) == 0) {
			/* optimization: don't even bother selecting the
			   mailbox */
			iter->mailbox_idx++;
			continue;
		}

		dsync_worker_select_mailbox(iter->worker, &mailbox->box);

		if (dsync_brain_mailbox_add_new_msgs(iter, mailbox_guid)) {
			/* continue later */
			return;
		}

		/* all messages saved for this mailbox. continue with saving
		   its conflicts and waiting for copies to finish. */
		dsync_brain_mailbox_save_conflicts(iter);

		while (iter->copy_results_left == 0 &&
		       array_count(&iter->copy_retry_indexes) > 0)
			dsync_brain_mailbox_retry_copies(iter, mailbox_guid);

		if (iter->copy_results_left > 0) {
			/* wait for copies to finish */
			return;
		}

		/* done with this mailbox, try the next one */
		iter->mailbox_idx++;
	}
	iter->msgs_sent = TRUE;

	/* done with all mailboxes from this iter */
	dsync_worker_set_input_callback(iter->worker, NULL, NULL);

	if (iter->sync->src_msg_iter->msgs_sent &&
	    iter->sync->dest_msg_iter->msgs_sent &&
	    iter->sync->src_msg_iter->save_results_left == 0 &&
	    iter->sync->dest_msg_iter->save_results_left == 0 &&
	    dsync_worker_output_flush(iter->sync->dest_worker) > 0 &&
	    dsync_worker_output_flush(iter->sync->src_worker) > 0) {
		iter->sync->brain->state++;
		dsync_brain_sync(iter->sync->brain);
	}
}

static void dsync_worker_new_msg_output(void *context)
{
	struct dsync_brain_msg_iter *iter = context;

	dsync_brain_msg_sync_add_new_msgs(iter);
}

static int dsync_brain_new_msg_cmp(const struct dsync_brain_new_msg *m1,
				   const struct dsync_brain_new_msg *m2)
{
	if (m1->mailbox_idx < m2->mailbox_idx)
		return -1;
	if (m1->mailbox_idx > m2->mailbox_idx)
		return 1;

	if (m1->msg->uid < m2->msg->uid)
		return -1;
	if (m1->msg->uid > m2->msg->uid)
		return 1;
	return 0;
}

static int
dsync_brain_uid_conflict_cmp(const struct dsync_brain_uid_conflict *c1,
			     const struct dsync_brain_uid_conflict *c2)
{
	if (c1->mailbox_idx < c2->mailbox_idx)
	       return -1;
	if (c1->mailbox_idx < c2->mailbox_idx)
		return 1;

	if (c1->new_uid < c2->new_uid)
		return -1;
	if (c1->new_uid > c2->new_uid)
		return 1;
	return 0;
}

static void
dsync_brain_msg_iter_sync_new_msgs(struct dsync_brain_msg_iter *iter)
{
	iter->mailbox_idx = 0;

	array_sort(&iter->new_msgs, dsync_brain_new_msg_cmp);
	array_sort(&iter->uid_conflicts, dsync_brain_uid_conflict_cmp);

	dsync_worker_set_input_callback(iter->worker, NULL, iter);
	dsync_worker_set_output_callback(iter->worker,
					 dsync_worker_new_msg_output, iter);
	dsync_brain_msg_sync_add_new_msgs(iter);
}

void dsync_brain_msg_sync_new_msgs(struct dsync_brain_mailbox_sync *sync)
{
	dsync_brain_msg_iter_sync_new_msgs(sync->src_msg_iter);
	dsync_brain_msg_iter_sync_new_msgs(sync->dest_msg_iter);
}

static void
sync_iter_resolve_uid_conflicts(struct dsync_brain_msg_iter *iter)
{
	const struct dsync_brain_uid_conflict *conflicts;
	const struct dsync_brain_mailbox *mailboxes, *mailbox;
	unsigned int i, count, mailbox_count;

	mailboxes = array_get(&iter->sync->mailboxes, &mailbox_count);
	conflicts = array_get(&iter->uid_conflicts, &count);
	for (i = 0; i < count; i++) {
		mailbox = &mailboxes[conflicts[i].mailbox_idx];
		dsync_worker_select_mailbox(iter->worker, &mailbox->box);
		dsync_worker_msg_update_uid(iter->worker, conflicts[i].old_uid,
					    conflicts[i].new_uid);
	}
}

void dsync_brain_msg_sync_resolve_uid_conflicts(struct dsync_brain_mailbox_sync *sync)
{
	sync_iter_resolve_uid_conflicts(sync->src_msg_iter);
	sync_iter_resolve_uid_conflicts(sync->dest_msg_iter);
}
