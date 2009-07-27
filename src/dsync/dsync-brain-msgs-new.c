/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "dsync-worker.h"
#include "dsync-brain-private.h"

struct dsync_brain_msg_copy_context {
	struct dsync_brain_msg_iter *iter;
	unsigned int msg_idx;
};

struct dsync_brain_msg_save_context {
	struct dsync_brain_msg_iter *iter;

	mailbox_guid_t mailbox;
	const struct dsync_message *msg;
};

static void
dsync_brain_msg_sync_retry_copies(struct dsync_brain_mailbox_sync *sync);

static bool
dsync_brain_msg_sync_is_save_done(struct dsync_brain_mailbox_sync *sync)
{
	return sync->src_msg_iter->copy_results_left == 0 &&
		sync->dest_msg_iter->copy_results_left == 0 &&
		sync->src_msg_iter->save_results_left == 0 &&
		sync->dest_msg_iter->save_results_left == 0;
}

static void msg_get_callback(enum dsync_msg_get_result result,
			     struct dsync_msg_static_data *data,
			     void *context)
{
	struct dsync_brain_msg_save_context *ctx = context;

	switch (result) {
	case DSYNC_MSG_GET_RESULT_SUCCESS:
		dsync_worker_select_mailbox(ctx->iter->worker, &ctx->mailbox);
		dsync_worker_msg_save(ctx->iter->worker, ctx->msg, data);
		break;
	case DSYNC_MSG_GET_RESULT_EXPUNGED:
		/* mail got expunged during sync. just skip this. */
		break;
	case DSYNC_MSG_GET_RESULT_FAILED:
		dsync_brain_fail(ctx->iter->sync->brain);
		break;
	}
	ctx->iter->save_results_left--;
}

static void dsync_brain_copy_callback(bool success, void *context)
{
	struct dsync_brain_msg_copy_context *ctx = context;
	const struct dsync_brain_new_msg *msg;
	struct dsync_brain_guid_instance *inst;

	ctx->iter->copy_results_left--;
	if (!success) {
		/* mark the guid instance invalid and try again later */
		msg = array_idx(&ctx->iter->new_msgs, ctx->msg_idx);
		inst = hash_table_lookup(ctx->iter->guid_hash, msg->msg->guid);
		inst->failed = TRUE;
		array_append(&ctx->iter->copy_retry_indexes, &ctx->msg_idx, 1);
	}

	if (dsync_brain_msg_sync_is_save_done(ctx->iter->sync)) {
		ctx->iter->sync->brain->state++;
		dsync_brain_sync(ctx->iter->sync->brain);
	}
}

static int
dsync_brain_msg_sync_add_new_msg(struct dsync_brain_msg_iter *dest_iter,
				 const mailbox_guid_t *src_mailbox,
				 unsigned int msg_idx,
				 const struct dsync_message *msg)
{
	struct dsync_brain_msg_save_context *save_ctx;
	struct dsync_brain_msg_copy_context *copy_ctx;
	struct dsync_brain_msg_iter *src_iter;
	const struct dsync_brain_guid_instance *inst;
	const struct dsync_brain_mailbox *inst_box;

	inst = hash_table_lookup(dest_iter->guid_hash, msg->guid);
	if (inst != NULL) {
		/* we can save this by copying an existing message */
		dsync_worker_select_mailbox(dest_iter->worker, src_mailbox);
		inst_box = array_idx(&dest_iter->sync->mailboxes,
				     inst->mailbox_idx);

		copy_ctx = p_new(dest_iter->sync->pool,
				 struct dsync_brain_msg_copy_context, 1);
		copy_ctx->iter = dest_iter;
		copy_ctx->msg_idx = msg_idx;

		dsync_worker_msg_copy(dest_iter->worker, &inst_box->box.guid,
				      inst->uid, msg, dsync_brain_copy_callback,
				      copy_ctx);
		dest_iter->copy_results_left++;
	} else {
		src_iter = dest_iter == dest_iter->sync->dest_msg_iter ?
			dest_iter->sync->src_msg_iter :
			dest_iter->sync->dest_msg_iter;

		save_ctx = p_new(src_iter->sync->pool,
				 struct dsync_brain_msg_save_context, 1);
		save_ctx->iter = dest_iter;
		save_ctx->mailbox = *src_mailbox;
		save_ctx->msg = dsync_message_dup(src_iter->sync->pool, msg);

		dsync_worker_select_mailbox(src_iter->worker, src_mailbox);
		dsync_worker_msg_get(src_iter->worker, msg->uid,
				     msg_get_callback, save_ctx);
		dest_iter->save_results_left++;
	}
	return dsync_worker_is_output_full(dest_iter->worker) ? 0 : 1;
}

static void
dsync_brain_msg_iter_add_new_msgs(struct dsync_brain_msg_iter *dest_iter)
{
	const struct dsync_brain_mailbox *mailboxes, *mailbox;
	const struct dsync_brain_new_msg *msgs;
	unsigned int i, mailbox_count, msg_count;

	mailboxes = array_get(&dest_iter->sync->mailboxes, &mailbox_count);
	msgs = array_get(&dest_iter->new_msgs, &msg_count);
	for (i = dest_iter->next_new_msg; i < msg_count; i++) {
		mailbox = &mailboxes[msgs[i].mailbox_idx];
		if (dsync_brain_msg_sync_add_new_msg(dest_iter,
						     &mailbox->box.guid, i,
						     msgs[i].msg) <= 0) {
			/* failed / continue later */
			dest_iter->next_new_msg = i + 1;
			break;
		}
	}
	dest_iter->msgs_sent = TRUE;
}

static void
dsync_brain_msg_sync_add_new_msgs(struct dsync_brain_msg_iter *iter)
{
	dsync_brain_msg_iter_add_new_msgs(iter);

	if (iter->sync->dest_msg_iter->msgs_sent &&
	    iter->sync->src_msg_iter->msgs_sent &&
	    dsync_brain_msg_sync_is_save_done(iter->sync))
		dsync_brain_msg_sync_retry_copies(iter->sync);
}

static void dsync_worker_new_msg_output(void *context)
{
	struct dsync_brain_msg_iter *iter = context;

	dsync_brain_msg_sync_add_new_msgs(iter);
}

static void
dsync_brain_msg_iter_sync_new_msgs(struct dsync_brain_msg_iter *iter)
{
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
dsync_brain_msg_iter_sync_retry_copies(struct dsync_brain_msg_iter *iter)
{
	const uint32_t *indexes;
	const struct dsync_brain_mailbox *mailboxes, *mailbox;
	const struct dsync_brain_new_msg *msgs;
	unsigned int i, msg_idx, idx_count, msg_count, mailbox_count;
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
	mailboxes = array_get(&iter->sync->mailboxes, &mailbox_count);
	for (i = 0; i < idx_count; i++) {
		msg_idx = indexes[i];
		mailbox = &mailboxes[msgs[msg_idx].mailbox_idx];
		(void)dsync_brain_msg_sync_add_new_msg(iter, &mailbox->box.guid,
						       msg_idx,
						       msgs[msg_idx].msg);
	}

	/* if we copied anything, we'll again have to wait for the results */
	array_clear(&iter->copy_retry_indexes);
	dsync_worker_set_output_callback(iter->worker, NULL, NULL);
}

static void
dsync_brain_msg_sync_retry_copies(struct dsync_brain_mailbox_sync *sync)
{
	dsync_brain_msg_iter_sync_retry_copies(sync->dest_msg_iter);
	dsync_brain_msg_iter_sync_retry_copies(sync->src_msg_iter);

	if (dsync_brain_msg_sync_is_save_done(sync)) {
		dsync_worker_set_input_callback(sync->src_worker, NULL, NULL);
		dsync_worker_set_input_callback(sync->dest_worker, NULL, NULL);
		sync->brain->state++;
		dsync_brain_sync(sync->brain);
	} else {
		/* temporarily move back the state. once copies have returned
		   success/failures, we'll get back to this function and see
		   if we need to retry again */
		sync->brain->state--;
	}
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
		dsync_worker_select_mailbox(iter->worker, &mailbox->box.guid);
		dsync_worker_msg_update_uid(iter->worker, conflicts[i].old_uid,
					    conflicts[i].new_uid);
	}
}

void dsync_brain_msg_sync_resolve_uid_conflicts(struct dsync_brain_mailbox_sync *sync)
{
	sync_iter_resolve_uid_conflicts(sync->src_msg_iter);
	sync_iter_resolve_uid_conflicts(sync->dest_msg_iter);
}
