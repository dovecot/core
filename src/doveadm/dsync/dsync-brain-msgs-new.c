/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

/*
   This code contains the step 6 explained in dsync-brain-msgs.c:
   It saves/copies new messages and gives new UIDs for conflicting messages.

   The input is both workers' msg iterators' new_msgs and uid_conflicts
   variables. They're first sorted by mailbox and secondarily by wanted
   destination UID. Destination UIDs of conflicts should always be higher
   than new messages'.

   Mailboxes are handled one at a time:

   1. Go through all saved messages. If we've already seen an instance of this
      message, try to copy it. Otherwise save a new instance of it.
   2. Some of the copies may fail because they're already expunged by that
      time. A list of these failed copies are saved to copy_retry_indexes.
   3. UID conflicts are resolved by assigning a new UID to the message.
      To avoid delays with remote dsync, this is done via worker API.
      Internally the local worker copies the message to its new UID and
      once the copy succeeds, the old UID is expunged. If the copy fails, it's
      either due to message already being expunged or something more fatal.
   4. Once all messages are saved/copied, see if there are any failed copies.
      If so, goto 1, but going through only the failed messages.
   5. If there are more mailboxes left, go to next one and goto 1.

   Step 4 may require waiting for remote worker to send all replies.
*/

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

static void msg_save_callback(void *context)
{
	struct dsync_brain_msg_save_context *ctx = context;

	if (--ctx->iter->save_results_left == 0 && !ctx->iter->adding_msgs)
		dsync_brain_msg_sync_add_new_msgs(ctx->iter);
	i_free(ctx);
}

static void msg_get_callback(enum dsync_msg_get_result result,
			     const struct dsync_msg_static_data *data,
			     void *context)
{
	struct dsync_brain_msg_save_context *ctx = context;
	const struct dsync_brain_mailbox *mailbox;
	struct istream *input;

	i_assert(ctx->iter->save_results_left > 0);

	mailbox = array_idx(&ctx->iter->sync->mailboxes, ctx->mailbox_idx);
	switch (result) {
	case DSYNC_MSG_GET_RESULT_SUCCESS:
		/* the mailbox may have changed, make sure we've the
		   right one */
		dsync_worker_select_mailbox(ctx->iter->worker, &mailbox->box);

		input = data->input;
		dsync_worker_msg_save(ctx->iter->worker, ctx->msg, data,
				      msg_save_callback, ctx);
		i_stream_unref(&input);
		break;
	case DSYNC_MSG_GET_RESULT_EXPUNGED:
		/* mail got expunged during sync. just skip this. */
		msg_save_callback(ctx);
		break;
	case DSYNC_MSG_GET_RESULT_FAILED:
		i_error("msg-get failed: box=%s uid=%u guid=%s",
			mailbox->box.name, ctx->msg->uid, ctx->msg->guid);
		dsync_brain_fail(ctx->iter->sync->brain);
		msg_save_callback(ctx);
		break;
	}
}

static void
dsync_brain_sync_remove_guid_instance(struct dsync_brain_msg_iter *iter,
				      const struct dsync_brain_new_msg *msg)
{
	struct dsync_brain_guid_instance *inst;
	void *orig_key, *orig_value;

	if (!hash_table_lookup_full(iter->guid_hash, msg->msg->guid,
				    &orig_key, &orig_value)) {
		/* another failed copy already removed it */
		return;
	}
	inst = orig_value;

	if (inst->next == NULL)
		hash_table_remove(iter->guid_hash, orig_key);
	else
		hash_table_update(iter->guid_hash, orig_key, inst->next);
}

static void dsync_brain_copy_callback(bool success, void *context)
{
	struct dsync_brain_msg_copy_context *ctx = context;
	struct dsync_brain_new_msg *msg;

	if (!success) {
		/* mark the guid instance invalid and try again later */
		msg = array_idx_modifiable(&ctx->iter->new_msgs, ctx->msg_idx);
		i_assert(msg->saved);
		msg->saved = FALSE;

		if (ctx->iter->next_new_msg > ctx->msg_idx)
			ctx->iter->next_new_msg = ctx->msg_idx;

		dsync_brain_sync_remove_guid_instance(ctx->iter, msg);
	}

	if (--ctx->iter->copy_results_left == 0 && !ctx->iter->adding_msgs)
		dsync_brain_msg_sync_add_new_msgs(ctx->iter);
	i_free(ctx);
}

static int
dsync_brain_msg_sync_add_new_msg(struct dsync_brain_msg_iter *dest_iter,
				 const mailbox_guid_t *src_mailbox,
				 unsigned int msg_idx,
				 struct dsync_brain_new_msg *msg)
{
	struct dsync_brain_msg_save_context *save_ctx;
	struct dsync_brain_msg_copy_context *copy_ctx;
	struct dsync_brain_msg_iter *src_iter;
	const struct dsync_brain_guid_instance *inst;
	const struct dsync_brain_mailbox *inst_box;

	msg->saved = TRUE;

	inst = hash_table_lookup(dest_iter->guid_hash, msg->msg->guid);
	if (inst != NULL) {
		/* we can save this by copying an existing message */
		inst_box = array_idx(&dest_iter->sync->mailboxes,
				     inst->mailbox_idx);

		copy_ctx = i_new(struct dsync_brain_msg_copy_context, 1);
		copy_ctx->iter = dest_iter;
		copy_ctx->msg_idx = msg_idx;

		dest_iter->copy_results_left++;
		dest_iter->adding_msgs = TRUE;
		dsync_worker_msg_copy(dest_iter->worker,
				      &inst_box->box.mailbox_guid,
				      inst->uid, msg->msg,
				      dsync_brain_copy_callback, copy_ctx);
		dest_iter->adding_msgs = FALSE;
	} else {
		src_iter = dest_iter == dest_iter->sync->dest_msg_iter ?
			dest_iter->sync->src_msg_iter :
			dest_iter->sync->dest_msg_iter;

		save_ctx = i_new(struct dsync_brain_msg_save_context, 1);
		save_ctx->iter = dest_iter;
		save_ctx->msg = msg->msg;
		save_ctx->mailbox_idx = dest_iter->mailbox_idx;

		dest_iter->save_results_left++;
		dest_iter->adding_msgs = TRUE;
		dsync_worker_msg_get(src_iter->worker, src_mailbox,
				     msg->orig_uid, msg_get_callback, save_ctx);
		dest_iter->adding_msgs = FALSE;
		if (dsync_worker_output_flush(src_iter->worker) < 0)
			return -1;
		if (dsync_worker_is_output_full(dest_iter->worker)) {
			/* see if the output becomes less full by flushing */
			if (dsync_worker_output_flush(dest_iter->worker) < 0)
				return -1;
		}
	}
	return dsync_worker_is_output_full(dest_iter->worker) ? 0 : 1;
}

static bool
dsync_brain_mailbox_add_new_msgs(struct dsync_brain_msg_iter *iter,
				 const mailbox_guid_t *mailbox_guid)
{
	struct dsync_brain_new_msg *msgs;
	unsigned int msg_count;
	bool ret = TRUE;

	msgs = array_get_modifiable(&iter->new_msgs, &msg_count);
	while (iter->next_new_msg < msg_count) {
		struct dsync_brain_new_msg *msg = &msgs[iter->next_new_msg];

		if (msg->mailbox_idx != iter->mailbox_idx) {
			i_assert(msg->mailbox_idx > iter->mailbox_idx);
			ret = FALSE;
			break;
		}
		iter->next_new_msg++;

		if (msg->saved)
			continue;
		if (dsync_brain_msg_sync_add_new_msg(iter, mailbox_guid,
						     iter->next_new_msg - 1,
						     msg) <= 0) {
			/* failed / continue later */
			break;
		}
	}
	if (iter->next_new_msg == msg_count)
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
dsync_brain_msg_sync_finish(struct dsync_brain_msg_iter *iter)
{
	struct dsync_brain_mailbox_sync *sync = iter->sync;

	i_assert(sync->brain->state == DSYNC_STATE_SYNC_MSGS);

	iter->msgs_sent = TRUE;

	/* done with all mailboxes from this iter */
	dsync_worker_set_input_callback(iter->worker, NULL, NULL);

	if (sync->src_msg_iter->msgs_sent &&
	    sync->dest_msg_iter->msgs_sent &&
	    sync->src_msg_iter->save_results_left == 0 &&
	    sync->dest_msg_iter->save_results_left == 0 &&
	    dsync_worker_output_flush(sync->dest_worker) > 0 &&
	    dsync_worker_output_flush(sync->src_worker) > 0) {
		dsync_worker_set_output_callback(sync->src_msg_iter->worker,
						 NULL, NULL);
		dsync_worker_set_output_callback(sync->dest_msg_iter->worker,
						 NULL, NULL);
		sync->brain->state++;
		dsync_brain_sync(sync->brain);
	}
}

static bool
dsync_brain_msg_sync_select_mailbox(struct dsync_brain_msg_iter *iter)
{
	const struct dsync_brain_mailbox *mailbox;

	while (iter->mailbox_idx < array_count(&iter->sync->mailboxes)) {
		if (array_count(&iter->new_msgs) == 0 &&
		    array_count(&iter->uid_conflicts) == 0) {
			/* optimization: don't even bother selecting this
			   mailbox */
			iter->mailbox_idx++;
			continue;
		}

		mailbox = array_idx(&iter->sync->mailboxes, iter->mailbox_idx);
		dsync_worker_select_mailbox(iter->worker, &mailbox->box);
		return TRUE;
	}
	dsync_brain_msg_sync_finish(iter);
	return FALSE;
}

static void
dsync_brain_msg_sync_add_new_msgs(struct dsync_brain_msg_iter *iter)
{
	const struct dsync_brain_mailbox *mailbox;
	const mailbox_guid_t *mailbox_guid;

	if (iter->msgs_sent) {
		dsync_brain_msg_sync_finish(iter);
		return;
	}

	do {
		mailbox = array_idx(&iter->sync->mailboxes, iter->mailbox_idx);
		mailbox_guid = &mailbox->box.mailbox_guid;
		if (dsync_brain_mailbox_add_new_msgs(iter, mailbox_guid)) {
			/* continue later */
			return;
		}

		/* all messages saved for this mailbox. continue with saving
		   its conflicts and waiting for copies to finish. */
		dsync_brain_mailbox_save_conflicts(iter);
		if (iter->save_results_left > 0 ||
		    iter->copy_results_left > 0) {
			/* wait for saves/copies to finish */
			return;
		}

		/* done with this mailbox, try the next one */
		iter->mailbox_idx++;
	} while (dsync_brain_msg_sync_select_mailbox(iter));
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

	/* sort input by 1) mailbox, 2) new message UID */
	array_sort(&iter->new_msgs, dsync_brain_new_msg_cmp);
	array_sort(&iter->uid_conflicts, dsync_brain_uid_conflict_cmp);

	dsync_worker_set_input_callback(iter->worker, NULL, iter);
	dsync_worker_set_output_callback(iter->worker,
					 dsync_worker_new_msg_output, iter);

	if (dsync_brain_msg_sync_select_mailbox(iter))
		dsync_brain_msg_sync_add_new_msgs(iter);
}

void dsync_brain_msg_sync_new_msgs(struct dsync_brain_mailbox_sync *sync)
{
	dsync_brain_msg_iter_sync_new_msgs(sync->src_msg_iter);
	dsync_brain_msg_iter_sync_new_msgs(sync->dest_msg_iter);
}
