/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "dsync-worker.h"
#include "dsync-brain-private.h"

static void dsync_brain_guid_add(struct dsync_brain_msg_iter *iter)
{
	struct dsync_brain_guid_instance *inst, *prev_inst;

	if ((iter->msg.flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0)
		return;

	inst = p_new(iter->sync->pool, struct dsync_brain_guid_instance, 1);
	inst->mailbox_idx = iter->mailbox_idx;
	inst->uid = iter->msg.uid;

	prev_inst = hash_table_lookup(iter->guid_hash, iter->msg.guid);
	if (prev_inst == NULL) {
		hash_table_insert(iter->guid_hash,
				  p_strdup(iter->sync->pool, iter->msg.guid),
				  inst);
	} else {
		inst->next = prev_inst->next;
		prev_inst->next = inst;
	}
}

static int dsync_brain_msg_iter_next(struct dsync_brain_msg_iter *iter)
{
	int ret = 1;

	if (iter->msg.guid == NULL) {
		ret = dsync_worker_msg_iter_next(iter->iter, &iter->mailbox_idx,
						 &iter->msg);
		if (ret > 0)
			dsync_brain_guid_add(iter);
	}

	if (iter->sync->wanted_mailbox_idx != iter->mailbox_idx) {
		/* finished with this mailbox */
		return -1;
	}
	return ret;
}

static int dsync_brain_msg_iter_next_pair(struct dsync_brain_mailbox_sync *sync)
{
	int ret;

	if ((ret = dsync_brain_msg_iter_next(sync->src_msg_iter)) <= 0)
		return ret;
	if ((ret = dsync_brain_msg_iter_next(sync->dest_msg_iter)) <= 0)
		return ret;
	return 1;
}

static void
dsync_brain_msg_sync_save(struct dsync_brain_msg_iter *iter,
			  unsigned int mailbox_idx,
			  const struct dsync_message *msg)
{
	struct dsync_brain_new_msg *new_msg;

	if ((msg->flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0)
		return;

	new_msg = array_append_space(&iter->new_msgs);
	new_msg->mailbox_idx = mailbox_idx;
	new_msg->orig_uid = msg->uid;
	new_msg->msg = dsync_message_dup(iter->sync->pool, msg);
}

static void
dsync_brain_msg_sync_conflict(struct dsync_brain_msg_iter *conflict_iter,
			      struct dsync_brain_msg_iter *save_iter,
			      const struct dsync_message *msg)
{
	struct dsync_brain_uid_conflict *conflict;
	struct dsync_brain_new_msg *new_msg;
	struct dsync_brain_mailbox *brain_box;
	uint32_t new_uid;

	brain_box = array_idx_modifiable(&save_iter->sync->mailboxes,
					 save_iter->mailbox_idx);
	new_uid = brain_box->box.uid_next++;

	conflict = array_append_space(&conflict_iter->uid_conflicts);
	conflict->mailbox_idx = conflict_iter->mailbox_idx;
	conflict->old_uid = msg->uid;
	conflict->new_uid = new_uid;

	new_msg = array_append_space(&save_iter->new_msgs);
	new_msg->mailbox_idx = save_iter->mailbox_idx;
	new_msg->orig_uid = msg->uid;
	new_msg->msg = dsync_message_dup(save_iter->sync->pool, msg);
	new_msg->msg->uid = new_uid;
}

static void dsync_brain_msg_sync_existing(struct dsync_brain_mailbox_sync *sync,
					  struct dsync_message *src_msg,
					  struct dsync_message *dest_msg)
{
	if (src_msg->modseq > dest_msg->modseq)
		dsync_worker_msg_update_metadata(sync->dest_worker, src_msg);
	else if (src_msg->modseq < dest_msg->modseq)
		dsync_worker_msg_update_metadata(sync->src_worker, dest_msg);
	else if (src_msg->flags != dest_msg->flags ||
		 !dsync_keyword_list_equals(src_msg->keywords,
					    dest_msg->keywords)) {
		/* modseqs match, but flags aren't the same. we can't really
		   know which one we should use, so just pick one. */
		dsync_worker_msg_update_metadata(sync->dest_worker, src_msg);
	}
}

static int dsync_brain_msg_sync_pair(struct dsync_brain_mailbox_sync *sync)
{
	struct dsync_message *src_msg = &sync->src_msg_iter->msg;
	struct dsync_message *dest_msg = &sync->dest_msg_iter->msg;
	const char *src_guid, *dest_guid;
	unsigned char guid_128_data[MAIL_GUID_128_SIZE * 2 + 1];
	bool src_expunged, dest_expunged;

	i_assert(sync->src_msg_iter->mailbox_idx ==
		 sync->dest_msg_iter->mailbox_idx);

	src_expunged = (src_msg->flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0;
	dest_expunged = (dest_msg->flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0;

	if (src_expunged) {
		src_guid = src_msg->guid;
		dest_guid = dsync_get_guid_128_str(dest_msg->guid,
						   guid_128_data,
						   sizeof(guid_128_data));
	} else if (dest_expunged) {
		src_guid = dsync_get_guid_128_str(src_msg->guid, guid_128_data,
						  sizeof(guid_128_data));
		dest_guid = dest_msg->guid;
	} else {
		src_guid = src_msg->guid;
		dest_guid = dest_msg->guid;
	}

	if (src_msg->uid < dest_msg->uid) {
		/* message has been expunged from dest. */
		if (src_expunged) {
			/* expunged from source already */
		} else if (sync->uid_conflict) {
			/* update uid src, copy to dest */
			dsync_brain_msg_sync_conflict(sync->src_msg_iter,
						      sync->dest_msg_iter,
						      src_msg);
		} else {
			/* expunge from source */
			dsync_worker_msg_expunge(sync->src_worker,
						 src_msg->uid);
		}
		src_msg->guid = NULL;
		return 0;
	} else if (src_msg->uid > dest_msg->uid) {
		/* message has been expunged from src. */
		if (dest_expunged) {
			/* expunged from dest already */
		} else if (sync->uid_conflict) {
			/* update uid in dest, copy to src */
			dsync_brain_msg_sync_conflict(sync->dest_msg_iter,
						      sync->src_msg_iter,
						      dest_msg);
		} else {
			/* expunge from dest */
			dsync_worker_msg_expunge(sync->dest_worker,
						 dest_msg->uid);
		}
		dest_msg->guid = NULL;
		return 0;
	}

	/* UIDs match, but do GUIDs? If either of the GUIDs aren't set, it
	   means that either the storage doesn't support GUIDs or we're
	   handling an old-style expunge record. In that case just assume
	   they match. */
	if (strcmp(src_guid, dest_guid) != 0 &&
	    *src_guid != '\0' && *dest_guid != '\0') {
		/* UID conflict. give new UIDs to messages in both src and
		   dest (if they're not expunged already) */
		sync->uid_conflict = TRUE;
		if (!dest_expunged) {
			dsync_brain_msg_sync_conflict(sync->dest_msg_iter,
						      sync->src_msg_iter,
						      dest_msg);
		}
		if (!src_expunged) {
			dsync_brain_msg_sync_conflict(sync->src_msg_iter,
						      sync->dest_msg_iter,
						      src_msg);
		}
	} else if (dest_expunged) {
		/* message expunged from destination */
		if (!src_expunged) {
			dsync_worker_msg_expunge(sync->src_worker,
						 src_msg->uid);
		}
	} else if (src_expunged) {
		/* message expunged from source, expunge from destination too */
		dsync_worker_msg_expunge(sync->dest_worker, dest_msg->uid);
	} else {
		/* message exists in both source and dest, sync metadata */
		dsync_brain_msg_sync_existing(sync, src_msg, dest_msg);
	}
	src_msg->guid = NULL;
	dest_msg->guid = NULL;
	return 0;
}

static bool dsync_brain_msg_sync_mailbox_end(struct dsync_brain_msg_iter *iter1,
					     struct dsync_brain_msg_iter *iter2)
{
	int ret;

	while ((ret = dsync_brain_msg_iter_next(iter1)) > 0) {
		dsync_brain_msg_sync_save(iter2, iter1->mailbox_idx,
					  &iter1->msg);
		iter1->msg.guid = NULL;
	}
	return ret < 0;
}

static bool
dsync_brain_msg_sync_mailbox_more(struct dsync_brain_mailbox_sync *sync)
{
	int ret;

	while ((ret = dsync_brain_msg_iter_next_pair(sync)) > 0) {
		if (dsync_brain_msg_sync_pair(sync) < 0)
			break;
		if (dsync_worker_is_output_full(sync->dest_worker)) {
			if (dsync_worker_output_flush(sync->dest_worker) <= 0)
				return FALSE;
		}
	}
 	if (ret == 0)
		return FALSE;

	/* finished syncing messages in this mailbox that exist in both source
	   and destination. if there are messages left, we can't reliably know
	   if they should be expunged, so just copy them to the other side. */
	if (!dsync_brain_msg_sync_mailbox_end(sync->dest_msg_iter,
					      sync->src_msg_iter))
		return FALSE;
	if (!dsync_brain_msg_sync_mailbox_end(sync->src_msg_iter,
					      sync->dest_msg_iter))
		return FALSE;

	/* done with this mailbox. the same iterator is still used for
	   getting messages from other mailboxes. */
	return TRUE;
}

static void dsync_brain_msg_sync_finish(struct dsync_brain_mailbox_sync *sync)
{
	/* synced all existing messages. now add the new messages. */
	if (dsync_worker_msg_iter_deinit(&sync->src_msg_iter->iter) < 0 ||
	    dsync_worker_msg_iter_deinit(&sync->dest_msg_iter->iter) < 0)
		dsync_brain_fail(sync->brain);

	dsync_brain_msg_sync_new_msgs(sync);
}

void dsync_brain_msg_sync_more(struct dsync_brain_mailbox_sync *sync)
{
	const struct dsync_brain_mailbox *mailboxes;
	unsigned int count, mailbox_idx;

	mailboxes = array_get(&sync->mailboxes, &count);
	while (dsync_brain_msg_sync_mailbox_more(sync)) {
		/* sync the next mailbox */
		sync->uid_conflict = FALSE;
		mailbox_idx = ++sync->wanted_mailbox_idx;
		if (mailbox_idx >= count) {
			dsync_brain_msg_sync_finish(sync);
			return;
		}
		dsync_worker_select_mailbox(sync->src_worker,
			&mailboxes[mailbox_idx].box);
		dsync_worker_select_mailbox(sync->dest_worker,
			&mailboxes[mailbox_idx].box);
	}
}

static void dsync_worker_msg_callback(void *context)
{
	struct dsync_brain_mailbox_sync *sync = context;

	dsync_brain_msg_sync_more(sync);
}

static struct dsync_brain_msg_iter *
dsync_brain_msg_iter_init(struct dsync_brain_mailbox_sync *sync,
			  struct dsync_worker *worker,
			  const mailbox_guid_t mailboxes[],
			  unsigned int mailbox_count)
{
	struct dsync_brain_msg_iter *iter;

	iter = p_new(sync->pool, struct dsync_brain_msg_iter, 1);
	iter->sync = sync;
	iter->worker = worker;
	i_array_init(&iter->uid_conflicts, 128);
	i_array_init(&iter->new_msgs, 128);
	i_array_init(&iter->copy_retry_indexes, 32);
	iter->guid_hash = hash_table_create(default_pool, sync->pool, 10000,
					    strcase_hash,
					    (hash_cmp_callback_t *)strcasecmp);

	iter->iter = dsync_worker_msg_iter_init(worker, mailboxes,
						mailbox_count);
	dsync_worker_set_input_callback(worker,
					dsync_worker_msg_callback, sync);
	dsync_worker_set_output_callback(worker,
					 dsync_worker_msg_callback, sync);
	if (mailbox_count > 0) {
		const struct dsync_brain_mailbox *first;

		first = array_idx(&sync->mailboxes, 0);
		dsync_worker_select_mailbox(worker, &first->box);
	}
	return iter;
}

static void dsync_brain_msg_iter_deinit(struct dsync_brain_msg_iter *iter)
{
	if (iter->iter != NULL)
		(void)dsync_worker_msg_iter_deinit(&iter->iter);

	hash_table_destroy(&iter->guid_hash);
	array_free(&iter->uid_conflicts);
	array_free(&iter->new_msgs);
	array_free(&iter->copy_retry_indexes);
}

static void
get_mailbox_guids(const ARRAY_TYPE(dsync_brain_mailbox) *mailboxes,
		  ARRAY_TYPE(mailbox_guid) *guids)
{
	const struct dsync_brain_mailbox *brain_box;

	t_array_init(guids, array_count(mailboxes));
	array_foreach(mailboxes, brain_box)
		array_append(guids, &brain_box->box.mailbox_guid, 1);
}

struct dsync_brain_mailbox_sync *
dsync_brain_msg_sync_init(struct dsync_brain *brain,
			  const ARRAY_TYPE(dsync_brain_mailbox) *mailboxes)
{
	struct dsync_brain_mailbox_sync *sync;
	pool_t pool;

	pool = pool_alloconly_create("dsync brain mailbox sync", 1024*256);
	sync = p_new(pool, struct dsync_brain_mailbox_sync, 1);
	sync->pool = pool;
	sync->brain = brain;
	sync->src_worker = brain->src_worker;
	sync->dest_worker = brain->dest_worker;

	p_array_init(&sync->mailboxes, pool, array_count(mailboxes));
	array_append_array(&sync->mailboxes, mailboxes);
	T_BEGIN {
		ARRAY_TYPE(mailbox_guid) guids_arr;
		const mailbox_guid_t *guids;
		unsigned int count;

		get_mailbox_guids(mailboxes, &guids_arr);

		/* initialize message iteration on both workers */
		guids = array_get(&guids_arr, &count);
		sync->src_msg_iter =
			dsync_brain_msg_iter_init(sync, brain->src_worker,
						  guids, count);
		sync->dest_msg_iter =
			dsync_brain_msg_iter_init(sync, brain->dest_worker,
						  guids, count);
	} T_END;
	return sync;
}

void dsync_brain_msg_sync_deinit(struct dsync_brain_mailbox_sync **_sync)
{
	struct dsync_brain_mailbox_sync *sync = *_sync;

	*_sync = NULL;

	dsync_brain_msg_iter_deinit(sync->src_msg_iter);
	dsync_brain_msg_iter_deinit(sync->dest_msg_iter);
	pool_unref(&sync->pool);
}
