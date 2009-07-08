/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "master-service.h"
#include "dsync-worker.h"
#include "dsync-brain-private.h"

static void
dsync_brain_mailbox_list_deinit(struct dsync_brain_mailbox_list **list);
static void dsync_brain_msg_sync_deinit(struct dsync_brain_mailbox_sync **sync);

struct dsync_brain *dsync_brain_init(struct dsync_worker *src_worker,
				     struct dsync_worker *dest_worker)
{
	struct dsync_brain *brain;

	brain = i_new(struct dsync_brain, 1);
	brain->src_worker = src_worker;
	brain->dest_worker = dest_worker;
	return brain;
}

static void dsync_brain_fail(struct dsync_brain *brain)
{
	brain->failed = TRUE;
	master_service_stop(master_service);
}

int dsync_brain_deinit(struct dsync_brain **_brain)
{
	struct dsync_brain *brain = *_brain;
	int ret = brain->failed ? -1 : 0;

	if (brain->mailbox_sync != NULL)
		dsync_brain_msg_sync_deinit(&brain->mailbox_sync);
	if (brain->src_mailbox_list != NULL)
		dsync_brain_mailbox_list_deinit(&brain->src_mailbox_list);
	if (brain->dest_mailbox_list != NULL)
		dsync_brain_mailbox_list_deinit(&brain->dest_mailbox_list);

	*_brain = NULL;
	i_free(brain);
	return ret;
}

static void dsync_brain_mailbox_list_finished(struct dsync_brain *brain)
{
	if (brain->src_mailbox_list->iter != NULL ||
	    brain->dest_mailbox_list->iter != NULL)
		return;

	/* both lists are finished */
	brain->state++;
	dsync_brain_sync(brain);
}

static void dsync_worker_mailbox_input(void *context)
{
	struct dsync_brain_mailbox_list *list = context;
	struct dsync_mailbox dsync_box, *dup_box;
	int ret;

	while ((ret = dsync_worker_mailbox_iter_next(list->iter,
						     &dsync_box)) > 0) {
		dup_box = dsync_mailbox_dup(list->pool, &dsync_box);
		array_append(&list->mailboxes, &dup_box, 1);
	}
	if (ret < 0) {
		/* finished listing mailboxes */
		if (dsync_worker_mailbox_iter_deinit(&list->iter) < 0)
			dsync_brain_fail(list->brain);
		array_sort(&list->mailboxes, dsync_mailbox_p_guid_cmp);
		dsync_brain_mailbox_list_finished(list->brain);
	}
}

static struct dsync_brain_mailbox_list *
dsync_brain_mailbox_list_init(struct dsync_brain *brain,
			      struct dsync_worker *worker)
{
	struct dsync_brain_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("dsync brain mailbox list", 10240);
	list = p_new(pool, struct dsync_brain_mailbox_list, 1);
	list->pool = pool;
	list->brain = brain;
	list->worker = worker;
	list->iter = dsync_worker_mailbox_iter_init(worker);
	p_array_init(&list->mailboxes, pool, 128);
	dsync_worker_set_input_callback(worker, dsync_worker_mailbox_input,
					list);
	return list;
}

static void
dsync_brain_mailbox_list_deinit(struct dsync_brain_mailbox_list **_list)
{
	struct dsync_brain_mailbox_list *list = *_list;

	*_list = NULL;

	if (list->iter != NULL)
		(void)dsync_worker_mailbox_iter_deinit(&list->iter);
	pool_unref(&list->pool);
}

static void dsync_brain_create_missing_mailboxes(struct dsync_brain *brain)
{
	struct dsync_mailbox *const *src_boxes, *const *dest_boxes, new_box;
	unsigned int src, dest, src_count, dest_count;
	int ret;

	/* FIXME: handle different hierarchy separators? */

	memset(&new_box, 0, sizeof(new_box));

	/* find mailboxes from source whose GUIDs don't exist in dest.
	   the mailboxes are sorted by GUID, so we can do this quickly. */
	src_boxes = array_get(&brain->src_mailbox_list->mailboxes, &src_count);
	dest_boxes = array_get(&brain->dest_mailbox_list->mailboxes, &dest_count);
	for (src = dest = 0; src < src_count && dest < dest_count; ) {
		ret = dsync_mailbox_guid_cmp(src_boxes[src], dest_boxes[dest]);
		if (ret == 0) {
			src++; dest++;
		} else if (ret < 0) {
			/* exists only in source */
			new_box = *src_boxes[src];
			new_box.uid_next = 0;
			new_box.highest_modseq = 0;
			dsync_worker_create_mailbox(brain->dest_worker,
						    &new_box);
			src++;
		} else {
			/* exists only in dest */
			dest++;
		}
	}
	for (; src < src_count; src++) {
		new_box = *src_boxes[src];
		new_box.uid_next = 0;
		new_box.highest_modseq = 0;
		dsync_worker_create_mailbox(brain->dest_worker, &new_box);
	}
}

static void dsync_brain_guid_add(struct dsync_brain_mailbox_sync *sync,
				 struct dsync_brain_msg_iter *iter)
{
	struct dsync_brain_guid_instance *inst, *prev_inst;

	inst = p_new(sync->pool, struct dsync_brain_guid_instance, 1);
	inst->mailbox_idx = iter->mailbox_idx;
	inst->uid = iter->msg.uid;

	prev_inst = hash_table_lookup(sync->guid_hash, iter->msg.guid);
	if (prev_inst == NULL) {
		hash_table_insert(sync->guid_hash,
				  p_strdup(sync->pool, iter->msg.guid), inst);
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
		if (ret > 0) {
			if (iter->save_guids)
				dsync_brain_guid_add(iter->sync, iter);
		}
	}

	if (iter->wanted_mailbox_idx != iter->mailbox_idx) {
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
dsync_brain_msg_sync_save_source(struct dsync_brain_mailbox_sync *sync)
{
	struct dsync_brain_new_msg *new_msg;

	new_msg = array_append_space(&sync->new_msgs);
	new_msg->mailbox_idx = sync->src_msg_iter->mailbox_idx;
	new_msg->msg = dsync_message_dup(sync->pool, &sync->src_msg_iter->msg);
}

static void dsync_brain_msg_sync_existing(struct dsync_brain *brain,
					  struct dsync_message *src_msg,
					  struct dsync_message *dest_msg)
{
	if (src_msg->flags != dest_msg->flags ||
	    src_msg->modseq > dest_msg->modseq ||
	    !dsync_keyword_list_equals(src_msg->keywords, dest_msg->keywords))
		dsync_worker_msg_update_metadata(brain->dest_worker, src_msg);
}

static int dsync_brain_msg_sync_pair(struct dsync_brain_mailbox_sync *sync)
{
	struct dsync_message *src_msg = &sync->src_msg_iter->msg;
	struct dsync_message *dest_msg = &sync->dest_msg_iter->msg;
	struct dsync_mailbox *const *boxp;
	struct dsync_brain_uid_conflict *conflict;

	if (src_msg->uid < dest_msg->uid) {
		/* message has been expunged from dest. ignore it, unless
		   we're in uid-conflict mode. */
		if (sync->uid_conflict)
			dsync_brain_msg_sync_save_source(sync);
		src_msg->guid = NULL;
	} else if (src_msg->uid > dest_msg->uid) {
		/* message has been expunged from src. expunge it from dest
		   too, unless we're in uid-conflict mode. */
		if (!sync->uid_conflict) {
			dsync_worker_msg_expunge(sync->brain->dest_worker,
						 dest_msg->uid);
		}
		dest_msg->guid = NULL;
	} else if (strcmp(src_msg->guid, dest_msg->guid) == 0) {
		/* message exists, sync metadata */
		dsync_brain_msg_sync_existing(sync->brain, src_msg, dest_msg);
		src_msg->guid = NULL;
		dest_msg->guid = NULL;
	} else {
		/* UID conflict. change UID in destination */
		sync->uid_conflict = TRUE;
		conflict = array_append_space(&sync->uid_conflicts);
		conflict->mailbox_idx = sync->src_msg_iter->mailbox_idx;
		conflict->uid = dest_msg->uid;

		/* give new UID for the source message message too. */
		boxp = array_idx(&sync->brain->src_mailbox_list->mailboxes,
				 conflict->mailbox_idx);
		src_msg->uid = (*boxp)->uid_next++;

		dsync_brain_msg_sync_save_source(sync);
		src_msg->guid = NULL;
		dest_msg->guid = NULL;
	}
	return 0;
}

static bool
dsync_brain_msg_sync_mailbox_more(struct dsync_brain_mailbox_sync *sync)
{
	struct dsync_mailbox *const *boxp;
	int ret;

	while ((ret = dsync_brain_msg_iter_next_pair(sync)) > 0) {
		if (dsync_brain_msg_sync_pair(sync) < 0)
			break;
		if (dsync_worker_is_output_full(sync->brain->dest_worker))
			return FALSE;
	}
	if (ret == 0)
		return FALSE;

	/* finished syncing messages in this mailbox that exist in both source
	   and destination. if there are any messages left in destination,
	   expunge them if possible and add their GUIDs to hash in any case. */

	boxp = array_idx(&sync->brain->src_mailbox_list->mailboxes,
			 sync->src_msg_iter->wanted_mailbox_idx);
	while ((ret = dsync_brain_msg_iter_next(sync->dest_msg_iter)) > 0) {
		if (sync->dest_msg_iter->msg.uid >= (*boxp)->uid_next)
			sync->uid_conflict = TRUE;
		if (!sync->uid_conflict) {
			dsync_worker_msg_expunge(sync->brain->dest_worker,
						 sync->dest_msg_iter->msg.uid);
		}

		sync->dest_msg_iter->msg.guid = NULL;
	}
	if (ret == 0)
		return FALSE;

	/* if there are any messages left in source, we'll copy all of them */
	while ((ret = dsync_brain_msg_iter_next(sync->src_msg_iter)) > 0) {
		dsync_brain_msg_sync_save_source(sync);
		sync->src_msg_iter->msg.guid = NULL;
	}
	if (ret == 0)
		return FALSE;
	/* done with this mailbox. the same iterator is still used for
	   getting messages from other mailboxes. */
	return TRUE;
}

static void dsync_brain_msg_sync_finish(struct dsync_brain_mailbox_sync *sync)
{
	/* synced all existing messages. now add the new messages. */
	if (dsync_worker_msg_iter_deinit(&sync->src_msg_iter->iter) < 0 ||
	    dsync_worker_msg_iter_deinit(&sync->dest_msg_iter->iter))
		dsync_brain_fail(sync->brain);

	sync->brain->state++;
	dsync_brain_sync(sync->brain);
}

static void dsync_brain_msg_sync_more(struct dsync_brain_mailbox_sync *sync)
{
	struct dsync_mailbox *const *mailboxes;
	unsigned int count, mailbox_idx;

	mailboxes = array_get(&sync->brain->src_mailbox_list->mailboxes,
			      &count);
	while (dsync_brain_msg_sync_mailbox_more(sync)) {
		/* sync the next mailbox */
		mailbox_idx = ++sync->src_msg_iter->wanted_mailbox_idx;
		sync->dest_msg_iter->wanted_mailbox_idx++;
		if (mailbox_idx == count) {
			dsync_brain_msg_sync_finish(sync);
			return;
		}
		dsync_worker_select_mailbox(sync->brain->dest_worker,
					    &mailboxes[mailbox_idx]->guid);
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
	iter->iter = dsync_worker_msg_iter_init(worker, mailboxes,
						mailbox_count);
	dsync_worker_set_input_callback(worker,
					dsync_worker_msg_callback, sync);
	dsync_worker_set_output_callback(worker,
					 dsync_worker_msg_callback, sync);
	return iter;
}

static struct dsync_brain_mailbox_sync *
dsync_brain_msg_sync_init(struct dsync_brain *brain)
{
	struct dsync_brain_mailbox_sync *sync;
	ARRAY_DEFINE(guids, mailbox_guid_t);
	struct dsync_mailbox *const *mailboxes;
	unsigned int i, count;
	pool_t pool;

	/* initialize message iteration on both workers */
	mailboxes = array_get(&brain->src_mailbox_list->mailboxes, &count);
	t_array_init(&guids, count);
	for (i = 0; i < count; i++)
		array_append(&guids, &mailboxes[i]->guid, 1);

	pool = pool_alloconly_create("dsync brain mailbox sync", 1024*256);
	sync = p_new(pool, struct dsync_brain_mailbox_sync, 1);
	sync->pool = pool;
	sync->brain = brain;

	i_array_init(&sync->uid_conflicts, 128);
	i_array_init(&sync->new_msgs, 128);
	i_array_init(&sync->copy_retry_indexes, 32);
	sync->src_msg_iter =
		dsync_brain_msg_iter_init(sync, brain->src_worker,
					  array_idx(&guids, 0), count);
	sync->dest_msg_iter =
		dsync_brain_msg_iter_init(sync, brain->dest_worker,
					  array_idx(&guids, 0), count);

	sync->guid_hash = hash_table_create(default_pool, pool, 10000,
					    strcase_hash,
					    (hash_cmp_callback_t *)strcasecmp);
	sync->dest_msg_iter->save_guids = TRUE;
	return sync;
}

static void dsync_brain_msg_sync_deinit(struct dsync_brain_mailbox_sync **_sync)
{
	struct dsync_brain_mailbox_sync *sync = *_sync;

	*_sync = NULL;

	if (sync->src_msg_iter->iter != NULL)
		(void)dsync_worker_msg_iter_deinit(&sync->src_msg_iter->iter);
	if (sync->dest_msg_iter->iter != NULL)
		(void)dsync_worker_msg_iter_deinit(&sync->dest_msg_iter->iter);

	hash_table_destroy(&sync->guid_hash);
	array_free(&sync->uid_conflicts);
	array_free(&sync->new_msgs);
	array_free(&sync->copy_retry_indexes);
	pool_unref(&sync->pool);
}

static void dsync_brain_sync_existing_mailboxes(struct dsync_brain *brain)
{
	brain->mailbox_sync = dsync_brain_msg_sync_init(brain);
	dsync_brain_msg_sync_more(brain->mailbox_sync);
}

static int
dsync_brain_msg_sync_add_new_msg(struct dsync_brain_mailbox_sync *sync,
				 const struct dsync_mailbox *src_mailbox,
				 unsigned int msg_idx,
				 const struct dsync_message *msg)
{
	const struct dsync_brain_guid_instance *inst;
	struct dsync_mailbox *const *inst_box;
	struct dsync_msg_static_data data;
	int ret;

	inst = hash_table_lookup(sync->guid_hash, msg->guid);
	if (inst != NULL) {
		/* we can save this by copying an existing message */
		dsync_worker_select_mailbox(sync->brain->dest_worker,
					    &src_mailbox->guid);
		dsync_worker_set_next_result_tag(sync->brain->dest_worker,
						 msg_idx+1);
		inst_box = array_idx(&sync->brain->src_mailbox_list->mailboxes,
				     inst->mailbox_idx);
		dsync_worker_msg_copy(sync->brain->dest_worker,
				      &(*inst_box)->guid, inst->uid, msg);
		sync->copy_results_left++;
	} else {
		dsync_worker_select_mailbox(sync->brain->src_worker,
					    &src_mailbox->guid);
		ret = dsync_worker_msg_get(sync->brain->src_worker,
					   msg->uid, &data);
		if (ret <= 0) {
			if (ret == 0) {
				/* mail got expunged during sync.
				   just skip this. */
				return 1;
			} else {
				dsync_brain_fail(sync->brain);
				return -1;
			}
		}
		dsync_worker_select_mailbox(sync->brain->dest_worker,
					    &src_mailbox->guid);
		dsync_worker_msg_save(sync->brain->dest_worker, msg, &data);
	}
	return dsync_worker_is_output_full(sync->brain->dest_worker) ? 0 : 1;
}

static void
dsync_brain_msg_sync_add_new_msgs(struct dsync_brain_mailbox_sync *sync)
{
	struct dsync_mailbox *const *mailboxes, *mailbox;
	const struct dsync_brain_new_msg *msgs;
	unsigned int i, mailbox_count, msg_count;

	mailboxes = array_get(&sync->brain->src_mailbox_list->mailboxes,
			      &mailbox_count);
	msgs = array_get(&sync->new_msgs, &msg_count);
	for (i = sync->next_new_msg; i < msg_count; i++) {
		mailbox = mailboxes[msgs[i].mailbox_idx];
		if (dsync_brain_msg_sync_add_new_msg(sync, mailbox, i,
						     msgs[i].msg) <= 0) {
			/* failed / continue later */
			sync->next_new_msg = i + 1;
			return;
		}
	}

	/* all messages sent */
	if (sync->copy_results_left == 0) {
		sync->brain->state++;
		dsync_brain_sync(sync->brain);
	}
}

static void dsync_worker_copy_input(void *context)
{
	struct dsync_brain_mailbox_sync *sync = context;
	struct dsync_brain_guid_instance *inst;
	const struct dsync_brain_new_msg *msgs;
	unsigned int count;
	uint32_t tag;
	int result;

	msgs = array_get(&sync->new_msgs, &count);
	while (dsync_worker_get_next_result(sync->brain->dest_worker,
					    &tag, &result)) {
		if (tag == 0 || tag > count) {
			i_error("Worker sent result with invalid tag %u", tag);
			dsync_brain_fail(sync->brain);
			return;
		}
		tag--;
		if (sync->copy_results_left == 0) {
			i_error("Worker sent unexpected result");
			dsync_brain_fail(sync->brain);
			return;
		}
		sync->copy_results_left--;
		if (result < 0) {
			/* mark the guid instance invalid and try again later */
			inst = hash_table_lookup(sync->guid_hash,
						 msgs[tag].msg->guid);
			inst->failed = TRUE;
			array_append(&sync->copy_retry_indexes, &tag, 1);
		}
	}
	if (sync->copy_results_left == 0) {
		sync->brain->state++;
		dsync_brain_sync(sync->brain);
	}
}

static void dsync_worker_new_msg_output(void *context)
{
	struct dsync_brain_mailbox_sync *sync = context;

	dsync_brain_msg_sync_add_new_msgs(sync);
}

static void
dsync_brain_msg_sync_new_msgs(struct dsync_brain_mailbox_sync *sync)
{
	dsync_worker_set_input_callback(sync->brain->dest_worker,
					dsync_worker_copy_input, sync);
	dsync_worker_set_output_callback(sync->brain->dest_worker,
					 dsync_worker_new_msg_output, sync);
	dsync_brain_msg_sync_add_new_msgs(sync);
}

static void
dsync_brain_msg_sync_retry_copies(struct dsync_brain_mailbox_sync *sync)
{
	const uint32_t *indexes;
	struct dsync_mailbox *const *mailboxes, *mailbox;
	const struct dsync_brain_new_msg *msgs;
	unsigned int i, msg_idx, idx_count, msg_count, mailbox_count;
	struct dsync_brain_guid_instance *inst;
	const char *guid_str;
	void *orig_key, *orig_value;

	/* first remove GUID instances that had failed. */
	msgs = array_get(&sync->new_msgs, &msg_count);
	indexes = array_get(&sync->copy_retry_indexes, &idx_count);
	for (i = 0; i < idx_count; i++) {
		guid_str = msgs[indexes[i]].msg->guid;
		if (hash_table_lookup_full(sync->guid_hash, guid_str,
					   &orig_key, &orig_value))
			inst = orig_value;
		else
			inst = NULL;
		if (inst != NULL && inst->failed) {
			inst = inst->next;
			if (inst == NULL)
				hash_table_remove(sync->guid_hash, guid_str);
			else {
				hash_table_update(sync->guid_hash, orig_key,
						  inst);
			}
		}
	}

	/* try saving again. there probably weren't many of them, so don't
	   worry about filling output buffer. */
	mailboxes = array_get(&sync->brain->src_mailbox_list->mailboxes,
			      &mailbox_count);
	for (i = 0; i < idx_count; i++) {
		msg_idx = indexes[i];
		mailbox = mailboxes[msgs[msg_idx].mailbox_idx];
		(void)dsync_brain_msg_sync_add_new_msg(sync, mailbox, msg_idx,
						       msgs[msg_idx].msg);
	}

	/* if we copied anything, we'll again have to wait for the results */
	array_clear(&sync->copy_retry_indexes);
	dsync_worker_set_output_callback(sync->brain->dest_worker, NULL, NULL);

	if (sync->copy_results_left == 0) {
		dsync_worker_set_input_callback(sync->brain->dest_worker,
						NULL, NULL);
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
dsync_brain_msg_sync_update_mailbox(struct dsync_brain *brain)
{
	struct dsync_mailbox *const *mailboxes;
	unsigned int i, count;

	mailboxes = array_get(&brain->src_mailbox_list->mailboxes, &count);
	for (i = 0; i < count; i++)
		dsync_worker_update_mailbox(brain->dest_worker, mailboxes[i]);
}

static void
dsync_brain_msg_sync_resolve_uid_conflicts(struct dsync_brain_mailbox_sync *sync)
{
	const struct dsync_brain_uid_conflict *conflicts;
	struct dsync_mailbox *const *mailboxes, *mailbox;
	unsigned int i, count, mailbox_count;

	mailboxes = array_get(&sync->brain->src_mailbox_list->mailboxes,
			      &mailbox_count);
	conflicts = array_get(&sync->uid_conflicts, &count);
	for (i = 0; i < count; i++) {
		mailbox = mailboxes[conflicts[i].mailbox_idx];
		dsync_worker_select_mailbox(sync->brain->dest_worker,
					    &mailbox->guid);
		dsync_worker_msg_update_uid(sync->brain->dest_worker,
					    conflicts[i].uid);
	}
}

static void dsync_worker_flush_callback(void *context)
{
	struct dsync_brain *brain = context;
	int ret;

	if ((ret = dsync_worker_output_flush(brain->dest_worker)) <= 0) {
		if (ret < 0)
			dsync_brain_fail(brain);
		return;
	}
	brain->state++;
	dsync_brain_sync(brain);
}

void dsync_brain_sync(struct dsync_brain *brain)
{
	switch (brain->state) {
	case DSYNC_STATE_GET_MAILBOXES:
		i_assert(brain->src_mailbox_list == NULL);
		brain->src_mailbox_list =
			dsync_brain_mailbox_list_init(brain, brain->src_worker);
		brain->dest_mailbox_list =
			dsync_brain_mailbox_list_init(brain, brain->dest_worker);
		dsync_worker_mailbox_input(brain->src_mailbox_list);
		dsync_worker_mailbox_input(brain->dest_mailbox_list);
		break;
	case DSYNC_STATE_CREATE_MAILBOXES:
		if (array_count(&brain->src_mailbox_list->mailboxes) == 0) {
			/* no mailboxes */
			i_error("No source mailboxes");
			dsync_brain_fail(brain);
		}

		/* FIXME: maybe wait and verify that all mailboxes are
		   created successfully? */
		dsync_brain_create_missing_mailboxes(brain);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_EXISTING_MSGS:
		dsync_brain_sync_existing_mailboxes(brain);
		break;
	case DSYNC_STATE_SYNC_NEW_MSGS:
		dsync_brain_msg_sync_new_msgs(brain->mailbox_sync);
		break;
	case DSYNC_STATE_SYNC_RETRY_COPIES:
		dsync_brain_msg_sync_retry_copies(brain->mailbox_sync);
		break;
	case DSYNC_STATE_SYNC_UPDATE_MAILBOX:
		dsync_brain_msg_sync_update_mailbox(brain);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_RESOLVE_UID_CONFLICTS:
		/* resolve uid conflicts after uid_nexts have been updated,
		   so that it won't again collide uids */
		dsync_brain_msg_sync_resolve_uid_conflicts(brain->mailbox_sync);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_FLUSH:
		dsync_worker_set_output_callback(brain->dest_worker,
						 dsync_worker_flush_callback,
						 brain);
		dsync_worker_flush_callback(brain);
		break;
	case DSYNC_STATE_SYNC_END:
		master_service_stop(master_service);
		break;
	}
}
