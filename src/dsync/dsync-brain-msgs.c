/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

/* This code synchronizes messages in all mailboxes between two workers.
   The "src" and "dest" terms don't really have anything to do with reality,
   they're both treated equal.

   1. Iterate through all messages in all (wanted) mailboxes. The mailboxes
      are iterated in the same order and messages in ascending order.
      All of the expunged messages at the end of mailbox (i.e.
      last_existing_uid+1 .. next_uid-1) are also returned with
      DSYNC_MAIL_FLAG_EXPUNGED set. We only care about the end of the mailbox,
      because we can detect UID conflicts for messages in the middle by looking
      at the next existing message and seeing if it has UID conflict.
   2. For each seen non-expunged message, save it to GUID instance hash table:
      message GUID => linked list of { uid, mailbox }
   3. Each message in a mailbox is matched between the two workers as long as
      both have messages left (the last ones may be expunged).
      The possibilities are:

      i) We don't know the GUIDs of both messages:

	a) Message is expunged in both. Do nothing.
	b) Message is expunged in only one of them. If there have been no UID
	   conflicts seen so far, expunge the message in the other one.
	   Otherwise, give the existing a message a new UID (at step 6).

      ii) We know GUIDs of both messages (one/both of them may be expunged):

	a) Messages have conflicting GUIDs. Give new UIDs for the non-expunged
	   message(s) (at step 6).
	b) Messages have matching GUIDs and one of them is expunged.
	   Expunge also the other one. (We don't need to care about previous
	   UID conflicts here, because we know this message is the same with
	   both workers, since they have the same GUID.)
	c) Messages have matching GUIDs and both of them exist. Sync flags from
	   whichever has the higher modseq. If both modseqs equal but flags
	   don't, pick the one that has more flags. If even the flag count is
	   the same, just pick one of them.
   4. One of the workers may messages left in the mailbox. Copy these
      (non-expunged) messages to the other worker (at step 6).
   5. If there are more mailboxes left, go to next one and goto 2.

   6. Copy the new messages and give new UIDs to conflicting messages.
      This code exists in dsync-brain-msgs-new.c
*/

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
		ret = dsync_worker_msg_iter_next(iter->iter,
						 &iter->mailbox_idx,
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

static int
dsync_brain_msg_iter_skip_mailbox(struct dsync_brain_mailbox_sync *sync)
{
	int ret;

	while ((ret = dsync_brain_msg_iter_next(sync->src_msg_iter)) > 0)
		sync->src_msg_iter->msg.guid = NULL;
	if (ret == 0)
		return 0;

	while ((ret = dsync_brain_msg_iter_next(sync->dest_msg_iter)) > 0)
		sync->dest_msg_iter->msg.guid = NULL;
	if (ret == 0)
		return 0;

	sync->skip_mailbox = FALSE;
	return -1;
}

static int dsync_brain_msg_iter_next_pair(struct dsync_brain_mailbox_sync *sync)
{
	int ret1, ret2;

	if (sync->skip_mailbox) {
		if (dsync_brain_msg_iter_skip_mailbox(sync) == 0)
			return 0;
	}

	ret1 = dsync_brain_msg_iter_next(sync->src_msg_iter);
	ret2 = dsync_brain_msg_iter_next(sync->dest_msg_iter);
	if (ret1 == 0 || ret2 == 0) {
		/* make sure we iterate through everything in both iterators
		   (even if it might not seem necessary, because proxy
		   requires it) */
		return 0;
	}
	if (ret1 < 0 || ret2 < 0)
		return -1;
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

	if (save_iter->sync->brain->backup) {
		i_warning("Destination mailbox %s has been modified, "
			  "need to recreate it before we can continue syncing",
			  brain_box->box.name);
		dsync_worker_delete_mailbox(save_iter->sync->brain->dest_worker,
					    &brain_box->box);
		save_iter->sync->brain->unexpected_changes = TRUE;
		save_iter->sync->skip_mailbox = TRUE;
		return;
	}

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

static int
dsync_message_flag_importance_cmp(const struct dsync_message *m1,
				  const struct dsync_message *m2)
{
	unsigned int i, count1, count2;

	if (m1->modseq > m2->modseq)
		return -1;
	else if (m1->modseq < m2->modseq)
		return 1;

	if (m1->flags == m2->flags &&
	    dsync_keyword_list_equals(m1->keywords, m2->keywords))
		return 0;

	/* modseqs match, but flags aren't the same. pick the one that
	   has more flags. */
	count1 = str_array_length(m1->keywords);
	count2 = str_array_length(m2->keywords);
	for (i = 1; i != MAIL_RECENT; i <<= 1) {
		if ((m1->flags & i) != 0)
			count1++;
		if ((m2->flags & i) != 0)
			count2++;
	}
	if (count1 > count2)
		return -1;
	else if (count1 < count2)
		return 1;

	/* they even have the same number of flags. don't bother with further
	   guessing, just pick the first one. */
	return -1;
}

static void dsync_brain_msg_sync_existing(struct dsync_brain_mailbox_sync *sync,
					  struct dsync_message *src_msg,
					  struct dsync_message *dest_msg)
{
	int ret;

	ret = dsync_message_flag_importance_cmp(src_msg, dest_msg);
	if (ret < 0 || (sync->brain->backup && ret > 0))
		dsync_worker_msg_update_metadata(sync->dest_worker, src_msg);
	else if (ret > 0)
		dsync_worker_msg_update_metadata(sync->src_worker, dest_msg);
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

	/* If a message is expunged, it's guaranteed to have a 128bit GUID.
	   If the other message isn't expunged, we'll need to convert its GUID
	   to the 128bit GUID form (if it's not already) so that we can compare
	   them. */
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

	/* FIXME: checking for sync->uid_conflict isn't fully reliable here.
	   we should be checking if the next matching message pair has a
	   conflict, not if the previous pair had one. */
	if (src_msg->uid < dest_msg->uid) {
		/* message has been expunged from dest. */
		if (src_expunged) {
			/* expunged from source already */
		} else if (sync->uid_conflict || sync->brain->backup) {
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
		} else if (sync->uid_conflict && !sync->brain->backup) {
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
		if (src_expunged) {
			/* expunged from source already */
		} else if (sync->brain->backup) {
			dsync_brain_msg_sync_conflict(sync->src_msg_iter,
						      sync->dest_msg_iter,
						      src_msg);
		} else {
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
	if (!sync->brain->backup) {
		if (!dsync_brain_msg_sync_mailbox_end(sync->dest_msg_iter,
						      sync->src_msg_iter))
			return FALSE;
	}
	if (!dsync_brain_msg_sync_mailbox_end(sync->src_msg_iter,
					      sync->dest_msg_iter))
		return FALSE;

	/* done with this mailbox. the same iterator is still used for
	   getting messages from other mailboxes. */
	return TRUE;
}

void dsync_brain_msg_sync_more(struct dsync_brain_mailbox_sync *sync)
{
	const struct dsync_brain_mailbox *mailboxes;
	unsigned int count, mailbox_idx = 0;

	mailboxes = array_get(&sync->mailboxes, &count);
	while (dsync_brain_msg_sync_mailbox_more(sync)) {
		/* sync the next mailbox */
		sync->uid_conflict = FALSE;
		mailbox_idx = ++sync->wanted_mailbox_idx;
		if (mailbox_idx >= count)
			break;

		dsync_worker_select_mailbox(sync->src_worker,
			&mailboxes[mailbox_idx].box);
		dsync_worker_select_mailbox(sync->dest_worker,
			&mailboxes[mailbox_idx].box);
	}
	if (mailbox_idx < count) {
		/* output buffer is full */
		return;
	}

	/* finished with all mailboxes. */
	dsync_worker_set_input_callback(sync->src_msg_iter->worker, NULL, NULL);
	dsync_worker_set_output_callback(sync->src_msg_iter->worker, NULL, NULL);
	dsync_worker_set_input_callback(sync->dest_msg_iter->worker, NULL, NULL);
	dsync_worker_set_output_callback(sync->dest_msg_iter->worker, NULL, NULL);

	if (dsync_worker_msg_iter_deinit(&sync->src_msg_iter->iter) < 0 ||
	    dsync_worker_msg_iter_deinit(&sync->dest_msg_iter->iter) < 0) {
		dsync_brain_fail(sync->brain);
		return;
	}

	dsync_brain_msg_sync_new_msgs(sync);
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
