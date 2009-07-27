/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "master-service.h"
#include "dsync-worker.h"
#include "dsync-brain-private.h"

static void
dsync_brain_mailbox_list_deinit(struct dsync_brain_mailbox_list **list);

struct dsync_brain *dsync_brain_init(struct dsync_worker *src_worker,
				     struct dsync_worker *dest_worker,
				     enum dsync_brain_flags flags)
{
	struct dsync_brain *brain;

	brain = i_new(struct dsync_brain, 1);
	brain->src_worker = src_worker;
	brain->dest_worker = dest_worker;
	brain->flags = flags;
	return brain;
}

void dsync_brain_fail(struct dsync_brain *brain)
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

	/* find mailboxes from whose GUIDs don't exist.
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
			new_box = *dest_boxes[dest];
			new_box.uid_next = 0;
			new_box.highest_modseq = 0;
			dsync_worker_create_mailbox(brain->src_worker,
						    &new_box);
			dest++;
		}
	}
	for (; src < src_count; src++) {
		new_box = *src_boxes[src];
		new_box.uid_next = 0;
		new_box.highest_modseq = 0;
		dsync_worker_create_mailbox(brain->dest_worker, &new_box);
	}
	for (; dest < dest_count; dest++) {
		new_box = *dest_boxes[dest];
		new_box.uid_next = 0;
		new_box.highest_modseq = 0;
		dsync_worker_create_mailbox(brain->src_worker, &new_box);
	}
}

static bool dsync_mailbox_has_changed_msgs(const struct dsync_mailbox *box1,
					   const struct dsync_mailbox *box2)
{
	return box1->uid_validity != box2->uid_validity ||
		box1->uid_next != box2->uid_next ||
		box1->highest_modseq != box2->highest_modseq;
}

static void
dsync_brain_get_changed_mailboxes(struct dsync_brain *brain,
				  ARRAY_TYPE(dsync_brain_mailbox) *brain_boxes,
				  bool full_sync)
{
	struct dsync_mailbox *const *src_boxes, *const *dest_boxes;
	struct dsync_brain_mailbox *brain_box;
	unsigned int src, dest, src_count, dest_count;
	int ret;

	src_boxes = array_get(&brain->src_mailbox_list->mailboxes, &src_count);
	dest_boxes = array_get(&brain->dest_mailbox_list->mailboxes, &dest_count);

	for (src = dest = 0; src < src_count && dest < dest_count; ) {
		ret = dsync_mailbox_guid_cmp(src_boxes[src], dest_boxes[dest]);
		if (ret == 0) {
			if (full_sync ||
			    dsync_mailbox_has_changed_msgs(src_boxes[src],
							   dest_boxes[dest])) {
				brain_box = array_append_space(brain_boxes);
				brain_box->box = *src_boxes[src];

				brain_box->box.highest_modseq =
					I_MAX(src_boxes[src]->highest_modseq,
					      dest_boxes[dest]->highest_modseq);
				brain_box->box.uid_next =
					I_MAX(src_boxes[src]->uid_next,
					      dest_boxes[dest]->uid_next);
				brain_box->src = src_boxes[src];
				brain_box->dest = dest_boxes[dest];
			}
			src++; dest++;
		} else if (ret < 0) {
			/* exists only in source */
			brain_box = array_append_space(brain_boxes);
			brain_box->box = *src_boxes[src];
			brain_box->src = src_boxes[src];
			src++;
		} else {
			/* exists only in dest */
			brain_box = array_append_space(brain_boxes);
			brain_box->box = *dest_boxes[dest];
			brain_box->dest = dest_boxes[dest];
			dest++;
		}
	}
	for (; src < src_count; src++) {
		brain_box = array_append_space(brain_boxes);
		brain_box->box = *src_boxes[src];
		brain_box->src = src_boxes[src];
	}
	for (; dest < dest_count; dest++) {
		brain_box = array_append_space(brain_boxes);
		brain_box->box = *dest_boxes[dest];
		brain_box->dest = dest_boxes[dest];
	}
}

static void dsync_brain_sync_msgs(struct dsync_brain *brain)
{
	ARRAY_TYPE(dsync_brain_mailbox) mailboxes;

	t_array_init(&mailboxes, 128);
	dsync_brain_get_changed_mailboxes(brain, &mailboxes,
		(brain->flags & DSYNC_BRAIN_FLAG_FULL_SYNC) != 0);
	brain->mailbox_sync = dsync_brain_msg_sync_init(brain, &mailboxes);
}

static void
dsync_brain_msg_sync_update_mailbox(struct dsync_brain *brain)
{
	const struct dsync_brain_mailbox *mailboxes;
	unsigned int i, count;

	mailboxes = array_get(&brain->mailbox_sync->mailboxes, &count);
	for (i = 0; i < count; i++) {
		dsync_worker_update_mailbox(brain->src_worker,
					    &mailboxes[i].box);
		dsync_worker_update_mailbox(brain->dest_worker,
					    &mailboxes[i].box);
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
		if (array_count(&brain->src_mailbox_list->mailboxes) == 0 &&
		    array_count(&brain->dest_mailbox_list->mailboxes) == 0) {
			/* no mailboxes */
			i_error("No mailboxes");
			dsync_brain_fail(brain);
		}

		/* FIXME: maybe wait and verify that all mailboxes are
		   created successfully? */
		dsync_brain_create_missing_mailboxes(brain);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_MSGS:
		dsync_brain_sync_msgs(brain);
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
		/* FIXME: retrieve worker failures and set brain failure */
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
