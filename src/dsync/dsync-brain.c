/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "master-service.h"
#include "dsync-worker.h"
#include "dsync-brain-private.h"

#include <unistd.h>

#define DSYNC_WRONG_DIRECTION_ERROR_MSG \
	"dsync backup: " \
	"Looks like you're trying to run backup in wrong direction. " \
	"Source is empty and destination is not."

static void
dsync_brain_mailbox_list_deinit(struct dsync_brain_mailbox_list **list);
static void
dsync_brain_subs_list_deinit(struct dsync_brain_subs_list **list);

struct dsync_brain *
dsync_brain_init(struct dsync_worker *src_worker,
		 struct dsync_worker *dest_worker,
		 const char *mailbox, enum dsync_brain_flags flags)
{
	struct dsync_brain *brain;

	brain = i_new(struct dsync_brain, 1);
	brain->src_worker = src_worker;
	brain->dest_worker = dest_worker;
	brain->mailbox = i_strdup(mailbox);
	brain->flags = flags;
	brain->verbose = (flags & DSYNC_BRAIN_FLAG_VERBOSE) != 0;
	brain->backup = (flags & DSYNC_BRAIN_FLAG_BACKUP) != 0;
	brain->stdout_tty = isatty(STDOUT_FILENO) > 0;

	if ((flags & DSYNC_BRAIN_FLAG_VERBOSE) != 0) {
		dsync_worker_set_verbose(src_worker);
		dsync_worker_set_verbose(dest_worker);
	}
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

	if (brain->state != DSYNC_STATE_SYNC_END)
		ret = -1;
	if (brain->to != NULL)
		timeout_remove(&brain->to);

	if (ret < 0) {
		/* make sure we unreference save input streams before workers
		   are deinitialized, so they can destroy the streams */
		dsync_worker_msg_save_cancel(brain->src_worker);
		dsync_worker_msg_save_cancel(brain->dest_worker);
	}

	if (brain->mailbox_sync != NULL)
		dsync_brain_msg_sync_deinit(&brain->mailbox_sync);

	if (brain->src_mailbox_list != NULL)
		dsync_brain_mailbox_list_deinit(&brain->src_mailbox_list);
	if (brain->dest_mailbox_list != NULL)
		dsync_brain_mailbox_list_deinit(&brain->dest_mailbox_list);

	if (brain->src_subs_list != NULL)
		dsync_brain_subs_list_deinit(&brain->src_subs_list);
	if (brain->dest_subs_list != NULL)
		dsync_brain_subs_list_deinit(&brain->dest_subs_list);

	if (dsync_worker_has_failed(brain->src_worker) ||
	    dsync_worker_has_failed(brain->dest_worker))
		ret = -1;

	*_brain = NULL;
	i_free(brain->mailbox);
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
		if (list->brain->mailbox != NULL &&
		    strcmp(list->brain->mailbox, dsync_box.name) != 0)
			continue;

		dup_box = dsync_mailbox_dup(list->pool, &dsync_box);
		if (!dsync_mailbox_is_noselect(dup_box))
			array_append(&list->mailboxes, &dup_box, 1);
		else
			array_append(&list->dirs, &dup_box, 1);
	}
	if (ret < 0) {
		/* finished listing mailboxes */
		if (dsync_worker_mailbox_iter_deinit(&list->iter) < 0)
			dsync_brain_fail(list->brain);
		array_sort(&list->mailboxes, dsync_mailbox_p_guid_cmp);
		array_sort(&list->dirs, dsync_mailbox_p_name_sha1_cmp);
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
	p_array_init(&list->dirs, pool, 32);
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

static void dsync_brain_subs_list_finished(struct dsync_brain *brain)
{
	if (brain->src_subs_list->iter != NULL ||
	    brain->dest_subs_list->iter != NULL)
		return;

	/* both lists are finished */
	brain->state++;
	dsync_brain_sync(brain);
}

static int
dsync_worker_subscription_cmp(const struct dsync_worker_subscription *s1,
			      const struct dsync_worker_subscription *s2)
{
	return strcmp(s1->vname, s2->vname);
}

static int
dsync_worker_unsubscription_cmp(const struct dsync_worker_unsubscription *u1,
				const struct dsync_worker_unsubscription *u2)
{
	int ret;

	ret = strcmp(u1->ns_prefix, u2->ns_prefix);
	return ret != 0 ? ret :
		dsync_guid_cmp(&u1->name_sha1, &u2->name_sha1);
}

static void dsync_worker_subs_input(void *context)
{
	struct dsync_brain_subs_list *list = context;
	struct dsync_worker_subscription subs;
	struct dsync_worker_unsubscription unsubs;
	int ret;

	memset(&subs, 0, sizeof(subs));
	while ((ret = dsync_worker_subs_iter_next(list->iter, &subs)) > 0) {
		subs.vname = p_strdup(list->pool, subs.vname);
		subs.storage_name = p_strdup(list->pool, subs.storage_name);
		subs.ns_prefix = p_strdup(list->pool, subs.ns_prefix);
		array_append(&list->subscriptions, &subs, 1);
	}
	if (ret == 0)
		return;

	memset(&unsubs, 0, sizeof(unsubs));
	while ((ret = dsync_worker_subs_iter_next_un(list->iter,
						     &unsubs)) > 0) {
		unsubs.ns_prefix = p_strdup(list->pool, unsubs.ns_prefix);
		array_append(&list->unsubscriptions, &unsubs, 1);
	}

	if (ret < 0) {
		/* finished listing subscriptions */
		if (dsync_worker_subs_iter_deinit(&list->iter) < 0)
			dsync_brain_fail(list->brain);
		array_sort(&list->subscriptions,
			   dsync_worker_subscription_cmp);
		array_sort(&list->unsubscriptions,
			   dsync_worker_unsubscription_cmp);
		dsync_brain_subs_list_finished(list->brain);
	}
}

static struct dsync_brain_subs_list *
dsync_brain_subs_list_init(struct dsync_brain *brain,
			      struct dsync_worker *worker)
{
	struct dsync_brain_subs_list *list;
	pool_t pool;

	pool = pool_alloconly_create("dsync brain subs list", 1024*4);
	list = p_new(pool, struct dsync_brain_subs_list, 1);
	list->pool = pool;
	list->brain = brain;
	list->worker = worker;
	list->iter = dsync_worker_subs_iter_init(worker);
	p_array_init(&list->subscriptions, pool, 128);
	p_array_init(&list->unsubscriptions, pool, 64);
	dsync_worker_set_input_callback(worker, dsync_worker_subs_input, list);
	return list;
}

static void
dsync_brain_subs_list_deinit(struct dsync_brain_subs_list **_list)
{
	struct dsync_brain_subs_list *list = *_list;

	*_list = NULL;

	if (list->iter != NULL)
		(void)dsync_worker_subs_iter_deinit(&list->iter);
	pool_unref(&list->pool);
}

enum dsync_brain_mailbox_action {
	DSYNC_BRAIN_MAILBOX_ACTION_NONE,
	DSYNC_BRAIN_MAILBOX_ACTION_CREATE,
	DSYNC_BRAIN_MAILBOX_ACTION_DELETE
};

static void
dsync_brain_mailbox_action(struct dsync_brain *brain,
			   enum dsync_brain_mailbox_action action,
			   struct dsync_worker *action_worker,
			   struct dsync_mailbox *action_box)
{
	struct dsync_mailbox new_box;

	if (brain->backup && action_worker == brain->src_worker) {
		/* backup mode: switch actions */
		action_worker = brain->dest_worker;
		switch (action) {
		case DSYNC_BRAIN_MAILBOX_ACTION_NONE:
			break;
		case DSYNC_BRAIN_MAILBOX_ACTION_CREATE:
			action = DSYNC_BRAIN_MAILBOX_ACTION_DELETE;
			break;
		case DSYNC_BRAIN_MAILBOX_ACTION_DELETE:
			action = DSYNC_BRAIN_MAILBOX_ACTION_CREATE;
			break;
		}
	}

	switch (action) {
	case DSYNC_BRAIN_MAILBOX_ACTION_NONE:
		break;
	case DSYNC_BRAIN_MAILBOX_ACTION_CREATE:
		new_box = *action_box;
		new_box.uid_next = action_box->uid_validity == 0 ? 0 : 1;
		new_box.first_recent_uid = 0;
		new_box.highest_modseq = 0;
		dsync_worker_create_mailbox(action_worker, &new_box);
		break;
	case DSYNC_BRAIN_MAILBOX_ACTION_DELETE:
		if (!dsync_mailbox_is_noselect(action_box))
			dsync_worker_delete_mailbox(action_worker, action_box);
		else
			dsync_worker_delete_dir(action_worker, action_box);
		break;
	}
}

static bool
dsync_mailbox_list_is_empty(const ARRAY_TYPE(dsync_mailbox) *boxes_arr)
{
	struct dsync_mailbox *const *boxes;
	unsigned int count;

	boxes = array_get(boxes_arr, &count);
	if (count == 0)
		return TRUE;
	if (count == 1 && strcasecmp(boxes[0]->name, "INBOX") == 0 &&
	    boxes[0]->message_count == 0)
		return TRUE;
	return FALSE;
}

static void dsync_brain_sync_mailboxes(struct dsync_brain *brain)
{
	struct dsync_mailbox *const *src_boxes, *const *dest_boxes;
	struct dsync_mailbox *action_box = NULL;
	struct dsync_worker *action_worker = NULL;
	unsigned int src, dest, src_count, dest_count;
	enum dsync_brain_mailbox_action action;
	bool src_deleted, dest_deleted;
	int ret;

	if (brain->backup &&
	    dsync_mailbox_list_is_empty(&brain->src_mailbox_list->mailboxes) &&
	    !dsync_mailbox_list_is_empty(&brain->dest_mailbox_list->mailboxes)) {
		i_fatal(DSYNC_WRONG_DIRECTION_ERROR_MSG);
	}

	/* create/delete missing mailboxes. the mailboxes are sorted by
	   GUID, so we can do this quickly. */
	src_boxes = array_get(&brain->src_mailbox_list->mailboxes, &src_count);
	dest_boxes = array_get(&brain->dest_mailbox_list->mailboxes, &dest_count);
	for (src = dest = 0; src < src_count && dest < dest_count; ) {
		action = DSYNC_BRAIN_MAILBOX_ACTION_NONE;
		src_deleted = (src_boxes[src]->flags &
			       DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0;
		dest_deleted = (dest_boxes[dest]->flags &
				DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0;
		ret = dsync_mailbox_guid_cmp(src_boxes[src],
					     dest_boxes[dest]);
		if (ret < 0) {
			/* exists only in source */
			if (!src_deleted) {
				action = DSYNC_BRAIN_MAILBOX_ACTION_CREATE;
				action_worker = brain->dest_worker;
				action_box = src_boxes[src];
			}
			src++;
		} else if (ret > 0) {
			/* exists only in dest */
			if (!dest_deleted) {
				action = DSYNC_BRAIN_MAILBOX_ACTION_CREATE;
				action_worker = brain->src_worker;
				action_box = dest_boxes[dest];
			}
			dest++;
		} else if (src_deleted) {
			/* delete from dest too */
			if (!dest_deleted) {
				action = DSYNC_BRAIN_MAILBOX_ACTION_DELETE;
				action_worker = brain->dest_worker;
				action_box = dest_boxes[dest];
			}
			src++; dest++;
		} else if (dest_deleted) {
			/* delete from src too */
			action = DSYNC_BRAIN_MAILBOX_ACTION_DELETE;
			action_worker = brain->src_worker;
			action_box = src_boxes[src];
			src++; dest++;
		} else {
			src++; dest++;
		}
		dsync_brain_mailbox_action(brain, action,
					   action_worker, action_box);
	}
	for (; src < src_count; src++) {
		if ((src_boxes[src]->flags &
		     DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0)
			continue;

		dsync_brain_mailbox_action(brain,
			DSYNC_BRAIN_MAILBOX_ACTION_CREATE,
			brain->dest_worker, src_boxes[src]);
	}
	for (; dest < dest_count; dest++) {
		if ((dest_boxes[dest]->flags &
		     DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0)
			continue;

		dsync_brain_mailbox_action(brain,
			DSYNC_BRAIN_MAILBOX_ACTION_CREATE,
			brain->src_worker, dest_boxes[dest]);
	}
}

static void dsync_brain_sync_dirs(struct dsync_brain *brain)
{
	struct dsync_mailbox *const *src_boxes, *const *dest_boxes, *action_box;
	unsigned int src, dest, src_count, dest_count;
	enum dsync_brain_mailbox_action action;
	struct dsync_worker *action_worker = NULL;
	bool src_deleted, dest_deleted;
	int ret;

	/* create/delete missing directories. */
	src_boxes = array_get(&brain->src_mailbox_list->dirs, &src_count);
	dest_boxes = array_get(&brain->dest_mailbox_list->dirs, &dest_count);
	for (src = dest = 0; src < src_count && dest < dest_count; ) {
		action = DSYNC_BRAIN_MAILBOX_ACTION_NONE;
		action_box = NULL;

		src_deleted = (src_boxes[src]->flags &
			       DSYNC_MAILBOX_FLAG_DELETED_DIR) != 0;
		dest_deleted = (dest_boxes[dest]->flags &
				DSYNC_MAILBOX_FLAG_DELETED_DIR) != 0;
		ret = memcmp(src_boxes[src]->name_sha1.guid,
			     dest_boxes[dest]->name_sha1.guid,
			     sizeof(src_boxes[src]->name_sha1.guid));
		if (ret < 0) {
			/* exists only in source */
			if (!src_deleted) {
				action = DSYNC_BRAIN_MAILBOX_ACTION_CREATE;
				action_worker = brain->dest_worker;
				action_box = src_boxes[src];
			}
			src++;
		} else if (ret > 0) {
			/* exists only in dest */
			if (!dest_deleted) {
				action = DSYNC_BRAIN_MAILBOX_ACTION_CREATE;
				action_worker = brain->src_worker;
				action_box = dest_boxes[dest];
			}
			dest++;
		} else if (src_deleted) {
			/* delete from dest too */
			if (!dest_deleted) {
				action = DSYNC_BRAIN_MAILBOX_ACTION_DELETE;
				action_worker = brain->dest_worker;
				action_box = dest_boxes[dest];
			}
			src++; dest++;
		} else if (dest_deleted) {
			/* delete from src too */
			action = DSYNC_BRAIN_MAILBOX_ACTION_DELETE;
			action_worker = brain->src_worker;
			action_box = src_boxes[src];
			src++; dest++;
		} else {
			src++; dest++;
		}
		i_assert(action_box == NULL ||
			 dsync_mailbox_is_noselect(action_box));
		dsync_brain_mailbox_action(brain, action,
					   action_worker, action_box);
	}
	for (; src < src_count; src++) {
		if ((src_boxes[src]->flags &
		     DSYNC_MAILBOX_FLAG_DELETED_DIR) != 0)
			continue;

		dsync_brain_mailbox_action(brain,
			DSYNC_BRAIN_MAILBOX_ACTION_CREATE,
			brain->dest_worker, src_boxes[src]);
	}
	for (; dest < dest_count; dest++) {
		if ((dest_boxes[dest]->flags &
		     DSYNC_MAILBOX_FLAG_DELETED_DIR) != 0)
			continue;

		dsync_brain_mailbox_action(brain,
			DSYNC_BRAIN_MAILBOX_ACTION_CREATE,
			brain->src_worker, dest_boxes[dest]);
	}
}

static bool
dsync_brain_is_unsubscribed(struct dsync_brain_subs_list *list,
			    const struct dsync_worker_subscription *subs,
			    time_t *last_change_r)
{
	const struct dsync_worker_unsubscription *unsubs;
	struct dsync_worker_unsubscription lookup;

	lookup.ns_prefix = subs->ns_prefix;
	dsync_str_sha_to_guid(subs->storage_name, &lookup.name_sha1);
	unsubs = array_bsearch(&list->unsubscriptions, &lookup,
			       dsync_worker_unsubscription_cmp);
	if (unsubs == NULL) {
		*last_change_r = 0;
		return FALSE;
	} else if (unsubs->last_change <= subs->last_change) {
		*last_change_r = subs->last_change;
		return FALSE;
	} else {
		*last_change_r = unsubs->last_change;
		return TRUE;
	}
}

static void dsync_brain_sync_subscriptions(struct dsync_brain *brain)
{
	const struct dsync_worker_subscription *src_subs, *dest_subs;
	const struct dsync_worker_subscription *action_subs;
	struct dsync_worker *action_worker;
	unsigned int src, dest, src_count, dest_count;
	time_t last_change;
	bool subscribe;
	int ret;

	/* subscriptions are sorted by name. */
	src_subs = array_get(&brain->src_subs_list->subscriptions, &src_count);
	dest_subs = array_get(&brain->dest_subs_list->subscriptions, &dest_count);
	for (src = dest = 0;; ) {
		if (src == src_count) {
			if (dest == dest_count)
				break;
			ret = 1;
		} else if (dest == dest_count) {
			ret = -1;
		} else {
			ret = strcmp(src_subs[src].vname,
				     dest_subs[dest].vname);
			if (ret == 0) {
				src++; dest++;
				continue;
			}
		}

		if (ret < 0) {
			/* subscribed only in source */
			action_subs = &src_subs[src];
			if (dsync_brain_is_unsubscribed(brain->dest_subs_list,
							&src_subs[src],
							&last_change)) {
				action_worker = brain->src_worker;
				subscribe = FALSE;
			} else {
				action_worker = brain->dest_worker;
				subscribe = TRUE;
			}
			src++;
		} else {
			/* subscribed only in dest */
			action_subs = &dest_subs[dest];
			if (dsync_brain_is_unsubscribed(brain->src_subs_list,
							&dest_subs[dest],
							&last_change)) {
				action_worker = brain->dest_worker;
				subscribe = FALSE;
			} else {
				action_worker = brain->src_worker;
				subscribe = TRUE;
			}
			dest++;
		}

		if (brain->backup && action_worker == brain->src_worker) {
			/* backup mode: switch action */
			action_worker = brain->dest_worker;
			subscribe = !subscribe;
			last_change = ioloop_time;
		}
		dsync_worker_set_subscribed(action_worker, action_subs->vname,
					    last_change, subscribe);
	}
}

static bool dsync_mailbox_has_changed_msgs(struct dsync_brain *brain,
					   const struct dsync_mailbox *box1,
					   const struct dsync_mailbox *box2)
{
	const char *name = *box1->name != '\0' ? box1->name : box2->name;

	if (box1->uid_validity != box2->uid_validity) {
		if (brain->verbose) {
			i_info("%s: uidvalidity changed: %u != %u", name,
			       box1->uid_validity, box2->uid_validity);
		}
		return TRUE;
	}
	if (box1->uid_next != box2->uid_next) {
		if (brain->verbose) {
			i_info("%s: uidnext changed: %u != %u", name,
			       box1->uid_next, box2->uid_next);
		}
		return TRUE;
	}
	if (box1->highest_modseq != box2->highest_modseq) {
		if (brain->verbose) {
			i_info("%s: highest_modseq changed: %llu != %llu", name,
			       (unsigned long long)box1->highest_modseq,
			       (unsigned long long)box2->highest_modseq);
		}
		return TRUE;
	}
	if (box1->message_count != box2->message_count) {
		if (brain->verbose) {
			i_info("%s: message_count changed: %u != %u", name,
			       box1->message_count, box2->message_count);
		}
		return TRUE;
	}
	return FALSE;
}

static bool dsync_mailbox_has_changes(struct dsync_brain *brain,
				      const struct dsync_mailbox *box1,
				      const struct dsync_mailbox *box2)
{
	if (strcmp(box1->name, box2->name) != 0)
		return TRUE;
	return dsync_mailbox_has_changed_msgs(brain, box1, box2);
}

static void
dsync_brain_get_changed_mailboxes(struct dsync_brain *brain,
				  ARRAY_TYPE(dsync_brain_mailbox) *brain_boxes,
				  bool full_sync)
{
	struct dsync_mailbox *const *src_boxes, *const *dest_boxes;
	struct dsync_brain_mailbox *brain_box;
	unsigned int src, dest, src_count, dest_count;
	bool src_deleted, dest_deleted;
	int ret;

	src_boxes = array_get(&brain->src_mailbox_list->mailboxes, &src_count);
	dest_boxes = array_get(&brain->dest_mailbox_list->mailboxes, &dest_count);

	for (src = dest = 0; src < src_count && dest < dest_count; ) {
		src_deleted = (src_boxes[src]->flags &
			       DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0;
		dest_deleted = (dest_boxes[dest]->flags &
				DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0;

		ret = dsync_mailbox_guid_cmp(src_boxes[src], dest_boxes[dest]);
		if (ret == 0) {
			if ((full_sync ||
			     dsync_mailbox_has_changes(brain, src_boxes[src],
						       dest_boxes[dest])) &&
			    !src_deleted && !dest_deleted) {
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
			if (!src_deleted) {
				brain_box = array_append_space(brain_boxes);
				brain_box->box = *src_boxes[src];
				brain_box->src = src_boxes[src];
				if (brain->verbose) {
					i_info("%s: only in source (guid=%s)",
					       brain_box->box.name,
					       dsync_guid_to_str(&brain_box->box.mailbox_guid));
				}
			}
 			src++;
		} else {
			/* exists only in dest */
			if (!dest_deleted) {
				brain_box = array_append_space(brain_boxes);
				brain_box->box = *dest_boxes[dest];
				brain_box->dest = dest_boxes[dest];
				if (brain->verbose) {
					i_info("%s: only in dest (guid=%s)",
					       brain_box->box.name,
					       dsync_guid_to_str(&brain_box->box.mailbox_guid));
				}
			}
			dest++;
		}
	}
	for (; src < src_count; src++) {
		if ((src_boxes[src]->flags &
		     DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0)
			continue;

		brain_box = array_append_space(brain_boxes);
		brain_box->box = *src_boxes[src];
		brain_box->src = src_boxes[src];
		if (brain->verbose) {
			i_info("%s: only in source (guid=%s)",
			       brain_box->box.name,
			       dsync_guid_to_str(&brain_box->box.mailbox_guid));
		}
	}
	for (; dest < dest_count; dest++) {
		if ((dest_boxes[dest]->flags &
		     DSYNC_MAILBOX_FLAG_DELETED_MAILBOX) != 0)
			continue;

		brain_box = array_append_space(brain_boxes);
		brain_box->box = *dest_boxes[dest];
		brain_box->dest = dest_boxes[dest];
		if (brain->verbose) {
			i_info("%s: only in dest (guid=%s)",
			       brain_box->box.name,
			       dsync_guid_to_str(&brain_box->box.mailbox_guid));
		}
	}
}

static bool dsync_brain_sync_msgs(struct dsync_brain *brain)
{
	ARRAY_TYPE(dsync_brain_mailbox) mailboxes;
	pool_t pool;
	bool ret;

	pool = pool_alloconly_create("dsync changed mailboxes", 10240);
	p_array_init(&mailboxes, pool, 128);
	dsync_brain_get_changed_mailboxes(brain, &mailboxes,
		(brain->flags & DSYNC_BRAIN_FLAG_FULL_SYNC) != 0);
	if (array_count(&mailboxes) > 0) {
		brain->mailbox_sync =
			dsync_brain_msg_sync_init(brain, &mailboxes);
		dsync_brain_msg_sync_more(brain->mailbox_sync);
		ret = TRUE;
	} else {
		ret = FALSE;
	}
	pool_unref(&pool);
	return ret;
}

static void
dsync_brain_sync_rename_mailbox(struct dsync_brain *brain,
				const struct dsync_brain_mailbox *mailbox)
{
	if (mailbox->src->last_change > mailbox->dest->last_change ||
	    brain->backup) {
		dsync_worker_rename_mailbox(brain->dest_worker,
					    &mailbox->box.mailbox_guid,
					    mailbox->src);
	} else {
		dsync_worker_rename_mailbox(brain->src_worker,
					    &mailbox->box.mailbox_guid,
					    mailbox->dest);
	}
}

static void
dsync_brain_sync_update_mailboxes(struct dsync_brain *brain)
{
	const struct dsync_brain_mailbox *mailbox;
	bool failed_changes = dsync_brain_has_unexpected_changes(brain) ||
		dsync_worker_has_failed(brain->src_worker) ||
		dsync_worker_has_failed(brain->dest_worker);

	if (brain->mailbox_sync == NULL) {
		/* no mailboxes changed */
		return;
	}

	array_foreach(&brain->mailbox_sync->mailboxes, mailbox) {
		/* don't update mailboxes if any changes had failed.
		   for example if some messages couldn't be saved, we don't
		   want to increase the next_uid to jump over them */
		if (!brain->backup && !failed_changes) {
			dsync_worker_update_mailbox(brain->src_worker,
						    &mailbox->box);
		}
		if (!failed_changes) {
			dsync_worker_update_mailbox(brain->dest_worker,
						    &mailbox->box);
		}

		if (mailbox->src != NULL && mailbox->dest != NULL &&
		    strcmp(mailbox->src->name, mailbox->dest->name) != 0)
			dsync_brain_sync_rename_mailbox(brain, mailbox);
	}
}

static void dsync_brain_worker_finished(bool success, void *context)
{
	struct dsync_brain *brain = context;

	switch (brain->state) {
	case DSYNC_STATE_SYNC_MSGS_FLUSH:
	case DSYNC_STATE_SYNC_MSGS_FLUSH2:
	case DSYNC_STATE_SYNC_FLUSH:
	case DSYNC_STATE_SYNC_FLUSH2:
		break;
	default:
		i_panic("dsync brain state=%d", brain->state);
	}

	if (!success)
		dsync_brain_fail(brain);

	brain->state++;
	if (brain->to == NULL && (brain->flags & DSYNC_BRAIN_FLAG_LOCAL) == 0)
		brain->to = timeout_add(0, dsync_brain_sync, brain);
}

void dsync_brain_sync(struct dsync_brain *brain)
{
	if (dsync_worker_has_failed(brain->src_worker) ||
	    dsync_worker_has_failed(brain->dest_worker)) {
		/* we can't safely continue, especially with backup */
		return;
	}

	if (brain->to != NULL)
		timeout_remove(&brain->to);
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
	case DSYNC_STATE_GET_SUBSCRIPTIONS:
		i_assert(brain->src_subs_list == NULL);
		brain->src_subs_list =
			dsync_brain_subs_list_init(brain, brain->src_worker);
		brain->dest_subs_list =
			dsync_brain_subs_list_init(brain, brain->dest_worker);
		dsync_worker_subs_input(brain->src_subs_list);
		dsync_worker_subs_input(brain->dest_subs_list);
		break;
	case DSYNC_STATE_SYNC_MAILBOXES:
		dsync_worker_set_input_callback(brain->src_worker, NULL, NULL);
		dsync_worker_set_input_callback(brain->dest_worker, NULL, NULL);

		dsync_brain_sync_mailboxes(brain);
		dsync_brain_sync_dirs(brain);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_SUBSCRIPTIONS:
		dsync_brain_sync_subscriptions(brain);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_MSGS:
		if (dsync_brain_sync_msgs(brain))
			break;
		brain->state++;
		/* no mailboxes changed */
	case DSYNC_STATE_SYNC_MSGS_FLUSH:
		/* wait until all saves are done, so we don't try to close
		   the mailbox too early */
		dsync_worker_finish(brain->src_worker,
				    dsync_brain_worker_finished, brain);
		dsync_worker_finish(brain->dest_worker,
				    dsync_brain_worker_finished, brain);
		break;
	case DSYNC_STATE_SYNC_MSGS_FLUSH2:
		break;
	case DSYNC_STATE_SYNC_UPDATE_MAILBOXES:
		dsync_brain_sync_update_mailboxes(brain);
		brain->state++;
		/* fall through */
	case DSYNC_STATE_SYNC_FLUSH:
		dsync_worker_finish(brain->src_worker,
				    dsync_brain_worker_finished, brain);
		dsync_worker_finish(brain->dest_worker,
				    dsync_brain_worker_finished, brain);
		break;
	case DSYNC_STATE_SYNC_FLUSH2:
		break;
	case DSYNC_STATE_SYNC_END:
		master_service_stop(master_service);
		break;
	default:
		i_unreached();
	}
}

void dsync_brain_sync_all(struct dsync_brain *brain)
{
	enum dsync_state old_state;

	while (brain->state != DSYNC_STATE_SYNC_END) {
		old_state = brain->state;
		dsync_brain_sync(brain);

		if (dsync_worker_has_failed(brain->src_worker) ||
		    dsync_worker_has_failed(brain->dest_worker))
			break;

		i_assert(brain->state != old_state);
	}
}

bool dsync_brain_has_unexpected_changes(struct dsync_brain *brain)
{
	return brain->unexpected_changes ||
		dsync_worker_has_unexpected_changes(brain->src_worker) ||
		dsync_worker_has_unexpected_changes(brain->dest_worker);
}

bool dsync_brain_has_failed(struct dsync_brain *brain)
{
	return brain->failed ||
		dsync_worker_has_failed(brain->src_worker) ||
		dsync_worker_has_failed(brain->dest_worker);
}
