/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "master-service.h"
#include "dsync-brain-private.h"
#include "test-dsync-worker.h"
#include "test-dsync-common.h"

struct master_service *master_service;
static struct test_dsync_worker *src_test_worker, *dest_test_worker;

void master_service_stop(struct master_service *master_service ATTR_UNUSED)
{
}

struct dsync_brain_mailbox_sync *
dsync_brain_msg_sync_init(struct dsync_brain *brain,
			  const ARRAY_TYPE(dsync_brain_mailbox) *mailboxes)
{
	struct dsync_brain_mailbox_sync *sync;

	sync = i_new(struct dsync_brain_mailbox_sync, 1);
	sync->brain = brain;
	i_array_init(&sync->mailboxes, array_count(mailboxes));
	array_append_array(&sync->mailboxes, mailboxes);
	return sync;
}
void dsync_brain_msg_sync_more(struct dsync_brain_mailbox_sync *sync ATTR_UNUSED) {}

void dsync_brain_msg_sync_deinit(struct dsync_brain_mailbox_sync **_sync)
{
	array_free(&(*_sync)->mailboxes);
	i_free(*_sync);
}

static void mailboxes_set_guids(struct dsync_mailbox *boxes)
{
	for (; boxes->name != NULL; boxes++) {
		dsync_str_sha_to_guid(t_strconcat("box-", boxes->name, NULL),
				      &boxes->mailbox_guid);
		dsync_str_sha_to_guid(boxes->name, &boxes->name_sha1);
	}
}

static void mailboxes_send_to_worker(struct test_dsync_worker *test_worker,
				     struct dsync_mailbox *boxes)
{
	unsigned int i;

	for (i = 0; boxes[i].name != NULL; i++) {
		test_worker->box_iter.next_box = &boxes[i];
		test_worker->worker.input_callback(test_worker->worker.input_context);
	}
	test_worker->box_iter.last = TRUE;
	test_worker->worker.input_callback(test_worker->worker.input_context);
}

static void subscriptions_send_to_worker(struct test_dsync_worker *test_worker)
{
	test_worker->subs_iter.last_subs = TRUE;
	test_worker->subs_iter.last_unsubs = TRUE;
	test_worker->worker.input_callback(test_worker->worker.input_context);
}

static bool
test_dsync_mailbox_create_equals(const struct dsync_mailbox *cbox,
				 const struct dsync_mailbox *obox)
{
	return strcmp(cbox->name, obox->name) == 0 &&
		memcmp(cbox->mailbox_guid.guid, obox->mailbox_guid.guid,
		       sizeof(cbox->mailbox_guid.guid)) == 0 &&
		memcmp(cbox->name_sha1.guid, obox->name_sha1.guid,
		       sizeof(cbox->name_sha1.guid)) == 0 &&
		cbox->uid_validity == obox->uid_validity &&
		cbox->uid_next == 1 && cbox->highest_modseq == 0;
}

static bool
test_dsync_mailbox_delete_equals(const struct dsync_mailbox *dbox,
				 const struct dsync_mailbox *obox)
{
	return memcmp(dbox->mailbox_guid.guid, obox->mailbox_guid.guid,
		      sizeof(dbox->mailbox_guid.guid)) == 0 &&
		dbox->last_change == obox->last_change;
}

static void
test_dsync_mailbox_update(const struct dsync_mailbox *bbox,
			  const struct dsync_mailbox *box)
{
	struct test_dsync_box_event src_event, dest_event;

	test_assert(test_dsync_worker_next_box_event(src_test_worker, &src_event));
	test_assert(test_dsync_worker_next_box_event(dest_test_worker, &dest_event));
	test_assert(src_event.type == dest_event.type &&
		    dsync_mailboxes_equal(&src_event.box, &dest_event.box));

	test_assert(src_event.type == LAST_BOX_TYPE_UPDATE);
	test_assert(dsync_mailboxes_equal(&src_event.box, box));
	test_assert(dsync_mailboxes_equal(bbox, box));
}

static int
dsync_brain_mailbox_name_cmp(const struct dsync_brain_mailbox *box1,
			     const struct dsync_brain_mailbox *box2)
{
	return strcmp(box1->box.name, box2->box.name);
}

static void test_dsync_brain(void)
{
	static struct dsync_mailbox src_boxes[] = {
		{ "box1", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box2", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box3", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box4", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box5", '/', { { 0, } }, { { 0, } }, 1234567890, 5433, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box6", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123124ULL, 3636, 0, ARRAY_INIT },
		{ "boxx", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "boxd1", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "boxd2", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, DSYNC_MAILBOX_FLAG_DELETED_MAILBOX, ARRAY_INIT },
		{ NULL, 0, { { 0, } }, { { 0, } }, 0, 0, 0, 0, 0, 0, 0, ARRAY_INIT }
	};
	static struct dsync_mailbox dest_boxes[] = {
		{ "box1", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box2", '/', { { 0, } }, { { 0, } }, 1234567891, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box3", '/', { { 0, } }, { { 0, } }, 1234567890, 5433, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box4", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123124ULL, 3636, 0, ARRAY_INIT },
		{ "box5", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "box6", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "boxy", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ "boxd1", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, DSYNC_MAILBOX_FLAG_DELETED_MAILBOX, ARRAY_INIT },
		{ "boxd2", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 3636, 0, ARRAY_INIT },
		{ NULL, 0, { { 0, } }, { { 0, } }, 0, 0, 0, 0, 0, 0, 0, ARRAY_INIT }
	};
	struct dsync_brain *brain;
	struct dsync_worker *src_worker, *dest_worker;
	struct test_dsync_box_event box_event;
	const struct dsync_brain_mailbox *brain_boxes;
	unsigned int i, count;

	test_begin("dsync brain");

	mailboxes_set_guids(src_boxes);
	mailboxes_set_guids(dest_boxes);

	src_worker = dsync_worker_init_test();
	dest_worker = dsync_worker_init_test();
	src_test_worker = (struct test_dsync_worker *)src_worker;
	dest_test_worker = (struct test_dsync_worker *)dest_worker;

	brain = dsync_brain_init(src_worker, dest_worker, NULL,
				 DSYNC_BRAIN_FLAG_LOCAL);
	dsync_brain_sync(brain);

	/* have brain read the mailboxes */
	mailboxes_send_to_worker(src_test_worker, src_boxes);
	mailboxes_send_to_worker(dest_test_worker, dest_boxes);

	subscriptions_send_to_worker(src_test_worker);
	subscriptions_send_to_worker(dest_test_worker);

	test_assert(brain->state == DSYNC_STATE_SYNC_MSGS);

	/* check that it created/deleted missing mailboxes */
	test_assert(test_dsync_worker_next_box_event(dest_test_worker, &box_event));
	test_assert(box_event.type == LAST_BOX_TYPE_DELETE);
	test_assert(test_dsync_mailbox_delete_equals(&box_event.box, &dest_boxes[8]));

	test_assert(test_dsync_worker_next_box_event(src_test_worker, &box_event));
	test_assert(box_event.type == LAST_BOX_TYPE_DELETE);
	test_assert(test_dsync_mailbox_delete_equals(&box_event.box, &src_boxes[7]));

	test_assert(test_dsync_worker_next_box_event(dest_test_worker, &box_event));
	test_assert(box_event.type == LAST_BOX_TYPE_CREATE);
	test_assert(test_dsync_mailbox_create_equals(&box_event.box, &src_boxes[6]));

	test_assert(test_dsync_worker_next_box_event(src_test_worker, &box_event));
	test_assert(box_event.type == LAST_BOX_TYPE_CREATE);
	test_assert(test_dsync_mailbox_create_equals(&box_event.box, &dest_boxes[6]));

	test_assert(!test_dsync_worker_next_box_event(src_test_worker, &box_event));
	test_assert(!test_dsync_worker_next_box_event(dest_test_worker, &box_event));

	array_sort(&brain->mailbox_sync->mailboxes,
		   dsync_brain_mailbox_name_cmp);

	/* check mailbox updates */
	brain->state++;
	dsync_brain_sync(brain);
	test_assert(brain->state == DSYNC_STATE_SYNC_UPDATE_MAILBOXES);
	dsync_brain_sync(brain);
	test_assert(brain->state == DSYNC_STATE_SYNC_END);

	brain_boxes = array_get(&brain->mailbox_sync->mailboxes, &count);
	test_assert(count == 7);
	for (i = 0; i < 5; i++) {
		test_assert(dsync_mailboxes_equal(brain_boxes[i].src, &src_boxes[i+1]));
		test_assert(dsync_mailboxes_equal(brain_boxes[i].dest, &dest_boxes[i+1]));
	}
	test_assert(dsync_mailboxes_equal(brain_boxes[5].src, &src_boxes[6]));
	test_assert(brain_boxes[5].dest == NULL);
	test_assert(brain_boxes[6].src == NULL);
	test_assert(dsync_mailboxes_equal(brain_boxes[6].dest, &dest_boxes[6]));

	test_dsync_mailbox_update(&brain_boxes[0].box, &src_boxes[1]);
	test_dsync_mailbox_update(&brain_boxes[1].box, &dest_boxes[2]);
	test_dsync_mailbox_update(&brain_boxes[2].box, &dest_boxes[3]);
	test_dsync_mailbox_update(&brain_boxes[3].box, &src_boxes[4]);
	test_dsync_mailbox_update(&brain_boxes[4].box, &src_boxes[5]);
	test_dsync_mailbox_update(&brain_boxes[5].box, &src_boxes[6]);
	test_dsync_mailbox_update(&brain_boxes[6].box, &dest_boxes[6]);

	test_assert(!test_dsync_worker_next_box_event(src_test_worker, &box_event));
	test_assert(!test_dsync_worker_next_box_event(dest_test_worker, &box_event));

	dsync_brain_deinit(&brain);
	dsync_worker_deinit(&src_worker);
	dsync_worker_deinit(&dest_worker);

	test_end();
}

static void test_dsync_brain_full(void)
{
	static struct dsync_mailbox boxes[] = {
		{ "box1", '/', { { 0, } }, { { 0, } }, 1234567890, 5432, 0, 1, 123123123123ULL, 2352, 0, ARRAY_INIT },
		{ NULL, 0, { { 0, } }, { { 0, } }, 0, 0, 0, 0, 0, 0, 0, ARRAY_INIT }
	};
	struct dsync_brain *brain;
	struct dsync_worker *src_worker, *dest_worker;
	struct test_dsync_box_event box_event;
	const struct dsync_brain_mailbox *brain_boxes;
	unsigned int count;

	test_begin("dsync brain full");

	mailboxes_set_guids(boxes);

	src_worker = dsync_worker_init_test();
	dest_worker = dsync_worker_init_test();
	src_test_worker = (struct test_dsync_worker *)src_worker;
	dest_test_worker = (struct test_dsync_worker *)dest_worker;

	brain = dsync_brain_init(src_worker, dest_worker, NULL,
				 DSYNC_BRAIN_FLAG_FULL_SYNC |
				 DSYNC_BRAIN_FLAG_LOCAL);
	dsync_brain_sync(brain);

	/* have brain read the mailboxes */
	mailboxes_send_to_worker(src_test_worker, boxes);
	mailboxes_send_to_worker(dest_test_worker, boxes);

	subscriptions_send_to_worker(src_test_worker);
	subscriptions_send_to_worker(dest_test_worker);

	test_assert(brain->state == DSYNC_STATE_SYNC_MSGS);

	test_assert(!test_dsync_worker_next_box_event(src_test_worker, &box_event));
	test_assert(!test_dsync_worker_next_box_event(dest_test_worker, &box_event));

	/* check mailbox updates */
	brain->state++;
	dsync_brain_sync(brain);
	test_assert(brain->state == DSYNC_STATE_SYNC_UPDATE_MAILBOXES);
	dsync_brain_sync(brain);
	test_assert(brain->state == DSYNC_STATE_SYNC_END);

	brain_boxes = array_get(&brain->mailbox_sync->mailboxes, &count);
	test_assert(count == 1);
	test_assert(dsync_mailboxes_equal(brain_boxes[0].src, &boxes[0]));
	test_assert(dsync_mailboxes_equal(brain_boxes[0].dest, &boxes[0]));
	test_dsync_mailbox_update(&brain_boxes[0].box, &boxes[0]);

	test_assert(!test_dsync_worker_next_box_event(src_test_worker, &box_event));
	test_assert(!test_dsync_worker_next_box_event(dest_test_worker, &box_event));

	dsync_brain_deinit(&brain);
	dsync_worker_deinit(&src_worker);
	dsync_worker_deinit(&dest_worker);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_dsync_brain,
		test_dsync_brain_full,
		NULL
	};
	return test_run(test_functions);
}
