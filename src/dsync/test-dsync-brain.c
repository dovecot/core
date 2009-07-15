/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "sha1.h"
#include "master-service.h"
#include "dsync-brain-private.h"
#include "test-common.h"
#include "test-dsync-worker.h"
#include "test-dsync-common.h"

#include <stdlib.h>

enum {
	FLAG_EXISTS	= 0x01,
	FLAG_CREATED	= 0x02,
};

struct test_dsync_mailbox {
	struct dsync_mailbox box;
	struct dsync_message *src_msgs, *dest_msgs;
	unsigned int dest_flags;
};

static const char *kw12[] = { "kw1", "kw2", NULL };

static struct dsync_message box1_src_msgs[] = {
	{ "guid1", 3, MAIL_SEEN, kw12, 123, 987 },
	{ "guid2", 5, MAIL_DRAFT, NULL, 125, 989 },
	{ "guid3", 8, 0, NULL, 128, 990 },
	{ NULL, 0, 0, NULL, 0, 0 }
};
static struct dsync_message box1_dest_msgs[] = {
	{ "guid1", 3, MAIL_FLAGGED, NULL, 123, 987 },
	{ "guid2", 5, MAIL_DRAFT, kw12, 125, 989 },
	{ NULL, 0, 0, NULL, 0, 0 }
};

static struct dsync_message box2_src_msgs[] = {
	{ "guid2", 6, MAIL_ANSWERED | MAIL_FLAGGED, NULL, 3434, 6552354 },
	{ "guid4", 10, 0, NULL, 3426, 43643 },
	{ NULL, 0, 0, NULL, 0, 0 }
};

static struct dsync_message box3_src_msgs[] = {
	{ "guid1", 1, MAIL_FLAGGED, NULL, 5454, 273850 },
	{ "guid5", 5, 0, NULL, 331, 38701233 },
	{ "b75c81f2b3a4c9f84f24851c37acedee", 6, DSYNC_MAIL_FLAG_EXPUNGED, NULL, 331, 38701233 },
	{ NULL, 0, 0, NULL, 0, 0 }
};
static struct dsync_message box3_dest_msgs[] = {
	{ "guid1", 1, MAIL_FLAGGED, NULL, 5454, 273850 },
	{ "guid8", 3, 0, NULL, 330, 2424 },
	{ "guid5", 5, 0, NULL, 1, 38701233 },
	{ "guid6", 6, 0, NULL, 333, 6482 },
	{ "guid7", 7, 0, NULL, 333, 6482 },
	{ NULL, 0, 0, NULL, 0, 0 }
};

static struct test_dsync_mailbox basic_mailboxes[] = {
	{ { "box1", { { 0x12, 0x34, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		        0x21, 0x43, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe } },
	    1234567890, 4321, 605040302010ULL },
	  box1_src_msgs, box1_dest_msgs, FLAG_EXISTS },
	{ { "box2", { { 0xa3, 0xbd, 0x78, 0x24, 0xde, 0xfe, 0x08, 0xf7,
		        0xac, 0xc7, 0xca, 0x8c, 0xe7, 0x39, 0xdb, 0xca } },
	    554321023, 6767, 79 },
	  box2_src_msgs, NULL, 0 },
	{ { "box3", { { 0x46, 0x25, 0xb3, 0x24, 0xde, 0xfe, 0x08, 0xf7,
		        0xac, 0xc7, 0xca, 0x1a, 0xe7, 0x39, 0xdb, 0x54 } },
	    4545454, 656, 2366 }, box3_src_msgs,
	  box3_dest_msgs, FLAG_EXISTS },
	{ { "dir1", { { 0, } }, 0, 0, 0 }, NULL, NULL, FLAG_EXISTS },
	{ { "dir2", { { 0, } }, 0, 0, 0 }, NULL, NULL, 0 },
	{ { NULL, { { 0, } }, 0, 0, 0 }, NULL, NULL, 0 }
};

static struct test_dsync_mailbox *mailboxes;
struct master_service *master_service;

void master_service_stop(struct master_service *master_service ATTR_UNUSED)
{
}

void mail_generate_guid_128_hash(const char *guid,
				 uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	unsigned char sha1_sum[SHA1_RESULTLEN];

	sha1_get_digest(guid, strlen(guid), sha1_sum);
	memcpy(guid_128, sha1_sum, MAIL_GUID_128_SIZE);
}

static bool mailbox_find(const char *name, unsigned int *idx_r)
{
	unsigned int i;

	for (i = 0; mailboxes[i].box.name != NULL; i++) {
		if (strcmp(mailboxes[i].box.name, name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

static int test_dsync_mailbox_cmp(const void *p1, const void *p2)
{
	const struct test_dsync_mailbox *t1 = p1, *t2 = p2;

	return dsync_mailbox_guid_cmp(&t1->box, &t2->box);
}

static void test_dsync_sync_msgs(struct test_dsync_worker *worker, bool dest)
{
	struct test_dsync_worker_msg test_msg;
	struct dsync_message *msgs;
	unsigned int i, j;

	for (i = 0; mailboxes[i].box.name != NULL; i++) {
		msgs = dest ? mailboxes[i].dest_msgs : mailboxes[i].src_msgs;
		if (msgs == NULL)
			continue;

		for (j = 0; msgs[j].guid != NULL; j++) {
			test_msg.msg = msgs[j];
			test_msg.mailbox_idx = i;
			array_append(&worker->msg_iter.msgs, &test_msg, 1);
			worker->worker.input_callback(worker->worker.input_context);
		}
	}

	worker->msg_iter.last = TRUE;
	worker->worker.input_callback(worker->worker.input_context);
}

static int test_dsync_msg_event_cmp(const struct test_dsync_msg_event *e1,
				    const struct test_dsync_msg_event *e2)
{
	int ret;

	ret = memcmp(e1->mailbox.guid, e2->mailbox.guid,
		     sizeof(e1->mailbox.guid));
	if (ret != 0)
		return ret;

	return (int)e1->msg.uid - (int)e2->msg.uid;
}

static bool test_dsync_msg_find_guid(const struct test_dsync_mailbox *box,
				     const struct dsync_message *msg,
				     const struct test_dsync_mailbox **box2_r,
				     const struct dsync_message **msg2_r)
{
	unsigned int i, j;

	for (i = 0; mailboxes[i].box.name != NULL; i++) {
		if (mailboxes[i].src_msgs == NULL)
			continue;

		for (j = 0; mailboxes[i].src_msgs[j].guid != NULL; j++) {
			if (strcmp(mailboxes[i].src_msgs[j].guid, msg->guid) != 0)
				continue;

			if (memcmp(mailboxes[i].box.guid.guid, box->box.guid.guid,
				   MAILBOX_GUID_SIZE) != 0 ||
			    mailboxes[i].src_msgs[j].uid != msg->uid) {
				*box2_r = &mailboxes[i];
				*msg2_r = &mailboxes[i].src_msgs[j];
				return TRUE;
			}
		}
	}
	return FALSE;
}

static void
test_dsync_brain_verify_existing_one(const struct test_dsync_mailbox *box,
				     const struct test_dsync_msg_event *event,
				     const struct dsync_message *src)
{
	test_assert(event->msg.guid != NULL);
	test_assert(event->type == LAST_MSG_TYPE_UPDATE);
	test_assert(memcmp(event->mailbox.guid, box->box.guid.guid,
			   MAILBOX_GUID_SIZE) == 0);
	test_assert(event->msg.flags == src->flags);
	test_assert(dsync_keyword_list_equals(event->msg.keywords,
					      src->keywords));
	test_assert(event->msg.modseq == src->modseq);
}

static void
test_dsync_brain_verify_existing(const struct test_dsync_mailbox *box,
				 const struct test_dsync_msg_event **eventsp,
				 unsigned int *idx_r)
{
	const struct test_dsync_msg_event *event = *eventsp;
	unsigned int i, j;

	/* we don't try to handle uid conflicts here */
	i = j = 0;
	while (box->src_msgs[i].guid != NULL && box->dest_msgs[j].guid != NULL) {
		if (box->src_msgs[i].uid < box->dest_msgs[j].uid) {
			/* need to add message to dest */
			i++;
		} else if (box->src_msgs[i].uid > box->dest_msgs[j].uid) {
			/* message expunged from src */
			test_assert(event->type == LAST_MSG_TYPE_EXPUNGE);
			test_assert(memcmp(event->mailbox.guid, box->box.guid.guid,
					   MAILBOX_GUID_SIZE) == 0);
			test_assert(event->msg.uid == box->dest_msgs[j].uid);
			j++; event++;
		} else if (box->src_msgs[i].flags == DSYNC_MAIL_FLAG_EXPUNGED) {
			/* message expunged from end of mailbox */
			test_assert(event->type == LAST_MSG_TYPE_EXPUNGE);
			test_assert(event->msg.uid == box->dest_msgs[j].uid);
			i++; j++; event++;
		} else if (box->src_msgs[i].modseq > box->dest_msgs[j].modseq ||
			   box->src_msgs[i].flags != box->dest_msgs[j].flags ||
			   !dsync_keyword_list_equals(box->src_msgs[i].keywords,
						      box->dest_msgs[j].keywords)) {
			/* message changed */
			i_assert(strcmp(box->src_msgs[i].guid,
					box->dest_msgs[j].guid) == 0);

			test_dsync_brain_verify_existing_one(box, event,
							     &box->src_msgs[i]);
			i++; j++; event++;
		} else {
			/* message unchanged */
			i_assert(strcmp(box->src_msgs[i].guid,
					box->dest_msgs[j].guid) == 0);
			i++; j++;
		}
	}
	while (box->dest_msgs[j].guid != NULL) {
		/* message expunged from src */
		test_assert(event->type == LAST_MSG_TYPE_EXPUNGE);
		test_assert(memcmp(event->mailbox.guid, box->box.guid.guid,
				   MAILBOX_GUID_SIZE) == 0);
		test_assert(event->msg.uid == box->dest_msgs[j].uid);
		j++; event++;
	}
	*idx_r = i;
	*eventsp = event;
}

static void
test_dsync_brain_verify_mailbox(const struct test_dsync_mailbox *box,
				const struct test_dsync_msg_event **eventsp)
{
	const struct test_dsync_msg_event *event = *eventsp;
	const struct test_dsync_mailbox *box2;
	const struct dsync_message *msgs, *msg2;
	unsigned int i = 0;

	if (box->src_msgs == NULL)
		return;

	msgs = box->src_msgs;
	if (box->dest_msgs != NULL) {
		/* sync existing messages */
		test_dsync_brain_verify_existing(box, &event, &i);
	}

	/* sync new messages */
	for (; msgs[i].guid != NULL; i++) {
		test_assert(event->msg.guid != NULL);
		test_assert(memcmp(event->mailbox.guid, box->box.guid.guid,
				   MAILBOX_GUID_SIZE) == 0);
		if (test_dsync_msg_find_guid(box, &msgs[i], &box2, &msg2)) {
			test_assert(event->type == LAST_MSG_TYPE_COPY);
			test_assert(memcmp(event->copy_src_mailbox.guid,
					   box2->box.guid.guid,
					   MAILBOX_GUID_SIZE) == 0);
			test_assert(event->copy_src_uid == msg2->uid);
		} else {
			test_assert(event->type == LAST_MSG_TYPE_SAVE);
			test_assert(strcmp(event->save_body,
					   "hdr\n\nbody") == 0);
		}
		test_assert(strcmp(event->msg.guid, msgs[i].guid) == 0);
		test_assert(event->msg.uid == msgs[i].uid);
		test_assert(event->msg.flags == msgs[i].flags);
		test_assert(dsync_keyword_list_equals(event->msg.keywords,
						      msgs[i].keywords));
		test_assert(event->msg.modseq == msgs[i].modseq);
		test_assert(event->msg.save_date == msgs[i].save_date);

		event++;
	}

	*eventsp = event;
}

static void
test_dsync_brain_verify_msg_events(struct test_dsync_worker *dest_test_worker)
{
	ARRAY_DEFINE(msg_events, struct test_dsync_msg_event);
	const struct test_dsync_msg_event *events, *events_end;
	struct test_dsync_msg_event msg_event;
	unsigned int i, event_count;

	/* get events and sort them so we can easily check if they're correct */
	t_array_init(&msg_events, 64);
	while (test_dsync_worker_next_msg_event(dest_test_worker, &msg_event))
		array_append(&msg_events, &msg_event, 1);
	array_sort(&msg_events, test_dsync_msg_event_cmp);

	events = array_get(&msg_events, &event_count);
	events_end = events + event_count;
	for (i = 0; mailboxes[i].box.name != NULL; i++)
		test_dsync_brain_verify_mailbox(&mailboxes[i], &events);
	test_assert(events == events_end);
}

static void
test_dsync_brain_run(const struct test_dsync_mailbox *test_mailboxes,
		     void (*verify_func)(struct test_dsync_worker *))
{
	struct dsync_brain *brain;
	struct dsync_worker *src_worker, *dest_worker;
	struct test_dsync_worker *src_test_worker, *dest_test_worker;
	struct dsync_mailbox new_box;
	struct test_dsync_box_event box_event;
	unsigned int i, box_count;

	box_count = 0;
	while (test_mailboxes[box_count].box.name != NULL)
		box_count++;

	mailboxes = t_new(struct test_dsync_mailbox, box_count + 1);
	memcpy(mailboxes, test_mailboxes, sizeof(*mailboxes) * box_count);

	src_worker = dsync_worker_init_test();
	dest_worker = dsync_worker_init_test();
	src_test_worker = (struct test_dsync_worker *)src_worker;
	dest_test_worker = (struct test_dsync_worker *)dest_worker;

	brain = dsync_brain_init(src_worker, dest_worker);
	dsync_brain_sync(brain);

	/* have brain read the mailboxes */
	for (i = 0; mailboxes[i].box.name != NULL; i++) {
		src_test_worker->box_iter.next_box = &mailboxes[i].box;
		src_worker->input_callback(src_worker->input_context);

		if (mailboxes[i].dest_flags & FLAG_EXISTS) {
			dest_test_worker->box_iter.next_box = &mailboxes[i].box;
			dest_worker->input_callback(dest_worker->input_context);
		}
	}
	src_test_worker->box_iter.last = TRUE;
	src_worker->input_callback(src_worker->input_context);
	dest_test_worker->box_iter.last = TRUE;
	dest_worker->input_callback(dest_worker->input_context);

	/* check that it created missing mailboxes */
	while (test_dsync_worker_next_box_event(dest_test_worker, &box_event)) {
		test_assert(box_event.type == LAST_BOX_TYPE_CREATE);
		test_assert(mailbox_find(box_event.box.name, &i));
		test_assert(mailboxes[i].dest_flags == 0);
		mailboxes[i].dest_flags |= FLAG_CREATED;

		new_box = mailboxes[i].box;
		new_box.uid_next = 0;
		new_box.highest_modseq = 0;
		test_assert(dsync_mailboxes_equal(&box_event.box, &new_box));
	}

	/* brain wants mailboxes in guid order. make things easier for us
	   by sorting them now. */
	qsort(mailboxes, box_count, sizeof(*mailboxes),
	      test_dsync_mailbox_cmp);

	/* start syncing messages */
	test_assert(dest_test_worker->msg_iter_mailbox_count == box_count);
	for (i = 0; mailboxes[i].box.name != NULL; i++) {
		test_assert(memcmp(&dest_test_worker->msg_iter_mailboxes[i],
				   mailboxes[i].box.guid.guid, MAILBOX_GUID_SIZE) == 0);
	}
	test_dsync_sync_msgs(src_test_worker, FALSE);
	test_dsync_sync_msgs(dest_test_worker, TRUE);

	verify_func(dest_test_worker);

	dsync_worker_deinit(&src_worker);
	dsync_worker_deinit(&dest_worker);
	dsync_brain_deinit(&brain);
}

static void test_dsync_brain(void)
{
	test_begin("dsync brain basics");
	test_dsync_brain_run(basic_mailboxes,
			     test_dsync_brain_verify_msg_events);
	test_end();
}

static struct dsync_message conflict_src_msgs[] = {
	{ "guid1", 1, 0, NULL, 1, 1 },
	{ "guid3", 3, 0, NULL, 1, 1 },
	{ "guid5", 5, 0, NULL, 1, 1 },
	{ "guidy", 6, 0, NULL, 1, 1 },
	{ "67ddfe2125de633c56e033b57c897018", 7, DSYNC_MAIL_FLAG_EXPUNGED, NULL, 1, 1 },
	{ "guidz", 8, DSYNC_MAIL_FLAG_EXPUNGED, NULL, 1, 1 },
	{ NULL, 0, 0, NULL, 0, 0 }
};
static struct dsync_message conflict_dest_msgs[] = {
	{ "guid1", 1, 0, NULL, 1, 1 },
	{ "guid2", 2, 0, NULL, 1, 1 },
	{ "guidx", 3, 0, NULL, 1, 1 },
	{ "guid4", 4, 0, NULL, 1, 1 },
	{ "guid5", 5, 0, NULL, 1, 1 },
	{ "guid7", 7, 0, NULL, 1, 1 },
	{ "guid8", 8, 0, NULL, 1, 1 },
	{ NULL, 0, 0, NULL, 0, 0 }
};

static struct test_dsync_mailbox conflict_mailboxes[] = {
	{ { "box1", { { 0x12, 0x34, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		        0x21, 0x43, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe } },
	    1234567890, 4321, 888 },
	  conflict_src_msgs, conflict_dest_msgs, FLAG_EXISTS },
	{ { NULL, { { 0, } }, 0, 0, 0 }, NULL, NULL, 0 }
};

static void
test_dsync_brain_verify_uid_conflict(struct test_dsync_worker *dest_test_worker)
{
	struct test_dsync_msg_event event;
	struct test_dsync_box_event box_event;

	test_assert(test_dsync_worker_next_msg_event(dest_test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(event.msg.uid == 2);

	test_assert(test_dsync_worker_next_msg_event(dest_test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(event.msg.uid == 7);

	test_assert(test_dsync_worker_next_msg_event(dest_test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_SAVE);
	test_assert(event.msg.uid == 4321);
	test_assert(strcmp(event.msg.guid, "guid3") == 0);

	test_assert(test_dsync_worker_next_msg_event(dest_test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_SAVE);
	test_assert(event.msg.uid == 6);
	test_assert(strcmp(event.msg.guid, "guidy") == 0);

	test_assert(test_dsync_worker_next_msg_event(dest_test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_UPDATE_UID);
	test_assert(event.msg.uid == 3);

	test_assert(test_dsync_worker_next_msg_event(dest_test_worker, &event));
	test_assert(event.type == LAST_MSG_TYPE_UPDATE_UID);
	test_assert(event.msg.uid == 8);

	test_assert(!test_dsync_worker_next_msg_event(dest_test_worker, &event));

	while (test_dsync_worker_next_box_event(dest_test_worker, &box_event) &&
	       box_event.type == LAST_BOX_TYPE_SELECT) ;

	test_assert(box_event.type == LAST_BOX_TYPE_UPDATE);
	test_assert(box_event.box.uid_next == 4322);
	test_assert(box_event.box.uid_validity == 1234567890);
	test_assert(box_event.box.highest_modseq == 888);

	while (test_dsync_worker_next_box_event(dest_test_worker, &box_event))
		test_assert(box_event.type == LAST_BOX_TYPE_SELECT);
}

static void test_dsync_brain_uid_conflict(void)
{
	test_begin("dsync brain uid conflict");
	test_dsync_brain_run(conflict_mailboxes,
			     test_dsync_brain_verify_uid_conflict);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_dsync_brain,
		test_dsync_brain_uid_conflict,
		NULL
	};
	return test_run(test_functions);
}
