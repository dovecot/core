/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "dsync-brain-private.h"
#include "test-dsync-worker.h"
#include "test-dsync-common.h"

enum test_box_add_type {
	ADD_SRC,
	ADD_DEST,
	ADD_BOTH
};

struct test_dsync_mailbox {
	struct dsync_brain_mailbox box;
	ARRAY_DEFINE(src_msgs, struct dsync_message);
	ARRAY_DEFINE(dest_msgs, struct dsync_message);
};
ARRAY_DEFINE_TYPE(test_dsync_mailbox, struct test_dsync_mailbox);

static ARRAY_TYPE(test_dsync_mailbox) mailboxes;
static struct test_dsync_worker *test_src_worker, *test_dest_worker;

void dsync_brain_fail(struct dsync_brain *brain ATTR_UNUSED) {}
void dsync_brain_msg_sync_new_msgs(struct dsync_brain_mailbox_sync *sync ATTR_UNUSED) {}

static struct test_dsync_mailbox *test_box_find(const char *name)
{
	struct test_dsync_mailbox *boxes;
	unsigned int i, count;

	boxes = array_get_modifiable(&mailboxes, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(boxes[i].box.box.name, name) == 0)
			return &boxes[i];
	}
	return NULL;
}

static bool
test_box_has_guid(const char *name, const mailbox_guid_t *guid)
{
	const struct test_dsync_mailbox *box;

	box = test_box_find(name);
	return box != NULL &&
		memcmp(box->box.box.mailbox_guid.guid, guid->guid,
		       sizeof(box->box.box.mailbox_guid.guid)) == 0;
}

static struct test_dsync_mailbox *
test_box_add(enum test_box_add_type type, const char *name)
{
	struct test_dsync_mailbox *tbox;
	struct dsync_mailbox *box;

	tbox = test_box_find(name);
	if (tbox == NULL) {
		tbox = array_append_space(&mailboxes);
		i_array_init(&tbox->src_msgs, 16);
		i_array_init(&tbox->dest_msgs, 16);
	}

	box = i_new(struct dsync_mailbox, 1);
	box->name = i_strdup(name);

	dsync_str_sha_to_guid(t_strconcat("box-", name, NULL),
			      &box->mailbox_guid);
	dsync_str_sha_to_guid(name, &box->name_sha1);

	box->uid_validity = crc32_str(name);
	box->highest_modseq = 1;

	switch (type) {
	case ADD_SRC:
		tbox->box.src = box;
		break;
	case ADD_DEST:
		tbox->box.dest = box;
		break;
	case ADD_BOTH:
		tbox->box.src = box;
		tbox->box.dest = box;
		break;
	}
	tbox->box.box.name = box->name;
	tbox->box.box.mailbox_guid = box->mailbox_guid;
	tbox->box.box.name_sha1 = box->name_sha1;
	tbox->box.box.uid_validity = box->uid_validity;
	return tbox;
}

static void test_msg_add(struct test_dsync_mailbox *box,
			 enum test_box_add_type type,
			 const char *guid, uint32_t uid)
{
	static int msg_date = 0;
	struct dsync_message msg;

	memset(&msg, 0, sizeof(msg));
	msg.guid = i_strdup(guid);
	msg.uid = uid;
	msg.modseq = ++box->box.box.highest_modseq;
	msg.save_date = ++msg_date;

	switch (type) {
	case ADD_SRC:
		box->box.src->highest_modseq++;
		box->box.src->uid_next = uid + 1;
		array_append(&box->src_msgs, &msg, 1);
		break;
	case ADD_DEST:
		box->box.dest->highest_modseq++;
		box->box.dest->uid_next = uid + 1;
		array_append(&box->dest_msgs, &msg, 1);
		break;
	case ADD_BOTH:
		box->box.src->highest_modseq++;
		box->box.dest->highest_modseq++;
		box->box.src->uid_next = uid + 1;
		box->box.dest->uid_next = uid + 1;
		array_append(&box->src_msgs, &msg, 1);
		array_append(&box->dest_msgs, &msg, 1);
		break;
	}
	if (box->box.box.uid_next <= uid)
		box->box.box.uid_next = uid + 1;
}

static void test_msg_set_modseq(struct test_dsync_mailbox *box,
				enum test_box_add_type type,
				uint32_t uid, uint64_t modseq)
{
	struct dsync_message *msgs;
	unsigned int i, count;

	i_assert(modseq <= box->box.box.highest_modseq);
	if (type != ADD_DEST) {
		msgs = array_get_modifiable(&box->src_msgs, &count);
		for (i = 0; i < count; i++) {
			if (msgs[i].uid == uid) {
				msgs[i].modseq = modseq;
				break;
			}
		}
		i_assert(i < count);
	}
	if (type != ADD_SRC) {
		msgs = array_get_modifiable(&box->dest_msgs, &count);
		for (i = 0; i < count; i++) {
			if (msgs[i].uid == uid) {
				msgs[i].modseq = modseq;
				break;
			}
		}
		i_assert(i < count);
	}
}

static void test_msg_set_flags(struct test_dsync_mailbox *box,
			       enum test_box_add_type type,
			       uint32_t uid, enum mail_flags flags)
{
	unsigned char guid_128_data[MAIL_GUID_128_SIZE * 2 + 1];
	struct dsync_message *msgs;
	unsigned int i, count;

	box->box.box.highest_modseq++;
	if (type != ADD_DEST) {
		box->box.src->highest_modseq = box->box.box.highest_modseq;
		msgs = array_get_modifiable(&box->src_msgs, &count);
		for (i = 0; i < count; i++) {
			if (msgs[i].uid == uid) {
				if ((flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0) {
					msgs[i].guid = i_strdup(dsync_get_guid_128_str(msgs[i].guid,
						guid_128_data, sizeof(guid_128_data)));
				}
				msgs[i].flags = flags;
				msgs[i].modseq = box->box.src->highest_modseq;
				break;
			}
		}
		i_assert(i < count);
	}
	if (type != ADD_SRC) {
		box->box.dest->highest_modseq = box->box.box.highest_modseq;
		msgs = array_get_modifiable(&box->dest_msgs, &count);
		for (i = 0; i < count; i++) {
			if (msgs[i].uid == uid) {
				if ((flags & DSYNC_MAIL_FLAG_EXPUNGED) != 0) {
					msgs[i].guid = i_strdup(dsync_get_guid_128_str(msgs[i].guid,
						guid_128_data, sizeof(guid_128_data)));
				}
				msgs[i].flags = flags;
				msgs[i].modseq = box->box.dest->highest_modseq;
				break;
			}
		}
		i_assert(i < count);
	}
}

static void ATTR_SENTINEL
test_msg_set_keywords(struct test_dsync_mailbox *box,
		      enum test_box_add_type type,
		      uint32_t uid, const char *kw, ...)
{
	struct dsync_message *msgs;
	unsigned int i, count;
	va_list va;
	ARRAY_TYPE(const_string) keywords;

	t_array_init(&keywords, 8);
	array_append(&keywords, &kw, 1);
	va_start(va, kw);
	while ((kw = va_arg(va, const char *)) != NULL)
		array_append(&keywords, &kw, 1);
	va_end(va);
	(void)array_append_space(&keywords);

	box->box.box.highest_modseq++;
	if (type != ADD_DEST) {
		box->box.src->highest_modseq = box->box.box.highest_modseq;
		msgs = array_get_modifiable(&box->src_msgs, &count);
		for (i = 0; i < count; i++) {
			if (msgs[i].uid == uid) {
				msgs[i].keywords = array_idx(&keywords, 0);
				msgs[i].modseq = box->box.src->highest_modseq;
				break;
			}
		}
		i_assert(i < count);
	}
	if (type != ADD_SRC) {
		box->box.dest->highest_modseq = box->box.box.highest_modseq;
		msgs = array_get_modifiable(&box->dest_msgs, &count);
		for (i = 0; i < count; i++) {
			if (msgs[i].uid == uid) {
				msgs[i].keywords = array_idx(&keywords, 0);
				msgs[i].modseq = box->box.src->highest_modseq;
				break;
			}
		}
		i_assert(i < count);
	}
}

static void
test_dsync_sync_msgs(struct test_dsync_worker *worker, bool dest)
{
	const struct test_dsync_mailbox *boxes;
	const struct dsync_message *msgs;
	struct test_dsync_worker_msg test_msg;
	unsigned int i, j, box_count, msg_count;

	boxes = array_get(&mailboxes, &box_count);
	for (i = 0; i < box_count; i++) {
		msgs = dest ? array_get(&boxes[i].dest_msgs, &msg_count) :
			array_get(&boxes[i].src_msgs, &msg_count);
		for (j = 0; j < msg_count; j++) {
			test_msg.msg = msgs[j];
			test_msg.mailbox_idx = i;
			array_append(&worker->msg_iter.msgs, &test_msg, 1);
			worker->worker.input_callback(worker->worker.input_context);
		}
	}

	worker->msg_iter.last = TRUE;
	worker->worker.input_callback(worker->worker.input_context);
}

static struct dsync_brain *test_dsync_brain_init(void)
{
	struct dsync_brain *brain;

	brain = i_new(struct dsync_brain, 1);
	brain->src_worker = dsync_worker_init_test();
	brain->dest_worker = dsync_worker_init_test();

	test_src_worker = (struct test_dsync_worker *)brain->src_worker;
	test_dest_worker = (struct test_dsync_worker *)brain->dest_worker;
	return brain;
}

static struct dsync_brain_mailbox_sync *
test_dsync_brain_sync_init(void)
{
	ARRAY_TYPE(dsync_brain_mailbox) brain_boxes;
	struct dsync_brain_mailbox_sync *sync;
	const struct test_dsync_mailbox *tboxes;
	unsigned int i, count;

	tboxes = array_get(&mailboxes, &count);
	t_array_init(&brain_boxes, count);
	for (i = 0; i < count; i++)
		array_append(&brain_boxes, &tboxes[i].box, 1);

	sync = dsync_brain_msg_sync_init(test_dsync_brain_init(), &brain_boxes);
	dsync_brain_msg_sync_more(sync);
	test_dsync_sync_msgs(test_dest_worker, TRUE);
	test_dsync_sync_msgs(test_src_worker, FALSE);
	return sync;
}

static void test_dsync_brain_msg_sync_box_multi(void)
{
	struct test_dsync_mailbox *box;
	struct dsync_brain_mailbox_sync *sync;
	struct test_dsync_msg_event msg_event;
	const struct dsync_brain_new_msg *new_msgs;
	unsigned int count;

	/* test that msg syncing finds and syncs all mailboxes */
	test_begin("dsync brain msg sync box multi");

	i_array_init(&mailboxes, 32);
	box = test_box_add(ADD_BOTH, "both");
	test_msg_add(box, ADD_BOTH, "guid1", 1);
	test_msg_set_flags(box, ADD_SRC, 1, MAIL_SEEN);
	test_msg_set_flags(box, ADD_DEST, 1, MAIL_DRAFT);
	test_msg_set_flags(box, ADD_SRC, 1, MAIL_ANSWERED);
	box = test_box_add(ADD_SRC, "src");
	test_msg_add(box, ADD_SRC, "guid2", 5);
	box = test_box_add(ADD_DEST, "dest");
	test_msg_add(box, ADD_DEST, "guid3", 3);

	sync = test_dsync_brain_sync_init();

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(test_box_has_guid("both", &msg_event.mailbox));
	test_assert(msg_event.msg.uid == 1);
	test_assert(msg_event.msg.flags == MAIL_ANSWERED);
	test_assert(!test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));

	new_msgs = array_get(&sync->dest_msg_iter->new_msgs, &count);
	test_assert(count == 1);
	test_assert(new_msgs[0].mailbox_idx == 1);
	test_assert(new_msgs[0].msg->uid == 5);
	test_assert(strcmp(new_msgs[0].msg->guid, "guid2") == 0);

	new_msgs = array_get(&sync->src_msg_iter->new_msgs, &count);
	test_assert(count == 1);
	test_assert(new_msgs[0].mailbox_idx == 2);
	test_assert(new_msgs[0].msg->uid == 3);
	test_assert(strcmp(new_msgs[0].msg->guid, "guid3") == 0);

	test_end();
}

static void test_dsync_brain_msg_sync_box(enum test_box_add_type type)
{
	struct test_dsync_mailbox *box;
	struct dsync_brain_mailbox_sync *sync;
	struct test_dsync_msg_event msg_event;
	const struct dsync_brain_new_msg *new_msgs;
	unsigned int count;

	i_array_init(&mailboxes, 32);
	box = test_box_add(type, "box1");
	test_msg_add(box, type, "guid1", 1);
	box = test_box_add(type, "box2");
	test_msg_add(box, type, "guid2", 2);

	sync = test_dsync_brain_sync_init();

	test_assert(!test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));

	new_msgs = array_get(type == ADD_DEST ? &sync->src_msg_iter->new_msgs :
			     &sync->dest_msg_iter->new_msgs, &count);
	test_assert(count == 2);
	test_assert(new_msgs[0].mailbox_idx == 0);
	test_assert(new_msgs[0].msg->uid == 1);
	test_assert(strcmp(new_msgs[0].msg->guid, "guid1") == 0);
	test_assert(new_msgs[1].mailbox_idx == 1);
	test_assert(new_msgs[1].msg->uid == 2);
	test_assert(strcmp(new_msgs[1].msg->guid, "guid2") == 0);
}

static void test_dsync_brain_msg_sync_box_single(void)
{
	test_begin("dsync brain msg sync box src");
	test_dsync_brain_msg_sync_box(ADD_SRC);
	test_end();

	test_begin("dsync brain msg sync box dest");
	test_dsync_brain_msg_sync_box(ADD_DEST);
	test_end();
}

static void test_dsync_brain_msg_sync_existing(void)
{
	struct test_dsync_mailbox *box;
	struct dsync_brain_mailbox_sync *sync;
	struct test_dsync_msg_event msg_event;

	test_begin("dsync brain msg sync existing");

	i_array_init(&mailboxes, 1);
	box = test_box_add(ADD_BOTH, "box");
	test_msg_add(box, ADD_BOTH, "guid1", 1);
	test_msg_add(box, ADD_BOTH, "guid2", 2);
	test_msg_add(box, ADD_BOTH, "guid3", 3);
	test_msg_add(box, ADD_BOTH, "guid5", 5);
	test_msg_add(box, ADD_BOTH, "guid6", 6);
	test_msg_add(box, ADD_BOTH, "guid9", 9);
	test_msg_add(box, ADD_BOTH, "guid10", 10);
	test_msg_add(box, ADD_BOTH, "guid11", 11);
	test_msg_add(box, ADD_BOTH, "guid12", 12);

	/* unchanged */
	test_msg_set_flags(box, ADD_BOTH, 1, MAIL_SEEN);

	/* changed, same modseq - dest has more flags so it will be used */
	test_msg_set_flags(box, ADD_SRC, 2, MAIL_ANSWERED);
	test_msg_set_flags(box, ADD_DEST, 2, MAIL_ANSWERED | MAIL_SEEN);
	test_msg_set_modseq(box, ADD_BOTH, 2, 2);

	/* changed, same modseq - src has more flags so it will be used */
	test_msg_set_flags(box, ADD_SRC, 3, MAIL_ANSWERED | MAIL_SEEN);
	test_msg_set_flags(box, ADD_DEST, 3, MAIL_ANSWERED);
	test_msg_set_modseq(box, ADD_BOTH, 3, 3);

	/* changed, dest has higher modseq */
	test_msg_set_flags(box, ADD_BOTH, 5, MAIL_DRAFT);
	test_msg_set_flags(box, ADD_DEST, 5, MAIL_FLAGGED);

	/* changed, src has higher modseq */
	test_msg_set_flags(box, ADD_DEST, 6, MAIL_FLAGGED);
	test_msg_set_flags(box, ADD_SRC, 6, 0);

	/* keywords changed, src has higher modseq */
	test_msg_set_keywords(box, ADD_SRC, 9, "hello", "world", NULL);

	/* flag/keyword conflict, same modseq - src has more so it
	   will be used */
	test_msg_set_keywords(box, ADD_SRC, 10, "foo", NULL);
	test_msg_set_flags(box, ADD_SRC, 10, MAIL_SEEN);
	test_msg_set_flags(box, ADD_DEST, 10, MAIL_DRAFT);
	test_msg_set_modseq(box, ADD_BOTH, 10, 5);

	/* flag/keyword conflict, same modseq - dest has more so it
	   will be used */
	test_msg_set_keywords(box, ADD_DEST, 11, "foo", NULL);
	test_msg_set_flags(box, ADD_SRC, 11, MAIL_SEEN);
	test_msg_set_flags(box, ADD_DEST, 11, MAIL_DRAFT);
	test_msg_set_modseq(box, ADD_BOTH, 11, 5);

	/* flag/keyword conflict, same modseq - both have same number of
	   flags so src will be used */
	test_msg_set_keywords(box, ADD_SRC, 12, "bar", NULL);
	test_msg_set_keywords(box, ADD_DEST, 12, "foo", NULL);
	test_msg_set_flags(box, ADD_SRC, 12, MAIL_SEEN);
	test_msg_set_flags(box, ADD_DEST, 12, MAIL_DRAFT);
	test_msg_set_modseq(box, ADD_BOTH, 12, 5);

	sync = test_dsync_brain_sync_init();
	test_assert(array_count(&sync->src_msg_iter->new_msgs) == 0);
	test_assert(array_count(&sync->dest_msg_iter->new_msgs) == 0);

	test_assert(test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 2);
	test_assert(msg_event.msg.flags == (MAIL_ANSWERED | MAIL_SEEN));

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 3);
	test_assert(msg_event.msg.flags == (MAIL_ANSWERED | MAIL_SEEN));

	test_assert(test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 5);
	test_assert(msg_event.msg.flags == MAIL_FLAGGED);

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 6);
	test_assert(msg_event.msg.flags == 0);

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 9);
	test_assert(msg_event.msg.flags == 0);
	test_assert(strcmp(msg_event.msg.keywords[0], "hello") == 0);
	test_assert(strcmp(msg_event.msg.keywords[1], "world") == 0);
	test_assert(msg_event.msg.keywords[2] == NULL);

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 10);
	test_assert(msg_event.msg.flags == MAIL_SEEN);
	test_assert(strcmp(msg_event.msg.keywords[0], "foo") == 0);
	test_assert(msg_event.msg.keywords[1] == NULL);

	test_assert(test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 11);
	test_assert(msg_event.msg.flags == MAIL_DRAFT);
	test_assert(strcmp(msg_event.msg.keywords[0], "foo") == 0);
	test_assert(msg_event.msg.keywords[1] == NULL);

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_UPDATE);
	test_assert(msg_event.msg.uid == 12);
	test_assert(msg_event.msg.flags == MAIL_SEEN);
	test_assert(strcmp(msg_event.msg.keywords[0], "bar") == 0);
	test_assert(msg_event.msg.keywords[1] == NULL);

	test_assert(!test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(!test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_end();
}

static void test_dsync_brain_msg_sync_expunges(void)
{
	struct test_dsync_mailbox *box;
	struct dsync_brain_mailbox_sync *sync;
	struct test_dsync_msg_event msg_event;

	test_begin("dsync brain msg sync expunges");

	i_array_init(&mailboxes, 1);
	box = test_box_add(ADD_BOTH, "box");

	/* expunged from dest */
	test_msg_add(box, ADD_SRC, "guid1", 1);
	/* expunged from src */
	test_msg_add(box, ADD_DEST, "guid2", 2);
	/* expunged from dest with expunge record */
	test_msg_add(box, ADD_BOTH, "guid3", 3);
	test_msg_set_flags(box, ADD_DEST, 3, DSYNC_MAIL_FLAG_EXPUNGED);
	/* expunged from src with expunge record */
	test_msg_add(box, ADD_BOTH, "guid4", 4);
	test_msg_set_flags(box, ADD_SRC, 4, DSYNC_MAIL_FLAG_EXPUNGED);
	/* expunged from both, with expunge record in src */
	test_msg_add(box, ADD_SRC, "guid5", 5);
	test_msg_set_flags(box, ADD_SRC, 5, DSYNC_MAIL_FLAG_EXPUNGED);
	/* expunged from both, with expunge record in dest */
	test_msg_add(box, ADD_DEST, "guid6", 6);
	test_msg_set_flags(box, ADD_DEST, 6, DSYNC_MAIL_FLAG_EXPUNGED);
	/* expunged from both, with expunge record in both */
	test_msg_add(box, ADD_BOTH, "guid7", 7);
	test_msg_set_flags(box, ADD_BOTH, 7, DSYNC_MAIL_FLAG_EXPUNGED);

	sync = test_dsync_brain_sync_init();
	test_assert(array_count(&sync->src_msg_iter->new_msgs) == 0);
	test_assert(array_count(&sync->dest_msg_iter->new_msgs) == 0);

	test_assert(test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(msg_event.msg.uid == 1);

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(msg_event.msg.uid == 2);

	test_assert(test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(msg_event.msg.uid == 3);

	test_assert(test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_assert(msg_event.type == LAST_MSG_TYPE_EXPUNGE);
	test_assert(msg_event.msg.uid == 4);

	test_assert(!test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(!test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));
	test_end();
}

static void test_dsync_brain_msg_sync_uid_conflicts(void)
{
	struct test_dsync_mailbox *box;
	struct dsync_brain_mailbox_sync *sync;
	struct test_dsync_msg_event msg_event;
	const struct dsync_brain_uid_conflict *conflicts;
	const struct dsync_brain_new_msg *src_msgs, *dest_msgs;
	unsigned int src_count, dest_count;

	test_begin("dsync brain msg sync uid conflicts");

	i_array_init(&mailboxes, 16);

	/* existing guid mismatch */
	box = test_box_add(ADD_BOTH, "box1");
	test_msg_add(box, ADD_SRC, "guid1", 1);
	test_msg_add(box, ADD_DEST, "guid2", 1);

	/* preserve uid */
	test_msg_add(box, ADD_BOTH, "guid3", 3);
	/* extra message in src */
	test_msg_add(box, ADD_SRC, "guid4", 4);
	/* extra message in dest */
	test_msg_add(box, ADD_DEST, "guid5", 5);

	/* conflict in expunged message expunged in dest */
	test_msg_add(box, ADD_SRC, "guid6", 6);
	test_msg_add(box, ADD_DEST, "guid7", 6);
	test_msg_set_flags(box, ADD_DEST, 6, DSYNC_MAIL_FLAG_EXPUNGED);

	/* conflict in expunged message expunged in src */
	test_msg_add(box, ADD_SRC, "guid8", 8);
	test_msg_set_flags(box, ADD_SRC, 8, DSYNC_MAIL_FLAG_EXPUNGED);
	test_msg_add(box, ADD_DEST, "guid9", 8);

	/* conflict in expunged message expunged in both */
	test_msg_add(box, ADD_SRC, "guid10", 10);
	test_msg_set_flags(box, ADD_SRC, 10, DSYNC_MAIL_FLAG_EXPUNGED);
	test_msg_add(box, ADD_DEST, "guid11", 10);
	test_msg_set_flags(box, ADD_DEST, 10, DSYNC_MAIL_FLAG_EXPUNGED);

	sync = test_dsync_brain_sync_init();

	conflicts = array_get(&sync->src_msg_iter->uid_conflicts, &src_count);
	test_assert(src_count == 3);
	test_assert(conflicts[0].old_uid == 1);
	test_assert(conflicts[0].new_uid == 12);
	test_assert(conflicts[1].old_uid == 4);
	test_assert(conflicts[1].new_uid == 13);
	test_assert(conflicts[2].old_uid == 6);
	test_assert(conflicts[2].new_uid == 15);

	conflicts = array_get(&sync->dest_msg_iter->uid_conflicts, &dest_count);
	test_assert(dest_count == 3);
	test_assert(conflicts[0].old_uid == 1);
	test_assert(conflicts[0].new_uid == 11);
	test_assert(conflicts[1].old_uid == 5);
	test_assert(conflicts[1].new_uid == 14);
	test_assert(conflicts[2].old_uid == 8);
	test_assert(conflicts[2].new_uid == 16);

	test_assert(!test_dsync_worker_next_msg_event(test_src_worker, &msg_event));
	test_assert(!test_dsync_worker_next_msg_event(test_dest_worker, &msg_event));

	src_msgs = array_get(&sync->src_msg_iter->new_msgs, &src_count);
	dest_msgs = array_get(&sync->dest_msg_iter->new_msgs, &dest_count);
	test_assert(src_count == 3);
	test_assert(dest_count == 3);

	test_assert(dest_msgs[0].msg->uid == 12);
	test_assert(strcmp(dest_msgs[0].msg->guid, "guid1") == 0);
	test_assert(src_msgs[0].msg->uid == 11);
	test_assert(strcmp(src_msgs[0].msg->guid, "guid2") == 0);
	test_assert(dest_msgs[1].msg->uid == 13);
	test_assert(strcmp(dest_msgs[1].msg->guid, "guid4") == 0);
	test_assert(src_msgs[1].msg->uid == 14);
	test_assert(strcmp(src_msgs[1].msg->guid, "guid5") == 0);
	test_assert(dest_msgs[2].msg->uid == 15);
	test_assert(strcmp(dest_msgs[2].msg->guid, "guid6") == 0);
	test_assert(src_msgs[2].msg->uid == 16);
	test_assert(strcmp(src_msgs[2].msg->guid, "guid9") == 0);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_dsync_brain_msg_sync_box_multi,
		test_dsync_brain_msg_sync_box_single,
		test_dsync_brain_msg_sync_existing,
		test_dsync_brain_msg_sync_expunges,
		test_dsync_brain_msg_sync_uid_conflicts,
		NULL
	};

	return test_run(test_functions);
}
