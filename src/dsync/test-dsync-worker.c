/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "test-dsync-worker.h"

extern struct dsync_worker_vfuncs test_dsync_worker;

struct dsync_worker *dsync_worker_init_test(void)
{
	struct test_dsync_worker *worker;

	worker = i_new(struct test_dsync_worker, 1);
	worker->worker.v = test_dsync_worker;
	worker->tmp_pool = pool_alloconly_create("test worker", 256);
	i_array_init(&worker->box_events, 64);
	i_array_init(&worker->msg_events, 64);
	i_array_init(&worker->results, 64);
	worker->body_stream = i_stream_create_from_data("hdr\n\nbody", 9);
	return &worker->worker;
}

static void test_worker_deinit(struct dsync_worker *_worker)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	pool_unref(&worker->tmp_pool);
	array_free(&worker->box_events);
	array_free(&worker->msg_events);
	array_free(&worker->results);
	i_stream_unref(&worker->body_stream);
	i_free(worker);
}

static void
test_worker_set_result(struct test_dsync_worker *worker, int result)
{
	struct test_dsync_worker_result r;

	if (worker->worker.next_tag == 0)
		return;

	memset(&r, 0, sizeof(r));
	r.tag = worker->worker.next_tag;
	r.result = result;
	array_append(&worker->results, &r, 1);

	worker->worker.next_tag = 0;
}

static bool
test_worker_get_next_result(struct dsync_worker *_worker,
			    uint32_t *tag_r, int *result_r)
{
	struct test_dsync_worker *worker =
		(struct test_dsync_worker *)_worker;
	const struct test_dsync_worker_result *result;

	if (array_count(&worker->results) == 0)
		return FALSE;

	result = array_idx(&worker->results, 0);
	*tag_r = result->tag;
	*result_r = result->result;
	array_delete(&worker->results, 0, 1);
	return TRUE;
}

static bool test_worker_is_output_full(struct dsync_worker *worker ATTR_UNUSED)
{
	return FALSE;
}

static int test_worker_output_flush(struct dsync_worker *worker ATTR_UNUSED)
{
	return 1;
}

static struct dsync_worker_mailbox_iter *
test_worker_mailbox_iter_init(struct dsync_worker *_worker)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	i_assert(worker->box_iter.iter.worker == NULL);

	worker->box_iter.iter.worker = _worker;
	return &worker->box_iter.iter;
}

static int
test_worker_mailbox_iter_next(struct dsync_worker_mailbox_iter *_iter,
			      struct dsync_mailbox *dsync_box_r)
{
	struct test_dsync_worker_mailbox_iter *iter =
		(struct test_dsync_worker_mailbox_iter *)_iter;

	if (iter->next_box == NULL)
		return iter->last ? -1 : 0;

	*dsync_box_r = *iter->next_box;
	iter->next_box = NULL;
	return 1;
}

static int
test_worker_mailbox_iter_deinit(struct dsync_worker_mailbox_iter *iter)
{
	struct test_dsync_worker *worker =
		(struct test_dsync_worker *)iter->worker;

	memset(&worker->box_iter, 0, sizeof(worker->box_iter));
	return 0;
}

static struct dsync_worker_msg_iter *
test_worker_msg_iter_init(struct dsync_worker *_worker,
			  const mailbox_guid_t mailboxes[],
			  unsigned int mailbox_count)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	i_assert(worker->msg_iter.iter.worker == NULL);

	worker->msg_iter_mailboxes =
		p_new(worker->tmp_pool, mailbox_guid_t, mailbox_count);
	memcpy(worker->msg_iter_mailboxes, mailboxes,
	       sizeof(mailboxes[0]) * mailbox_count);
	worker->msg_iter_mailbox_count = mailbox_count;
	i_array_init(&worker->msg_iter.msgs, 64);

	worker->msg_iter.iter.worker = _worker;
	return &worker->msg_iter.iter;
}

static int
test_worker_msg_iter_next(struct dsync_worker_msg_iter *_iter,
			  unsigned int *mailbox_idx_r,
			  struct dsync_message *msg_r)
{
	struct test_dsync_worker_msg_iter *iter =
		(struct test_dsync_worker_msg_iter *)_iter;
	const struct test_dsync_worker_msg *msg;

	if (iter->idx == array_count(&iter->msgs))
		return iter->last ? -1 : 0;

	msg = array_idx(&iter->msgs, iter->idx++);
	*msg_r = msg->msg;
	*mailbox_idx_r = msg->mailbox_idx;
	return 1;
}

static int
test_worker_msg_iter_deinit(struct dsync_worker_msg_iter *iter)
{
	struct test_dsync_worker *worker =
		(struct test_dsync_worker *)iter->worker;

	array_free(&worker->msg_iter.msgs);
	memset(&worker->msg_iter, 0, sizeof(worker->msg_iter));
	return 0;
}

static void
test_worker_set_last_box(struct dsync_worker *_worker,
			 const struct dsync_mailbox *dsync_box,
			 enum test_dsync_last_box_type type)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;
	struct test_dsync_box_event event;

	event.type = type;

	event.box = *dsync_box;
	event.box.name = p_strdup(worker->tmp_pool, dsync_box->name);
	array_append(&worker->box_events, &event, 1);
}

bool test_dsync_worker_next_box_event(struct test_dsync_worker *worker,
				      struct test_dsync_box_event *event_r)
{
	const struct test_dsync_box_event *events;
	unsigned int count;

	events = array_get(&worker->box_events, &count);
	if (count == 0)
		return FALSE;

	*event_r = events[0];
	array_delete(&worker->box_events, 0, 1);
	return TRUE;
}

static void
test_worker_create_mailbox(struct dsync_worker *_worker,
			   const struct dsync_mailbox *dsync_box)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	test_worker_set_last_box(_worker, dsync_box, LAST_BOX_TYPE_CREATE);
	test_worker_set_result(worker, 0);
}

static void
test_worker_update_mailbox(struct dsync_worker *_worker,
			   const struct dsync_mailbox *dsync_box)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	test_worker_set_last_box(_worker, dsync_box, LAST_BOX_TYPE_UPDATE);
	test_worker_set_result(worker, 0);
}

static void
test_worker_select_mailbox(struct dsync_worker *_worker,
			   const mailbox_guid_t *mailbox)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;
	struct dsync_mailbox box;

	worker->selected_mailbox = *mailbox;

	memset(&box, 0, sizeof(box));
	memcpy(box.guid.guid, mailbox, sizeof(box.guid.guid));
	test_worker_set_last_box(_worker, &box, LAST_BOX_TYPE_SELECT);
	test_worker_set_result(worker, 0);
}

static struct test_dsync_msg_event *
test_worker_set_last_msg(struct test_dsync_worker *worker,
			 const struct dsync_message *msg,
			 enum test_dsync_last_msg_type type)
{
	struct test_dsync_msg_event *event;
	const char **keywords;
	unsigned int i, count;

	event = array_append_space(&worker->msg_events);
	event->type = type;
	event->msg = *msg;
	event->mailbox = worker->selected_mailbox;
	event->msg.guid = p_strdup(worker->tmp_pool, msg->guid);
	if (msg->keywords != NULL) {
		count = str_array_length(msg->keywords);
		keywords = p_new(worker->tmp_pool, const char *, count+1);
		for (i = 0; i < count; i++) {
			keywords[i] = p_strdup(worker->tmp_pool,
					       msg->keywords[i]);
		}
		event->msg.keywords = keywords;
	}
	return event;
}

bool test_dsync_worker_next_msg_event(struct test_dsync_worker *worker,
				      struct test_dsync_msg_event *event_r)
{
	const struct test_dsync_msg_event *events;
	unsigned int count;

	events = array_get(&worker->msg_events, &count);
	if (count == 0)
		return FALSE;

	*event_r = events[0];
	array_delete(&worker->msg_events, 0, 1);
	return TRUE;
}

static void
test_worker_msg_update_metadata(struct dsync_worker *_worker,
				const struct dsync_message *msg)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	test_worker_set_last_msg(worker, msg, LAST_MSG_TYPE_UPDATE);
	test_worker_set_result(worker, 0);
}

static void
test_worker_msg_update_uid(struct dsync_worker *_worker, uint32_t uid)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;
	struct dsync_message msg;

	memset(&msg, 0, sizeof(msg));
	msg.uid = uid;
	test_worker_set_last_msg(worker, &msg, LAST_MSG_TYPE_UPDATE_UID);
	test_worker_set_result(worker, 0);
}

static void test_worker_msg_expunge(struct dsync_worker *_worker, uint32_t uid)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;
	struct dsync_message msg;

	memset(&msg, 0, sizeof(msg));
	msg.uid = uid;
	test_worker_set_last_msg(worker, &msg, LAST_MSG_TYPE_EXPUNGE);
	test_worker_set_result(worker, 0);
}

static void
test_worker_msg_copy(struct dsync_worker *_worker,
		     const mailbox_guid_t *src_mailbox,
		     uint32_t src_uid, const struct dsync_message *dest_msg)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;
	struct test_dsync_msg_event *event;

	event = test_worker_set_last_msg(worker, dest_msg, LAST_MSG_TYPE_COPY);
	event->copy_src_mailbox = *src_mailbox;
	event->copy_src_uid = src_uid;
	test_worker_set_result(worker, 0);
}

static void
test_worker_msg_save(struct dsync_worker *_worker,
		     const struct dsync_message *msg,
		     struct dsync_msg_static_data *data)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;
	struct test_dsync_msg_event *event;
	const unsigned char *d;
	size_t size;
	ssize_t ret;
	string_t *body;

	event = test_worker_set_last_msg(worker, msg, LAST_MSG_TYPE_SAVE);
	event->save_data.pop3_uidl = p_strdup(worker->tmp_pool, data->pop3_uidl);
	event->save_data.received_date = data->received_date;

	body = t_str_new(256);
	while ((ret = i_stream_read_data(data->input, &d, &size, 0)) > 0) {
		str_append_n(body, d, size);
		i_stream_skip(data->input, size);
	}
	i_assert(ret == -1);
	event->save_body = p_strdup(worker->tmp_pool, str_c(body));

	test_worker_set_result(worker, 0);
}

static int
test_worker_msg_get(struct dsync_worker *_worker,
		    uint32_t uid ATTR_UNUSED,
		    struct dsync_msg_static_data *data_r)
{
	struct test_dsync_worker *worker = (struct test_dsync_worker *)_worker;

	data_r->pop3_uidl = "uidl";
	data_r->received_date = 123456;
	data_r->input = worker->body_stream;
	i_stream_seek(data_r->input, 0);
	return 1;
}

struct dsync_worker_vfuncs test_dsync_worker = {
	test_worker_deinit,

	test_worker_get_next_result,
	test_worker_is_output_full,
	test_worker_output_flush,

	test_worker_mailbox_iter_init,
	test_worker_mailbox_iter_next,
	test_worker_mailbox_iter_deinit,

	test_worker_msg_iter_init,
	test_worker_msg_iter_next,
	test_worker_msg_iter_deinit,

	test_worker_create_mailbox,
	test_worker_update_mailbox,

	test_worker_select_mailbox,
	test_worker_msg_update_metadata,
	test_worker_msg_update_uid,
	test_worker_msg_expunge,
	test_worker_msg_copy,
	test_worker_msg_save,
	test_worker_msg_get
};
