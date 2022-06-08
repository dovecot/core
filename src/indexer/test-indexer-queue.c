/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "indexer-queue.h"

void indexer_refresh_proctitle(void) { }

static void
indexer_queue_status_callback(int status ATTR_UNUSED, void *context ATTR_UNUSED)
{
}

static void test_indexer_queue(void)
{
	struct indexer_queue *queue;
	struct indexer_request *request;

	test_begin("indexer queue");
	queue = indexer_queue_init(indexer_queue_status_callback);

	indexer_queue_append(queue, TRUE, "user2", "mailbox3", "session3", 50, NULL);
	indexer_queue_append(queue, TRUE, "user1", "mailbox4", "session4", 0, NULL);
	indexer_queue_append(queue, FALSE, "user2", "mailbox2", "session2", 0, NULL);
	indexer_queue_append(queue, FALSE, "user1", "mailbox1", "session1", 0, NULL);

	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->username, "user1");
	test_assert_strcmp(request->mailbox, "mailbox1");

	indexer_queue_move_head_to_tail(queue);

	struct {
		const char *username;
		const char *mailbox;
	} expected[] = {
		{ "user2", "mailbox2" },
		{ "user2", "mailbox3" },
		{ "user1", "mailbox4" },
		{ "user1", "mailbox1" },
	};
	for (unsigned int i = 0; i < N_ELEMENTS(expected); i++) {
		request = indexer_queue_request_peek(queue);
		test_assert_strcmp_idx(request->username, expected[i].username, i);
		test_assert_strcmp_idx(request->mailbox, expected[i].mailbox, i);

		indexer_queue_request_remove(queue);
		indexer_queue_request_finish(queue, &request, TRUE);
	}
	test_assert(indexer_queue_request_peek(queue) == NULL);

	indexer_queue_deinit(&queue);
	test_end();
}

static void test_indexer_queue_repeated_prepend(void)
{
	struct indexer_queue *queue;
	struct indexer_request *request;

	test_begin("indexer queue");
	queue = indexer_queue_init(indexer_queue_status_callback);

	indexer_queue_append(queue, FALSE, "user1", "mailbox1", "session1", 0, NULL);
	indexer_queue_append(queue, FALSE, "user1", "mailbox1", "session1", 0, NULL);

	test_assert_cmp(indexer_queue_count(queue), ==, 1);

	request = indexer_queue_request_peek(queue);
	indexer_queue_request_remove(queue);
	indexer_queue_request_finish(queue, &request, TRUE);

	test_assert(indexer_queue_request_peek(queue) == NULL);

	/* this used to assert crash before the fix */
	indexer_queue_deinit(&queue);
	test_end();
}

static void test_indexer_queue_reindex(void)
{
	struct indexer_queue *queue;
	struct indexer_request *request;

	test_begin("indexer queue reindex");
	queue = indexer_queue_init(indexer_queue_status_callback);

	indexer_queue_append(queue, TRUE, "user1", "mailbox1", "session1", 0, NULL);
	indexer_queue_append(queue, TRUE, "user1", "mailbox2", "session2", 0, NULL);

	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox1");

	/* start working on the request */
	indexer_queue_request_remove(queue);
	indexer_queue_request_work(request);
	test_assert(request->working);

	/* prepend another request to the same mailbox */
	indexer_queue_append(queue, FALSE, "user1", "mailbox1", "session1", 0, NULL);
	test_assert(request->reindex_head);

	/* finish the request, and it should now be at the head again */
	indexer_queue_request_finish(queue, &request, TRUE);
	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox1");
	test_assert(!request->working);

	/* start working on the request again */
	indexer_queue_request_remove(queue);
	indexer_queue_request_work(request);
	/* append another request to the same mailbox */
	indexer_queue_append(queue, TRUE, "user1", "mailbox1", "session1", 0, NULL);
	test_assert(request->reindex_tail);

	/* finish the request, and it should now be at the tail again */
	indexer_queue_request_finish(queue, &request, TRUE);

	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox2");
	indexer_queue_request_remove(queue);
	indexer_queue_request_finish(queue, &request, TRUE);

	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox1");
	indexer_queue_request_remove(queue);
	indexer_queue_request_finish(queue, &request, TRUE);

	test_assert(indexer_queue_request_peek(queue) == NULL);

	indexer_queue_deinit(&queue);
	test_end();
}

static void test_indexer_queue_cancel(void)
{
	struct indexer_queue *queue;
	struct indexer_request *request;

	test_begin("indexer queue cancel");
	queue = indexer_queue_init(indexer_queue_status_callback);

	indexer_queue_append(queue, TRUE, "user2", "mailbox3", "session3", 50, NULL);
	indexer_queue_append(queue, TRUE, "user1", "mailbox4", "session4", 0, NULL);
	indexer_queue_append(queue, FALSE, "user2", "mailbox2", "session2", 0, NULL);
	indexer_queue_append(queue, FALSE, "user1", "mailbox1", "session1", 0, NULL);

	/* try to cancel nonexistent user */
	indexer_queue_cancel(queue, "user-none", "mailbox1");
	/* try to cancel nonexistent mailbox */
	indexer_queue_cancel(queue, "user1", "mailbox-none");

	test_assert(indexer_queue_count(queue) == 4);
	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox1");

	/* cancel user1's all requests */
	indexer_queue_cancel(queue, "user1", NULL);
	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox2");
	test_assert_strcmp(request->next->mailbox, "mailbox3");
	test_assert(request->next->next == NULL);

	/* cancel user2's requests one by one */
	indexer_queue_cancel(queue, "user2", "mailbox2");
	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "mailbox3");
	test_assert(request->next == NULL);

	indexer_queue_cancel(queue, "user2", "mailbox3");
	test_assert(indexer_queue_request_peek(queue) == NULL);

	/* cancelling a working request should just drop the reindex-flag */
	indexer_queue_append(queue, TRUE, "user1", "mailbox1", "session1", 0, NULL);
	request = indexer_queue_request_peek(queue);
	indexer_queue_request_remove(queue);
	indexer_queue_request_work(request);
	indexer_queue_append(queue, TRUE, "user1", "mailbox1", "session1", 0, NULL);
	test_assert(request->reindex_tail);
	indexer_queue_cancel(queue, "user1", NULL);
	test_assert(!request->reindex_tail);
	indexer_queue_request_finish(queue, &request, TRUE);
	test_assert(indexer_queue_request_peek(queue) == NULL);

	/* test cancelling mailbox wildcards */
	indexer_queue_append(queue, TRUE, "user1", "testbox1", "session1", 0, NULL);
	indexer_queue_append(queue, TRUE, "user1", "testbox2", "session1", 0, NULL);
	indexer_queue_append(queue, TRUE, "user1", "notbox", "session1", 0, NULL);
	indexer_queue_cancel(queue, "user1", "testbox*");
	request = indexer_queue_request_peek(queue);
	test_assert_strcmp(request->mailbox, "notbox");
	indexer_queue_cancel(queue, "user1", "*");
	test_assert(indexer_queue_request_peek(queue) == NULL);

	indexer_queue_deinit(&queue);
	test_end();
}

static void test_indexer_queue_iter(void)
{
	struct indexer_queue *queue;
	struct indexer_request *request, *request1, *request2;
	struct indexer_request *iter_request1, *iter_request2;

	test_begin("indexer queue iter");
	queue = indexer_queue_init(indexer_queue_status_callback);

	indexer_queue_append(queue, TRUE, "user2", "mailbox3", "session3", 50, NULL);
	indexer_queue_append(queue, TRUE, "user1", "mailbox4", "session4", 0, NULL);
	indexer_queue_append(queue, FALSE, "user2", "mailbox2", "session2", 0, NULL);
	indexer_queue_append(queue, FALSE, "user1", "mailbox1", "session1", 0, NULL);

	/* start working on the first two requests */
	request1 = indexer_queue_request_peek(queue);
	test_assert_strcmp(request1->username, "user1");
	test_assert_strcmp(request1->mailbox, "mailbox1");
	indexer_queue_request_remove(queue);
	indexer_queue_request_work(request1);

	request2 = indexer_queue_request_peek(queue);
	test_assert_strcmp(request2->username, "user2");
	test_assert_strcmp(request2->mailbox, "mailbox2");
	indexer_queue_request_remove(queue);
	indexer_queue_request_work(request2);

	/* Iteration shows the requests being worked on first. Their order
	   depends on hash table iteration, so any order is acceptable. */
	struct indexer_queue_iter *iter = indexer_queue_iter_init(queue, FALSE);
	iter_request1 = indexer_queue_iter_next(iter);
	iter_request2 = indexer_queue_iter_next(iter);
	test_assert((iter_request1 == request1 && iter_request2 == request2) ||
		    (iter_request1 == request2 && iter_request2 == request1));

	request = indexer_queue_request_peek(queue);
	test_assert(indexer_queue_iter_next(iter) == request);
	test_assert(indexer_queue_iter_next(iter) == request->next);
	test_assert(indexer_queue_iter_next(iter) == NULL);
	indexer_queue_iter_deinit(&iter);

	/* Iterate only worked-on requests. */
	iter = indexer_queue_iter_init(queue, TRUE);
	iter_request1 = indexer_queue_iter_next(iter);
	iter_request2 = indexer_queue_iter_next(iter);
	test_assert((iter_request1 == request1 && iter_request2 == request2) ||
		    (iter_request1 == request2 && iter_request2 == request1));
	test_assert(indexer_queue_iter_next(iter) == NULL);
	indexer_queue_iter_deinit(&iter);

	/* Finish cleanup */
	indexer_queue_request_finish(queue, &request1, FALSE);
	indexer_queue_request_finish(queue, &request2, FALSE);

	indexer_queue_cancel_all(queue);
	test_assert(indexer_queue_request_peek(queue) == NULL);

	indexer_queue_deinit(&queue);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_indexer_queue,
		test_indexer_queue_repeated_prepend,
		test_indexer_queue_reindex,
		test_indexer_queue_cancel,
		test_indexer_queue_iter,
		NULL
	};
	return test_run(test_functions);
}
