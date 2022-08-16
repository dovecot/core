/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "test-common.h"
#include "replicator-queue.h"

#define TEST_REPLICATION_FULL_SYNC_INTERVAL 60
#define TEST_REPLICATION_FAILURE_RESYNC_INTERVAL 10

static void test_replicator_queue(void)
{
	struct replicator_queue *queue;
	struct replicator_user *user1, *user2, *user3, *user4;
	unsigned int next_secs;

	test_begin("replicator queue");
	queue = replicator_queue_init(TEST_REPLICATION_FULL_SYNC_INTERVAL,
				      TEST_REPLICATION_FAILURE_RESYNC_INTERVAL);
	ioloop_time = time(NULL);

	/* 1) Add users */

	/* add the 1st user with priority=none */
	user1 = replicator_queue_get(queue, "user1");
	replicator_queue_update(queue, user1, REPLICATION_PRIORITY_NONE);
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_count(queue) == 1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* add the 2nd user with priority=none */
	user2 = replicator_queue_get(queue, "user2");
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_NONE);
	replicator_queue_add(queue, user2);
	test_assert(replicator_queue_count(queue) == 2);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* add the 3rd user with priority=none */
	user3 = replicator_queue_get(queue, "user3");
	replicator_queue_update(queue, user3, REPLICATION_PRIORITY_NONE);
	replicator_queue_add(queue, user3);
	test_assert(replicator_queue_count(queue) == 3);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* 2) User hasn't been synced yet, but priority is updated */

	/* update the 2nd user's priority to low */
	user2 = replicator_queue_get(queue, "user2");
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_LOW);
	replicator_queue_add(queue, user2);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* update the 1st user's priority to high */
	user1 = replicator_queue_get(queue, "user1");
	replicator_queue_update(queue, user1, REPLICATION_PRIORITY_HIGH);
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* update the 2nd user's priority to sync */
	user2 = replicator_queue_get(queue, "user2");
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_SYNC);
	replicator_queue_add(queue, user2);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* 3) User hasn't been synced, and priority is being updated.
	   user1 was synced 1 second before user2. */
	user1->last_fast_sync = ioloop_time;
	user1->last_full_sync = ioloop_time;
	user1->priority = REPLICATION_PRIORITY_NONE;
	replicator_queue_add(queue, user1);
	ioloop_time++;
	user2->last_fast_sync = ioloop_time;
	user2->last_full_sync = ioloop_time;
	user2->priority = REPLICATION_PRIORITY_NONE;
	replicator_queue_add(queue, user2);
	ioloop_time++;
	user3->last_fast_sync = ioloop_time;
	user3->last_full_sync = ioloop_time;
	user3->priority = REPLICATION_PRIORITY_NONE;
	replicator_queue_add(queue, user3);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs > 0);

	/* update the 2nd user's priority to low */
	user2 = replicator_queue_get(queue, "user2");
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_LOW);
	replicator_queue_add(queue, user2);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* update the 1st user's priority to high */
	user1 = replicator_queue_get(queue, "user1");
	replicator_queue_update(queue, user1, REPLICATION_PRIORITY_HIGH);
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* update the 2nd user's priority to sync */
	user2 = replicator_queue_get(queue, "user2");
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_SYNC);
	replicator_queue_add(queue, user2);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* 4) Test failed sync with a new user */
	user1->priority = REPLICATION_PRIORITY_NONE;
	replicator_queue_add(queue, user1);
	user2->priority = REPLICATION_PRIORITY_NONE;
	replicator_queue_add(queue, user2);

	user4 = replicator_queue_get(queue, "user4");
	user4->last_fast_sync = ioloop_time - 5;
	user4->last_sync_failed = TRUE;
	replicator_queue_add(queue, user4);

	test_assert(replicator_queue_count(queue) == 4);
	test_assert(replicator_queue_peek(queue, &next_secs) == user4 &&
		    next_secs == TEST_REPLICATION_FAILURE_RESYNC_INTERVAL - 5);

	/* low priority sync is prioritized over failed sync */
	replicator_queue_update(queue, user1, REPLICATION_PRIORITY_LOW);
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* However, if the last failure was old enough it will be before
	   the low priority one. Test the edge case. */
	user4->last_fast_sync = ioloop_time -
		TEST_REPLICATION_FAILURE_RESYNC_INTERVAL -
		(60*15) - 1;
	replicator_queue_add(queue, user4);
	test_assert(replicator_queue_peek(queue, &next_secs) == user4 && next_secs == 0);
	user4->last_fast_sync++;
	replicator_queue_add(queue, user4);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);

	/* 5) Test priority starvation */

	/* high priority is normally prioritized over low priority */
	i_assert(user1->priority == REPLICATION_PRIORITY_LOW);
	user2 = replicator_queue_get(queue, "user2");
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_HIGH);
	replicator_queue_add(queue, user2);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* if low priority is old enough, it gets prioritized over high */
	user1->last_update = ioloop_time - (60*15) - 1;
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);
	user1->last_update++;
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* similarly low priority eventually gets prioritized over sync
	   priority */
	replicator_queue_update(queue, user2, REPLICATION_PRIORITY_SYNC);
	replicator_queue_add(queue, user2);
	user1->last_update = ioloop_time - (60*30) - 1;
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);
	user1->last_update++;
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	/* likewise for none priority also */
	user1->priority = REPLICATION_PRIORITY_NONE;
	user1->last_update = ioloop_time;
	user1->last_fast_sync = ioloop_time;
	user1->last_full_sync = ioloop_time - (60*45) -
		TEST_REPLICATION_FULL_SYNC_INTERVAL - 1;
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user1 && next_secs == 0);
	user1->last_full_sync++;
	replicator_queue_add(queue, user1);
	test_assert(replicator_queue_peek(queue, &next_secs) == user2 && next_secs == 0);

	replicator_queue_deinit(&queue);
	test_end();
}

static void test_replicator_queue_verify_drained(struct replicator_queue *queue)
{
	struct replicator_queue_iter *iter =
		replicator_queue_iter_init(queue);
	struct replicator_user *user;
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		i_assert(user->priority == REPLICATION_PRIORITY_NONE);
		i_assert(user->last_sync_failed ||
			 ioloop_time - user->last_full_sync < TEST_REPLICATION_FULL_SYNC_INTERVAL);
	}
	replicator_queue_iter_deinit(&iter);
}

static void test_replicator_queue_drain(struct replicator_queue *queue)
{
	struct replicator_user *user;
	unsigned int next_secs;
	enum replication_priority prev_priority = REPLICATION_PRIORITY_SYNC;
	time_t prev_sync = INT_MAX;

	while ((user = replicator_queue_pop(queue, &next_secs)) != NULL) {
		if (user->priority < prev_priority) {
			prev_sync = INT_MAX;
		} else {
			test_assert(user->priority == prev_priority);
			if (user->priority == REPLICATION_PRIORITY_NONE) {
				test_assert(user->last_full_sync <= prev_sync);
				prev_sync = user->last_full_sync;
			} else {
				test_assert(user->last_fast_sync <= prev_sync);
				prev_sync = user->last_fast_sync;
			}
		}
		user->priority = REPLICATION_PRIORITY_NONE;
		user->last_fast_sync = user->last_full_sync = ioloop_time-1;
		/* dsync runs here */
		if (i_rand_limit(5) == 0)
			user->last_sync_failed = TRUE;
		else {
			user->last_successful_sync = ioloop_time;
			user->last_sync_failed = FALSE;
		}
		replicator_queue_push(queue, user);
	}
	test_replicator_queue_verify_drained(queue);
}

static void test_replicator_queue_random(void)
{
	struct replicator_queue *queue;
	struct replicator_user *user;

	test_begin("replicator queue random");
	queue = replicator_queue_init(TEST_REPLICATION_FULL_SYNC_INTERVAL,
				      TEST_REPLICATION_FAILURE_RESYNC_INTERVAL);
	/* fill some users */
	ioloop_time = time(NULL);
	for (unsigned int i = 0; i < 1000; i++) T_BEGIN {
		enum replication_priority priority =
			i_rand_minmax(REPLICATION_PRIORITY_NONE,
				      REPLICATION_PRIORITY_SYNC);
		const char *username =
			t_strdup_printf("test%u", i_rand_minmax(1, 200));
		user = replicator_queue_get(queue, username);
		replicator_queue_update(queue, user, priority);
		replicator_queue_add(queue, user);
		ioloop_time++;
	} T_END;
	for (unsigned int i = 0; i < 1000; i++) {
		test_replicator_queue_drain(queue);
		ioloop_time++;
	}
	replicator_queue_deinit(&queue);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_replicator_queue,
		test_replicator_queue_random,
		NULL
	};
	return test_run(test_functions);
}
