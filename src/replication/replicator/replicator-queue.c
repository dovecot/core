/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "hash.h"
#include "replicator-queue-private.h"
#include "replicator-settings.h"

#include <unistd.h>
#include <fcntl.h>

struct replicator_sync_lookup {
	struct replicator_user *user;

	replicator_sync_callback_t *callback;
	void *context;

	bool wait_for_next_push;
};

struct replicator_queue_iter {
	struct replicator_queue *queue;
	struct hash_iterate_context *iter;
};

static unsigned int replicator_full_sync_interval = 0;
static unsigned int replicator_failure_resync_interval = 0;

static time_t replicator_user_next_sync_time(const struct replicator_user *user)
{
	/* The idea is that the higher the priority, the more likely it will
	   be prioritized over low priority syncs. However, to avoid permanent
	   starvation of lower priority users, the priority boost is only
	   temporary.

	   The REPLICATION_PRIORITY_*_SECS macros effectively specify how long
	   lower priority requests are allowed to be waiting. */
#define REPLICATION_PRIORITY_LOW_SECS (60*15)
#define REPLICATION_PRIORITY_HIGH_SECS (60*30)
#define REPLICATION_PRIORITY_SYNC_SECS (60*45)
	/* When priority != none, user needs to be replicated ASAP.
	   The question is just whether the queue is already busy and other
	   users need to be synced even more faster. */
	if (user->last_fast_sync == 0) {
		/* User has never been synced yet. These will be replicated
		   first. Still, try to replicate higher priority users faster
		   than lower priority users. */
		if (user->priority != REPLICATION_PRIORITY_NONE)
			return REPLICATION_PRIORITY_SYNC - user->priority;
	}
	switch (user->priority) {
	case REPLICATION_PRIORITY_NONE:
		break;
	case REPLICATION_PRIORITY_LOW:
		i_assert(user->last_update >= REPLICATION_PRIORITY_LOW_SECS);
		return user->last_update - REPLICATION_PRIORITY_LOW_SECS;
	case REPLICATION_PRIORITY_HIGH:
		i_assert(user->last_update >= REPLICATION_PRIORITY_HIGH_SECS);
		return user->last_update - REPLICATION_PRIORITY_HIGH_SECS;
	case REPLICATION_PRIORITY_SYNC:
		i_assert(user->last_update >= REPLICATION_PRIORITY_HIGH_SECS);
		return user->last_update - REPLICATION_PRIORITY_SYNC_SECS;
	}
	if (user->last_sync_failed) {
		/* failures need to be retried at specific intervals */
		return user->last_fast_sync +
			replicator_failure_resync_interval;
	}
	/* full resyncs should be done at configured intervals */
	return user->last_full_sync + replicator_full_sync_interval;
}

static int user_priority_cmp(const void *p1, const void *p2)
{
	const struct replicator_user *user1 = p1, *user2 = p2;
	time_t next_sync1 = replicator_user_next_sync_time(user1);
	time_t next_sync2 = replicator_user_next_sync_time(user2);
	if (next_sync1 < next_sync2)
		return -1;
	if (next_sync1 > next_sync2)
		return 1;
	return 0;
}

struct replicator_queue *
replicator_queue_init(unsigned int full_sync_interval,
		      unsigned int failure_resync_interval)
{
	struct replicator_queue *queue;

	/* priorityq callback needs to access these */
	i_assert(replicator_full_sync_interval == 0 ||
		 replicator_full_sync_interval == full_sync_interval);
	replicator_full_sync_interval = full_sync_interval;
	i_assert(replicator_failure_resync_interval == 0 ||
		 replicator_failure_resync_interval == failure_resync_interval);
	replicator_full_sync_interval = full_sync_interval;
	replicator_failure_resync_interval = failure_resync_interval;

	queue = i_new(struct replicator_queue, 1);
	queue->full_sync_interval = full_sync_interval;
	queue->failure_resync_interval = failure_resync_interval;
	queue->user_queue = priorityq_init(user_priority_cmp, 1024);
	hash_table_create(&queue->user_hash, default_pool, 1024,
			  str_hash, strcmp);
	i_array_init(&queue->sync_lookups, 32);
	queue->event = event_create(NULL);
	event_add_category(queue->event, &event_category_replication);
	return queue;
}

void replicator_queue_deinit(struct replicator_queue **_queue)
{
	struct replicator_queue *queue = *_queue;
	struct priorityq_item *item;

	*_queue = NULL;

	queue->change_callback = NULL;

	while ((item = priorityq_pop(queue->user_queue)) != NULL) {
		struct replicator_user *user = (struct replicator_user *)item;

		user->popped = TRUE;
		replicator_queue_remove(queue, &user);
	}

	priorityq_deinit(&queue->user_queue);
	hash_table_destroy(&queue->user_hash);
	i_assert(array_count(&queue->sync_lookups) == 0);
	array_free(&queue->sync_lookups);
	event_unref(&queue->event);
	i_free(queue);
}

void replicator_queue_set_change_callback(struct replicator_queue *queue,
					  void (*callback)(void *context),
					  void *context)
{
	queue->change_callback = callback;
	queue->change_context = context;
}

void replicator_user_ref(struct replicator_user *user)
{
	i_assert(user->refcount > 0);
	user->refcount++;
}

bool replicator_user_unref(struct replicator_user **_user)
{
	struct replicator_user *user = *_user;

	i_assert(user->refcount > 0);
	*_user = NULL;
	if (--user->refcount > 0)
		return TRUE;

	i_free(user->state);
	i_free(user->username);
	i_free(user);
	return FALSE;
}

struct replicator_user *
replicator_queue_lookup(struct replicator_queue *queue, const char *username)
{
	return hash_table_lookup(queue->user_hash, username);
}

struct replicator_user *
replicator_queue_get(struct replicator_queue *queue, const char *username)
{
	struct replicator_user *user;

	user = replicator_queue_lookup(queue, username);
	if (user == NULL) {
		e_debug(queue->event, "user %s: User not found from queue - adding", username);
		user = i_new(struct replicator_user, 1);
		user->refcount = 1;
		user->username = i_strdup(username);
		user->last_update = ioloop_time;
		hash_table_insert(queue->user_hash, user->username, user);
		if (!user->popped)
			priorityq_add(queue->user_queue, &user->item);
	}
	return user;
}

void replicator_queue_update(struct replicator_queue *queue,
			     struct replicator_user *user,
			     enum replication_priority priority)
{
	if (user->priority >= priority) {
		/* user already has at least this high priority */
		e_debug(queue->event, "user %s: Ignoring priority %u update, "
			"since user already has priority=%u",
			user->username, priority, user->priority);
		return;
	}
	e_debug(queue->event, "user %s: Updating priority %u -> %u",
		user->username, user->priority, priority);
	user->priority = priority;
	user->last_update = ioloop_time;
}

void replicator_queue_add(struct replicator_queue *queue,
			  struct replicator_user *user)
{
	if (!user->popped) {
		priorityq_remove(queue->user_queue, &user->item);
		priorityq_add(queue->user_queue, &user->item);
	}
	if (queue->change_callback != NULL) {
		e_debug(queue->event, "user %s: Queue changed - calling callback",
			user->username);
		queue->change_callback(queue->change_context);
	}
}

void replicator_queue_add_sync_callback(struct replicator_queue *queue,
					struct replicator_user *user,
					replicator_sync_callback_t *callback,
					void *context)
{
	struct replicator_sync_lookup *lookup;

	i_assert(user->priority == REPLICATION_PRIORITY_SYNC);

	lookup = array_append_space(&queue->sync_lookups);
	lookup->user = user;
	lookup->callback = callback;
	lookup->context = context;
	lookup->wait_for_next_push = user->popped;

	replicator_queue_add(queue, user);
}

void replicator_queue_remove(struct replicator_queue *queue,
			     struct replicator_user **_user)
{
	struct replicator_user *user = *_user;

	*_user = NULL;
	e_debug(queue->event, "user %s: Removing user from queue", user->username);
	if (!user->popped)
		priorityq_remove(queue->user_queue, &user->item);
	hash_table_remove(queue->user_hash, user->username);

	if (queue->change_callback != NULL) {
		e_debug(queue->event, "user %s: Queue changed - calling callback",
			user->username);
		queue->change_callback(queue->change_context);
	}
	replicator_user_unref(&user);
}

unsigned int replicator_queue_count(struct replicator_queue *queue)
{
	return priorityq_count(queue->user_queue);
}

bool replicator_queue_want_sync_now(struct replicator_user *user,
				    unsigned int *next_secs_r)
{
	time_t next_sync = replicator_user_next_sync_time(user);
	if (next_sync <= ioloop_time) {
		*next_secs_r = 0;
		return TRUE;
	}
	*next_secs_r = next_sync - ioloop_time;
	return FALSE;
}

struct replicator_user *
replicator_queue_peek(struct replicator_queue *queue,
		      unsigned int *next_secs_r)
{
	struct priorityq_item *item;
	struct replicator_user *user;

	item = priorityq_peek(queue->user_queue);
	if (item == NULL) {
		/* no users defined. we shouldn't normally get here */
		*next_secs_r = 3600;
		return NULL;
	}
	user = (struct replicator_user *)item;
	(void)replicator_queue_want_sync_now(user, next_secs_r);
	return user;
}

struct replicator_user *
replicator_queue_pop(struct replicator_queue *queue,
		     unsigned int *next_secs_r)
{
	struct replicator_user *user;

	user = replicator_queue_peek(queue, next_secs_r);
	if (*next_secs_r > 0) {
		/* we don't want to sync the user yet */
		return NULL;
	}
	if (user != NULL) {
		priorityq_remove(queue->user_queue, &user->item);
		user->popped = TRUE;
	}
	return user;
}

static void
replicator_queue_handle_sync_lookups(struct replicator_queue *queue,
				     struct replicator_user *user)
{
	struct replicator_sync_lookup *lookups;
	ARRAY(struct replicator_sync_lookup) callbacks;
	unsigned int i, count;
	bool success = !user->last_sync_failed;

	t_array_init(&callbacks, 8);
	lookups = array_get_modifiable(&queue->sync_lookups, &count);
	for (i = 0; i < count; ) {
		if (lookups[i].user != user)
			i++;
		else if (lookups[i].wait_for_next_push) {
			/* another sync request came while user was being
			   replicated */
			i_assert(user->priority == REPLICATION_PRIORITY_SYNC);
			lookups[i].wait_for_next_push = FALSE;
			i++;
		} else {
			array_push_back(&callbacks, &lookups[i]);
			array_delete(&queue->sync_lookups, i, 1);
		}
	}

	e_debug(queue->event, "user %s: Handled sync lookups", user->username);

	array_foreach_modifiable(&callbacks, lookups)
		lookups->callback(success, lookups->context);
}

void replicator_queue_push(struct replicator_queue *queue,
			   struct replicator_user *user)
{
	i_assert(user->popped);

	priorityq_add(queue->user_queue, &user->item);
	user->popped = FALSE;

	T_BEGIN {
		replicator_queue_handle_sync_lookups(queue, user);
	} T_END;
}

static int
replicator_queue_import_line(struct replicator_queue *queue, const char *line)
{
	const char *const *args, *username, *state;
	unsigned int priority;
	struct replicator_user *user, tmp_user;

	/* <user> <priority> <last update> <last fast sync> <last full sync>
	   <last failed> <state> <last successful sync>*/
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) < 7)
		return -1;

	i_zero(&tmp_user);
	username = args[0];
	state = t_strdup_noconst(args[6]);
	if (username[0] == '\0' ||
	    str_to_uint(args[1], &priority) < 0 ||
	    str_to_time(args[2], &tmp_user.last_update) < 0 ||
	    str_to_time(args[3], &tmp_user.last_fast_sync) < 0 ||
	    str_to_time(args[4], &tmp_user.last_full_sync) < 0)
		return -1;
	tmp_user.priority = priority;
	tmp_user.last_sync_failed = args[5][0] != '0';

	if (str_array_length(args) >= 8) {
		if (str_to_time(args[7], &tmp_user.last_successful_sync) < 0)
			return -1;
	} else {
		tmp_user.last_successful_sync = 0;
                /* On-disk format didn't have this yet */
	}

	user = hash_table_lookup(queue->user_hash, username);
	if (user != NULL) {
		if (user->last_update > tmp_user.last_update) {
			/* we already have a newer state */
			return 0;
		}
		if (user->last_update == tmp_user.last_update) {
			/* either one of these could be newer. use the one
			   with higher priority. */
			if (user->priority > tmp_user.priority)
				return 0;
		}
	} else {
		user = replicator_queue_get(queue, username);
	}
	user->priority = tmp_user.priority;
	user->last_update = tmp_user.last_update;
	user->last_fast_sync = tmp_user.last_fast_sync;
	user->last_full_sync = tmp_user.last_full_sync;
	user->last_successful_sync = tmp_user.last_successful_sync;
	user->last_sync_failed = tmp_user.last_sync_failed;
	i_free(user->state);
	user->state = i_strdup(state);
	replicator_queue_add(queue, user);
	return 0;
}

int replicator_queue_import(struct replicator_queue *queue, const char *path)
{
	struct istream *input;
	const char *line;
	int fd, ret = 0;

	e_debug(queue->event, "Importing queue from %s", path);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		e_error(queue->event, "open(%s) failed: %m", path);
		return -1;
	}

	input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		T_BEGIN {
			ret = replicator_queue_import_line(queue, line);
		} T_END;
		if (ret < 0) {
			e_error(queue->event,
				"Corrupted replicator record in %s: %s", path, line);
			break;
		}
	}
	if (input->stream_errno != 0) {
		e_error(queue->event, "read(%s) failed: %s", path, i_stream_get_error(input));
		ret = -1;
	}
	i_stream_destroy(&input);
	return ret;
}

static void
replicator_queue_export_user(struct replicator_user *user, string_t *str)
{
	str_append_tabescaped(str, user->username);
	str_printfa(str, "\t%d\t%lld\t%lld\t%lld\t%d\t", (int)user->priority,
		    (long long)user->last_update,
		    (long long)user->last_fast_sync,
		    (long long)user->last_full_sync,
		    user->last_sync_failed ? 1 : 0);
	if (user->state != NULL)
		str_append_tabescaped(str, user->state);
	str_printfa(str, "\t%lld\n", (long long)user->last_successful_sync);
}

int replicator_queue_export(struct replicator_queue *queue, const char *path)
{
	struct replicator_queue_iter *iter;
	struct replicator_user *user;
	struct ostream *output;
	string_t *str;
	int fd, ret = 0;

	fd = creat(path, 0600);
	if (fd == -1) {
		e_error(queue->event, "creat(%s) failed: %m", path);
		return -1;
	}
	output = o_stream_create_fd_file_autoclose(&fd, 0);
	o_stream_cork(output);

	str = t_str_new(128);
	iter = replicator_queue_iter_init(queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		str_truncate(str, 0);
		replicator_queue_export_user(user, str);
		if (o_stream_send(output, str_data(str), str_len(str)) < 0)
			break;
	}
	replicator_queue_iter_deinit(&iter);
	if (o_stream_finish(output) < 0) {
		e_error(queue->event, "write(%s) failed: %s", path, o_stream_get_error(output));
		ret = -1;
	}
	o_stream_destroy(&output);
	return ret;
}

struct replicator_queue_iter *
replicator_queue_iter_init(struct replicator_queue *queue)
{
	struct replicator_queue_iter *iter;

	iter = i_new(struct replicator_queue_iter, 1);
	iter->queue = queue;
	iter->iter = hash_table_iterate_init(queue->user_hash);
	return iter;
}

struct replicator_user *
replicator_queue_iter_next(struct replicator_queue_iter *iter)
{
	struct replicator_user *user;
	char *username;

	if (!hash_table_iterate(iter->iter, iter->queue->user_hash,
				&username, &user))
		return NULL;
	return user;
}

void replicator_queue_iter_deinit(struct replicator_queue_iter **_iter)
{
	struct replicator_queue_iter *iter = *_iter;

	*_iter = NULL;

	hash_table_iterate_deinit(&iter->iter);
	i_free(iter);
}
