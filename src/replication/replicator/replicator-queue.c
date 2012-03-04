/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "hash.h"
#include "replicator-queue.h"

#include <unistd.h>
#include <fcntl.h>

struct replicator_sync_lookup {
	struct replicator_user *user;

	replicator_sync_callback_t *callback;
	void *context;

	bool wait_for_next_push;
};

struct replicator_queue {
	struct priorityq *user_queue;
	/* username => struct replicator_user* */
	struct hash_table *user_hash;

	ARRAY_DEFINE(sync_lookups, struct replicator_sync_lookup);

	unsigned int full_sync_interval;

	void (*change_callback)(void *context);
	void *change_context;
};

static int user_priority_cmp(const void *p1, const void *p2)
{
	const struct replicator_user *user1 = p1, *user2 = p2;

	if (user1->priority > user2->priority)
		return -1;
	if (user1->priority < user2->priority)
		return 1;

	if (user1->priority != REPLICATION_PRIORITY_NONE) {
		/* there is something to replicate */
		if (user1->last_fast_sync < user2->last_fast_sync)
			return -1;
		if (user1->last_fast_sync > user2->last_fast_sync)
			return 1;
	} else {
		/* nothing to replicate, but do still periodic full syncs */
		if (user1->last_full_sync < user2->last_full_sync)
			return -1;
		if (user1->last_full_sync > user2->last_full_sync)
			return 1;
	}
	return 0;
}

struct replicator_queue *replicator_queue_init(unsigned int full_sync_interval)
{
	struct replicator_queue *queue;

	queue = i_new(struct replicator_queue, 1);
	queue->full_sync_interval = full_sync_interval;
	queue->user_queue = priorityq_init(user_priority_cmp, 1024);
	queue->user_hash =
		hash_table_create(default_pool, default_pool, 1024,
				  str_hash, (hash_cmp_callback_t *)strcmp);
	i_array_init(&queue->sync_lookups, 32);
	return queue;
}

void replicator_queue_deinit(struct replicator_queue **_queue)
{
	struct replicator_queue *queue = *_queue;
	struct priorityq_item *item;

	*_queue = NULL;

	while ((item = priorityq_pop(queue->user_queue)) != NULL) {
		struct replicator_user *user = (struct replicator_user *)item;
		replicator_queue_remove(queue, &user);
	}

	priorityq_deinit(&queue->user_queue);
	hash_table_destroy(&queue->user_hash);
	i_assert(array_count(&queue->sync_lookups) == 0);
	array_free(&queue->sync_lookups);
	i_free(queue);
}

void replicator_queue_set_change_callback(struct replicator_queue *queue,
					  void (*callback)(void *context),
					  void *context)
{
	queue->change_callback = callback;
	queue->change_context = context;
}

static struct replicator_user *
replicator_queue_add_int(struct replicator_queue *queue, const char *username,
			 enum replication_priority priority)
{
	struct replicator_user *user;

	user = hash_table_lookup(queue->user_hash, username);
	if (user == NULL) {
		user = i_new(struct replicator_user, 1);
		user->username = i_strdup(username);
	} else {
		if (user->priority > priority) {
			/* user already has a higher priority than this */
			return user;
		}
		if (!user->popped)
			priorityq_remove(queue->user_queue, &user->item);
	}
	user->priority = priority;
	user->last_update = ioloop_time;

	if (!user->popped)
		priorityq_add(queue->user_queue, &user->item);
	return user;
}

struct replicator_user *
replicator_queue_add(struct replicator_queue *queue, const char *username,
		     enum replication_priority priority)
{
	struct replicator_user *user;

	user = replicator_queue_add_int(queue, username, priority);
	if (queue->change_callback != NULL)
		queue->change_callback(queue->change_context);
	return user;
}

void replicator_queue_add_sync(struct replicator_queue *queue,
			       const char *username,
			       replicator_sync_callback_t *callback,
			       void *context)
{
	struct replicator_user *user;
	struct replicator_sync_lookup *lookup;

	user = replicator_queue_add_int(queue, username,
					REPLICATION_PRIORITY_SYNC);

	lookup = array_append_space(&queue->sync_lookups);
	lookup->user = user;
	lookup->callback = callback;
	lookup->context = context;
	lookup->wait_for_next_push = user->popped;

	if (queue->change_callback != NULL)
		queue->change_callback(queue->change_context);
}

void replicator_queue_remove(struct replicator_queue *queue,
			     struct replicator_user **_user)
{
	struct replicator_user *user = *_user;

	*_user = NULL;
	if (!user->popped)
		priorityq_remove(queue->user_queue, &user->item);
	hash_table_remove(queue->user_hash, user->username);

	i_free(user->username);
	i_free(user);

	if (queue->change_callback != NULL)
		queue->change_callback(queue->change_context);
}

struct replicator_user *
replicator_queue_pop(struct replicator_queue *queue,
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

	if (user->priority == REPLICATION_PRIORITY_NONE &&
	    user->last_full_sync + queue->full_sync_interval > ioloop_time) {
		/* we don't want to do a full sync yet */
		*next_secs_r = user->last_full_sync +
			queue->full_sync_interval - ioloop_time;
		return NULL;
	}
	priorityq_remove(queue->user_queue, &user->item);
	user->popped = TRUE;
	return user;
}

static void
replicator_queue_handle_sync_lookups(struct replicator_queue *queue,
				     struct replicator_user *user)
{
	struct replicator_sync_lookup *lookups;
	ARRAY_DEFINE(callbacks, struct replicator_sync_lookup);
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
			array_append(&callbacks, &lookups[i], 1);
			array_delete(&queue->sync_lookups, i, 1);
		}
	}

	array_foreach_modifiable(&callbacks, lookups)
		lookups->callback(success, lookups->context);
}

void replicator_queue_push(struct replicator_queue *queue,
			   struct replicator_user *user)
{
	priorityq_add(queue->user_queue, &user->item);
	user->popped = FALSE;

	T_BEGIN {
		replicator_queue_handle_sync_lookups(queue, user);
	} T_END;
}

static int
replicator_queue_import_line(struct replicator_queue *queue, const char *line)
{
	const char *const *args, *username;
	unsigned int priority;
	struct replicator_user *user, tmp_user;

	/* <user> <priority> <last update> <last fast sync> <last full sync> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) < 5)
		return -1;

	memset(&tmp_user, 0, sizeof(tmp_user));
	username = args[0];
	if (username[0] == '\0' ||
	    str_to_uint(args[1], &priority) < 0 ||
	    str_to_time(args[2], &tmp_user.last_update) < 0 ||
	    str_to_time(args[3], &tmp_user.last_fast_sync) < 0 ||
	    str_to_time(args[3], &tmp_user.last_full_sync) < 0)
		return -1;
	tmp_user.priority = priority;

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
	}
	user = replicator_queue_add(queue, tmp_user.username,
				    tmp_user.priority);
	user->last_update = tmp_user.last_update;
	user->last_fast_sync = tmp_user.last_fast_sync;
	user->last_full_sync = tmp_user.last_full_sync;
	return 0;
}

int replicator_queue_import(struct replicator_queue *queue, const char *path)
{
	struct istream *input;
	const char *line;
	int fd, ret = 0;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		i_error("open(%s) failed: %m", path);
		return -1;
	}

	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		T_BEGIN {
			ret = replicator_queue_import_line(queue, line);
		} T_END;
		if (ret < 0) {
			i_error("Invalid replicator db record: %s", line);
			break;
		}
	}
	if (input->stream_errno != 0)
		ret = -1;
	i_stream_destroy(&input);
	return ret;
}

static void
replicator_queue_export_user(struct replicator_user *user, string_t *str)
{
	str_tabescape_write(str, user->username);
	str_printfa(str, "\t%d\t%lld\t%lld\t%lld", (int)user->priority,
		    (long long)user->last_update,
		    (long long)user->last_fast_sync,
		    (long long)user->last_full_sync);
}

int replicator_queue_export(struct replicator_queue *queue, const char *path)
{
	struct ostream *output;
	struct priorityq_item *const *items;
	unsigned int i, count;
	string_t *str;
	int fd, ret;

	fd = creat(path, 0600);
	if (fd == -1) {
		i_error("creat(%s) failed: %m", path);
		return -1;
	}
	output = o_stream_create_fd_file(fd, 0, TRUE);
	o_stream_cork(output);

	str = t_str_new(128);
	items = priorityq_items(queue->user_queue);
	count = priorityq_count(queue->user_queue);
	for (i = 0; i < count; i++) {
		struct replicator_user *user =
			(struct replicator_user *)items[i];

		str_truncate(str, 0);
		replicator_queue_export_user(user, str);
		if (o_stream_send(output, str_data(str), str_len(str)) < 0)
			break;
	}

	ret = output->last_failed_errno != 0 ? -1 : 0;
	o_stream_destroy(&output);
	return ret;
}
