/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "mail-host.h"

/* n% of timeout_secs */
#define USER_NEAR_EXPIRING_PERCENTAGE 10
/* but min/max. of this many secs */
#define USER_NEAR_EXPIRING_MIN 3
#define USER_NEAR_EXPIRING_MAX 30
/* This shouldn't matter what it is exactly, just try it sometimes later. */
#define USER_BEING_KILLED_EXPIRE_RETRY_SECS 60

struct user_directory_iter {
	struct user_directory *dir;
	struct user *pos, *stop_after_tail;
};

struct user_directory {
	/* unsigned int username_hash => user */
	HASH_TABLE(void *, struct user *) hash;
	/* sorted by time. may be unsorted while handshakes are going on. */
	struct user *head, *tail;

	ARRAY(struct user_directory_iter *) iters;
	user_free_hook_t *user_free_hook;

	unsigned int timeout_secs;
	/* If user's expire time is less than this many seconds away,
	   don't assume that other directors haven't yet expired it */
	unsigned int user_near_expiring_secs;
	struct timeout *to_expire;
	time_t to_expire_timestamp;

	bool sort_pending;
};

static void user_move_iters(struct user_directory *dir, struct user *user)
{
	struct user_directory_iter *const *iterp;

	array_foreach(&dir->iters, iterp) {
		if ((*iterp)->pos == user)
			(*iterp)->pos = user->next;
		if ((*iterp)->stop_after_tail == user) {
			(*iterp)->stop_after_tail =
				user->prev != NULL ? user->prev : user->next;
		}
	}
}

static void user_free(struct user_directory *dir, struct user *user)
{
	i_assert(user->host->user_count > 0);
	user->host->user_count--;

	if (dir->user_free_hook != NULL)
		dir->user_free_hook(user);
	user_move_iters(dir, user);

	hash_table_remove(dir->hash, POINTER_CAST(user->username_hash));
	DLLIST2_REMOVE(&dir->head, &dir->tail, user);
	i_free(user);
}

static bool user_directory_user_has_connections(struct user_directory *dir,
						struct user *user,
						time_t *expire_timestamp_r)
{
	time_t expire_timestamp = user->timestamp + dir->timeout_secs;

	if (expire_timestamp > ioloop_time) {
		*expire_timestamp_r = expire_timestamp;
		return TRUE;
	}

	if (USER_IS_BEING_KILLED(user)) {
		/* don't free this user until the kill is finished */
		*expire_timestamp_r = ioloop_time +
			USER_BEING_KILLED_EXPIRE_RETRY_SECS;
		return TRUE;
	}

	if (user->weak) {
		if (expire_timestamp + USER_NEAR_EXPIRING_MAX > ioloop_time) {
			*expire_timestamp_r = expire_timestamp +
				USER_NEAR_EXPIRING_MAX;
			return TRUE;
		}

		i_warning("User %u weakness appears to be stuck, removing it",
			  user->username_hash);
	}
	return FALSE;
}

static void user_directory_drop_expired(struct user_directory *dir)
{
	time_t expire_timestamp = 0;

	while (dir->head != NULL &&
	       !user_directory_user_has_connections(dir, dir->head, &expire_timestamp)) {
		user_free(dir, dir->head);
		expire_timestamp = 0;
	}
	i_assert(expire_timestamp > ioloop_time || expire_timestamp == 0);

	if (expire_timestamp != dir->to_expire_timestamp) {
		timeout_remove(&dir->to_expire);
		if (expire_timestamp != 0) {
			struct timeval tv = { .tv_sec = expire_timestamp };
			dir->to_expire_timestamp = tv.tv_sec;
			dir->to_expire = timeout_add_absolute(&tv,
				user_directory_drop_expired, dir);
		}
	}
}

unsigned int user_directory_count(struct user_directory *dir)
{
	return hash_table_count(dir->hash);
}

struct user *user_directory_lookup(struct user_directory *dir,
				   unsigned int username_hash)
{
	struct user *user;
	time_t expire_timestamp;

	user_directory_drop_expired(dir);
	user = hash_table_lookup(dir->hash, POINTER_CAST(username_hash));
	if (user != NULL && !user_directory_user_has_connections(dir, user, &expire_timestamp)) {
		user_free(dir, user);
		user = NULL;
	}
	return user;
}

struct user *
user_directory_add(struct user_directory *dir, unsigned int username_hash,
		   struct mail_host *host, time_t timestamp)
{
	struct user *user;

	/* make sure we don't add timestamps higher than ioloop time */
	if (timestamp > ioloop_time)
		timestamp = ioloop_time;

	user = i_new(struct user, 1);
	user->username_hash = username_hash;
	user->host = host;
	user->host->user_count++;
	user->timestamp = timestamp;
	DLLIST2_APPEND(&dir->head, &dir->tail, user);

	if (dir->to_expire == NULL) {
		struct timeval tv = { .tv_sec = ioloop_time + dir->timeout_secs };
		dir->to_expire_timestamp = tv.tv_sec;
		dir->to_expire = timeout_add_absolute(&tv, user_directory_drop_expired, dir);
	}
	hash_table_insert(dir->hash, POINTER_CAST(user->username_hash), user);
	return user;
}

void user_directory_refresh(struct user_directory *dir, struct user *user)
{
	user_move_iters(dir, user);

	user->timestamp = ioloop_time;
	DLLIST2_REMOVE(&dir->head, &dir->tail, user);
	DLLIST2_APPEND(&dir->head, &dir->tail, user);
}

void user_directory_remove_host(struct user_directory *dir,
				struct mail_host *host)
{
	struct user *user, *next;

	for (user = dir->head; user != NULL; user = next) {
		next = user->next;

		if (user->host == host)
			user_free(dir, user);
	}
}

static int user_timestamp_cmp(struct user *const *user1,
			      struct user *const *user2)
{
	if ((*user1)->timestamp < (*user2)->timestamp)
		return -1;
	if ((*user1)->timestamp > (*user2)->timestamp)
		return 1;
	return 0;
}

void user_directory_sort(struct user_directory *dir)
{
	ARRAY(struct user *) users;
	struct user *user, *const *userp;
	unsigned int i, users_count = hash_table_count(dir->hash);

	dir->sort_pending = FALSE;

	if (users_count == 0) {
		i_assert(dir->head == NULL);
		return;
	}

	if (array_count(&dir->iters) > 0) {
		/* We can't sort the directory while there are iterators
		   or they'll skip users. Do the sort after there are no more
		   iterators. */
		dir->sort_pending = TRUE;
		return;
	}

	/* place all users into array and sort it */
	i_array_init(&users, users_count);
	user = dir->head;
	for (i = 0; i < users_count; i++, user = user->next)
		array_append(&users, &user, 1);
	i_assert(user == NULL);
	array_sort(&users, user_timestamp_cmp);

	/* recreate the linked list */
	dir->head = dir->tail = NULL;
	array_foreach(&users, userp)
		DLLIST2_APPEND(&dir->head, &dir->tail, *userp);
	i_assert(dir->head != NULL &&
		 dir->head->timestamp <= dir->tail->timestamp);
	array_free(&users);
}

bool user_directory_user_is_recently_updated(struct user_directory *dir,
					     struct user *user)
{
	return (time_t)(user->timestamp + dir->timeout_secs/2) >= ioloop_time;
}

bool user_directory_user_is_near_expiring(struct user_directory *dir,
					  struct user *user)
{
	time_t expire_timestamp;

	expire_timestamp = user->timestamp +
		(dir->timeout_secs - dir->user_near_expiring_secs);
	return expire_timestamp < ioloop_time;
}

struct user_directory *
user_directory_init(unsigned int timeout_secs,
		    user_free_hook_t *user_free_hook)
{
	struct user_directory *dir;

	i_assert(timeout_secs > USER_NEAR_EXPIRING_MIN);

	dir = i_new(struct user_directory, 1);
	dir->timeout_secs = timeout_secs;
	dir->user_near_expiring_secs =
		timeout_secs * USER_NEAR_EXPIRING_PERCENTAGE / 100;
	dir->user_near_expiring_secs =
		I_MIN(dir->user_near_expiring_secs, USER_NEAR_EXPIRING_MAX);
	dir->user_near_expiring_secs =
		I_MAX(dir->user_near_expiring_secs, USER_NEAR_EXPIRING_MIN);
	i_assert(dir->timeout_secs/2 > dir->user_near_expiring_secs);

	dir->user_free_hook = user_free_hook;
	hash_table_create_direct(&dir->hash, default_pool, 0);
	i_array_init(&dir->iters, 8);
	return dir;
}

void user_directory_deinit(struct user_directory **_dir)
{
	struct user_directory *dir = *_dir;

	*_dir = NULL;

	i_assert(array_count(&dir->iters) == 0);

	while (dir->head != NULL)
		user_free(dir, dir->head);
	timeout_remove(&dir->to_expire);
	hash_table_destroy(&dir->hash);
	array_free(&dir->iters);
	i_free(dir);
}

struct user_directory_iter *
user_directory_iter_init(struct user_directory *dir,
			 bool iter_until_current_tail)
{
	struct user_directory_iter *iter;

	iter = i_new(struct user_directory_iter, 1);
	iter->dir = dir;
	iter->pos = dir->head;
	iter->stop_after_tail = iter_until_current_tail ? dir->tail : NULL;
	array_push_back(&dir->iters, &iter);
	user_directory_drop_expired(dir);
	return iter;
}

struct user *user_directory_iter_next(struct user_directory_iter *iter)
{
	struct user *user;

	user = iter->pos;
	if (user == NULL)
		return NULL;

	iter->pos = user->next;
	if (user == iter->stop_after_tail) {
		/* this is the last user we want to iterate */
		iter->pos = NULL;
	}
	return user;
}

void user_directory_iter_deinit(struct user_directory_iter **_iter)
{
	struct user_directory_iter *iter = *_iter;
	struct user_directory_iter *const *iters;
	unsigned int i, count;

	*_iter = NULL;

	iters = array_get(&iter->dir->iters, &count);
	for (i = 0; i < count; i++) {
		if (iters[i] == iter) {
			array_delete(&iter->dir->iters, i, 1);
			break;
		}
	}
	if (array_count(&iter->dir->iters) == 0 && iter->dir->sort_pending)
		user_directory_sort(iter->dir);
	i_free(iter);
}
