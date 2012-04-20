/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "mail-user-hash.h"
#include "mail-host.h"
#include "user-directory.h"

/* n% of timeout_secs */
#define USER_NEAR_EXPIRING_PERCENTAGE 10
/* but max. of this many secs */
#define USER_NEAR_EXPIRING_MAX 30

struct user_directory_iter {
	struct user_directory *dir;
	struct user *pos;
};

struct user_directory {
	/* const char *username => struct user* */
	struct hash_table *hash;
	/* sorted by time */
	struct user *head, *tail;
	struct user *prev_insert_pos;

	ARRAY_DEFINE(iters, struct user_directory_iter *);

	char *username_hash_fmt;
	unsigned int timeout_secs;
	/* If user's expire time is less than this many seconds away,
	   don't assume that other directors haven't yet expired it */
	unsigned int user_near_expiring_secs;
};

static void user_move_iters(struct user_directory *dir, struct user *user)
{
	struct user_directory_iter *const *iterp;

	array_foreach(&dir->iters, iterp) {
		if ((*iterp)->pos == user)
			(*iterp)->pos = user->next;
	}

	if (dir->prev_insert_pos == user)
		dir->prev_insert_pos = user->next;
}

static void user_free(struct user_directory *dir, struct user *user)
{
	i_assert(user->host->user_count > 0);
	user->host->user_count--;

	user_move_iters(dir, user);

	hash_table_remove(dir->hash, POINTER_CAST(user->username_hash));
	DLLIST2_REMOVE(&dir->head, &dir->tail, user);
	i_free(user);
}

static bool user_directory_user_has_connections(struct user_directory *dir,
						struct user *user)
{
	time_t expire_timestamp = user->timestamp + dir->timeout_secs;

	return expire_timestamp >= ioloop_time;
}

static void user_directory_drop_expired(struct user_directory *dir)
{
	while (dir->head != NULL &&
	       !user_directory_user_has_connections(dir, dir->head))
		user_free(dir, dir->head);
}

struct user *user_directory_lookup(struct user_directory *dir,
				   unsigned int username_hash)
{
	user_directory_drop_expired(dir);

	return hash_table_lookup(dir->hash, POINTER_CAST(username_hash));
}

static void
user_directory_insert_backwards(struct user_directory *dir,
				struct user *pos, struct user *user)
{
	for (; pos != NULL; pos = pos->prev) {
		if ((time_t)pos->timestamp <= user->timestamp)
			break;
	}
	if (pos == NULL)
		DLLIST2_PREPEND(&dir->head, &dir->tail, user);
	else {
		user->prev = pos;
		user->next = pos->next;
		user->prev->next = user;
		if (user->next != NULL)
			user->next->prev = user;
		else
			dir->tail = user;
	}
}

static void
user_directory_insert_forwards(struct user_directory *dir,
			       struct user *pos, struct user *user)
{
	for (; pos != NULL; pos = pos->next) {
		if ((time_t)pos->timestamp >= user->timestamp)
			break;
	}
	if (pos == NULL)
		DLLIST2_APPEND(&dir->head, &dir->tail, user);
	else {
		user->prev = pos->prev;
		user->next = pos;
		if (user->prev != NULL)
			user->prev->next = user;
		else
			dir->head = user;
		user->next->prev = user;
	}
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

	if (dir->tail == NULL || (time_t)dir->tail->timestamp <= timestamp)
		DLLIST2_APPEND(&dir->head, &dir->tail, user);
	else {
		/* need to insert to correct position. we should get here
		   only when handshaking. the handshaking USER requests should
		   come sorted by timestamp. so keep track of the previous
		   insert position, the next USER should be inserted after
		   it. */
		if (dir->prev_insert_pos == NULL) {
			/* find the position starting from tail */
			user_directory_insert_backwards(dir, dir->tail, user);
		} else if (timestamp < dir->prev_insert_pos->timestamp) {
			user_directory_insert_backwards(dir, dir->prev_insert_pos,
							user);
		} else {
			user_directory_insert_forwards(dir, dir->prev_insert_pos,
						       user);
		}
	}

	dir->prev_insert_pos = user;
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

unsigned int user_directory_get_username_hash(struct user_directory *dir,
					      const char *username)
{
	return mail_user_hash(username, dir->username_hash_fmt);
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
user_directory_init(unsigned int timeout_secs, const char *username_hash_fmt)
{
	struct user_directory *dir;

	dir = i_new(struct user_directory, 1);
	dir->timeout_secs = timeout_secs;
	dir->user_near_expiring_secs =
		timeout_secs * USER_NEAR_EXPIRING_PERCENTAGE / 100;
	dir->user_near_expiring_secs =
		I_MIN(dir->user_near_expiring_secs, USER_NEAR_EXPIRING_MAX);
	dir->user_near_expiring_secs =
		I_MAX(dir->user_near_expiring_secs, 1);

	dir->username_hash_fmt = i_strdup(username_hash_fmt);
	dir->hash = hash_table_create(default_pool, default_pool,
				      0, NULL, NULL);
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
	hash_table_destroy(&dir->hash);
	array_free(&dir->iters);
	i_free(dir->username_hash_fmt);
	i_free(dir);
}

struct user_directory_iter *
user_directory_iter_init(struct user_directory *dir)
{
	struct user_directory_iter *iter;

	iter = i_new(struct user_directory_iter, 1);
	iter->dir = dir;
	iter->pos = dir->head;
	array_append(&dir->iters, &iter, 1);
	user_directory_drop_expired(dir);
	return iter;
}

struct user *user_directory_iter_next(struct user_directory_iter *iter)
{
	struct user *user;

	user = iter->pos;
	if (user == NULL)
		return FALSE;

	iter->pos = user->next;
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
	i_free(iter);
}
