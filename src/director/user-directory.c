/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "md5.h"
#include "hash.h"
#include "llist.h"
#include "mail-host.h"
#include "user-directory.h"

#define MAX_CLOCK_DRIFT_SECS 2

struct user_directory_iter {
	struct user_directory *dir;
	struct user *pos;
};

struct user_directory {
	/* const char *username => struct user* */
	struct hash_table *hash;
	/* sorted by time */
	struct user *head, *tail;

	ARRAY_DEFINE(iters, struct user_directory_iter *);

	unsigned int timeout_secs;
};

static void user_move_iters(struct user_directory *dir, struct user *user)
{
	struct user_directory_iter *const *iterp;

	array_foreach(&dir->iters, iterp) {
		if ((*iterp)->pos == user)
			(*iterp)->pos = user->next;
	}
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

struct user *
user_directory_add(struct user_directory *dir, unsigned int username_hash,
		   struct mail_host *host, time_t timestamp)
{
	struct user *user, *pos;

	user = i_new(struct user, 1);
	user->username_hash = username_hash;
	user->host = host;
	user->host->user_count++;
	user->timestamp = timestamp;

	if (dir->tail == NULL || (time_t)dir->tail->timestamp <= timestamp)
		DLLIST2_APPEND(&dir->head, &dir->tail, user);
	else {
		/* need to insert to correct position */
		for (pos = dir->tail; pos != NULL; pos = pos->prev) {
			if ((time_t)pos->timestamp <= timestamp)
				break;
		}
		if (pos == NULL)
			DLLIST2_PREPEND(&dir->head, &dir->tail, user);
		else {
			user->prev = pos;
			user->next = pos->next;
			user->prev->next = user;
			user->next->prev = user;
		}
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

unsigned int user_directory_get_username_hash(const char *username)
{
	/* NOTE: If you modify this, modify also
	   director_username_hash() in login-common/login-proxy.c */
	unsigned char md5[MD5_RESULTLEN];
	unsigned int i, hash = 0;

	md5_get_digest(username, strlen(username), md5);
	for (i = 0; i < sizeof(hash); i++)
		hash = (hash << CHAR_BIT) | md5[i];
	return hash;
}

bool user_directory_user_has_connections(struct user_directory *dir,
					 struct user *user)
{
	time_t expire_timestamp = user->timestamp + dir->timeout_secs;

	return expire_timestamp - MAX_CLOCK_DRIFT_SECS >= ioloop_time;
}

struct user_directory *user_directory_init(unsigned int timeout_secs)
{
	struct user_directory *dir;

	dir = i_new(struct user_directory, 1);
	dir->timeout_secs = timeout_secs;
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
