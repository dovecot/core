/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "hash.h"
#include "cookie.h"
#include "randgen.h"

#include <unistd.h>
#include <fcntl.h>

/* 30 seconds should be more than enough */
#define COOKIE_TIMEOUT 30

struct cookie_list {
	struct cookie_list *next;
	time_t created;

	struct cookie_data *data;
};

static struct hash_table *cookies;
static struct cookie_list *oldest_cookie, **next_cookie;

static struct timeout *to;

/* a char* hash function from ASU -- from glib */
static unsigned int cookie_hash(const void *p)
{
        const unsigned char *s = p;
	unsigned int i, g, h = 0;

	for (i = 0; i < AUTH_COOKIE_SIZE; i++) {
		h = (h << 4) + s[i];
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}

	return h;
}

static int cookie_cmp(const void *p1, const void *p2)
{
	int i, ret;

	for (i = 0; i < AUTH_COOKIE_SIZE; i++) {
		ret = ((const unsigned char *) p1)[i] -
			((const unsigned char *) p2)[i];
		if (ret != 0)
			return ret;
	}

	return 0;
}

void cookie_add(struct cookie_data *data)
{
	struct cookie_list *list;

	do {
		random_fill(data->cookie, AUTH_COOKIE_SIZE);
	} while (hash_lookup(cookies, data->cookie));

	/* add to linked list */
	list = i_new(struct cookie_list, 1);
	list->created = ioloop_time;
	list->data = data;

	*next_cookie = list;
	next_cookie = &list->next;

	/* add to hash */
	hash_insert(cookies, data->cookie, data);
}

static void cookie_destroy(unsigned char cookie[AUTH_COOKIE_SIZE],
			   int free_data)
{
	struct cookie_list **pos, *list;

	hash_remove(cookies, cookie);

	/* FIXME: slow */
	list = NULL;
	for (pos = &oldest_cookie; *pos != NULL; pos = &(*pos)->next) {
		if (cookie_cmp((*pos)->data->cookie, cookie) == 0) {
			list = *pos;
			*pos = list->next;
			break;
		}
	}
	i_assert(list != NULL);

	if (list->next == NULL)
		next_cookie = pos;

	if (free_data)
		list->data->free(list->data);
	i_free(list);
}

struct cookie_data *cookie_lookup(unsigned char cookie[AUTH_COOKIE_SIZE])
{
	return hash_lookup(cookies, cookie);
}

void cookie_remove(unsigned char cookie[AUTH_COOKIE_SIZE])
{
	cookie_destroy(cookie, TRUE);
}

struct cookie_data *
cookie_lookup_and_remove(unsigned int login_pid,
			 unsigned char cookie[AUTH_COOKIE_SIZE])
{
	struct cookie_data *data;

	data = hash_lookup(cookies, cookie);
	if (data != NULL) {
		if (data->login_pid != login_pid)
			data = NULL;
		else
			cookie_destroy(cookie, FALSE);
	}
	return data;
}

void cookies_remove_login_pid(unsigned int login_pid)
{
	struct cookie_list *list, *next;

	/* FIXME: slow */
	for (list = oldest_cookie; list != NULL; list = next) {
		next = list->next;

		if (list->data->login_pid == login_pid)
			cookie_destroy(list->data->cookie, TRUE);
	}
}

static void cookie_timeout(void *context __attr_unused__,
			   struct timeout *timeout __attr_unused__)
{
	time_t remove_time;

        remove_time = ioloop_time - COOKIE_TIMEOUT;
	while (oldest_cookie != NULL && oldest_cookie->created < remove_time)
		cookie_destroy(oldest_cookie->data->cookie, TRUE);
}

void cookies_init(void)
{
	oldest_cookie = NULL;
	next_cookie = &oldest_cookie;

	cookies = hash_create(default_pool, default_pool, 100,
			      cookie_hash, cookie_cmp);
	to = timeout_add(10000, cookie_timeout, NULL);
}

void cookies_deinit(void)
{
	while (oldest_cookie != NULL)
		cookie_destroy(oldest_cookie->data->cookie, TRUE);
	hash_destroy(cookies);

	timeout_remove(to);
}
