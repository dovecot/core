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

typedef struct _CookieList CookieList;

struct _CookieList {
	CookieList *next;
	time_t created;

	CookieData *data;
};

static HashTable *cookies;
static CookieList *oldest_cookie, **next_cookie;

static Timeout to;

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
		ret = ((unsigned char *) p1)[i] - ((unsigned char *) p2)[i];
		if (ret != 0)
			return ret;
	}

	return 0;
}

void cookie_add(CookieData *data)
{
	CookieList *list;

	do {
		random_fill(data->cookie, AUTH_COOKIE_SIZE);
	} while (hash_lookup(cookies, data->cookie));

	/* add to linked list */
	list = i_new(CookieList, 1);
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
	CookieList **pos, *list;

	hash_remove(cookies, cookie);

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

CookieData *cookie_lookup(unsigned char cookie[AUTH_COOKIE_SIZE])
{
	return hash_lookup(cookies, cookie);
}

void cookie_remove(unsigned char cookie[AUTH_COOKIE_SIZE])
{
	cookie_destroy(cookie, TRUE);
}

CookieData *cookie_lookup_and_remove(unsigned char cookie[AUTH_COOKIE_SIZE])
{
	CookieData *data;

	data = hash_lookup(cookies, cookie);
	if (data != NULL)
		cookie_destroy(cookie, FALSE);
	return data;
}

static void cookie_timeout(void *user_data __attr_unused__,
			   Timeout timeout __attr_unused__)
{
	time_t remove_time;

        remove_time = ioloop_time - COOKIE_TIMEOUT;
	while (oldest_cookie != NULL && oldest_cookie->created < remove_time)
		cookie_destroy(oldest_cookie->data->cookie, TRUE);
}

void cookies_init(void)
{
	random_init();

	oldest_cookie = NULL;
	next_cookie = &oldest_cookie;

	cookies = hash_create(default_pool, 100, cookie_hash, cookie_cmp);
	to = timeout_add(10000, cookie_timeout, NULL);
}

void cookies_deinit(void)
{
	while (oldest_cookie != NULL)
		cookie_destroy(oldest_cookie->data->cookie, TRUE);
	hash_destroy(cookies);

	timeout_remove(to);
	random_deinit();
}
