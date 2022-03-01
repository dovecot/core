/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "dict.h"
#include "dict-private.h"
#include "dict-init-cache.h"
#include "llist.h"

/* How many seconds to keep dict opened for reuse after it's been closed */
#define DICT_CACHE_TIMEOUT_SECS 30
/* How many closed dicts to keep */
#define DICT_CACHE_MAX_COUNT 10

struct dict_init_cache_list {
	struct dict_init_cache_list *prev, *next;

	struct dict *dict;
	char *dict_name;
	int refcount;

	time_t destroy_time;
};

static struct dict_init_cache_list *dicts = NULL;
static struct timeout *to_dict = NULL;

static struct dict_init_cache_list *
dict_init_cache_add(const char *dict_name, struct dict *dict)
{
	struct dict_init_cache_list *list;

	list = i_new(struct dict_init_cache_list, 1);
	list->refcount = 1;
	list->dict = dict;
	list->dict_name = i_strdup(dict_name);

	DLLIST_PREPEND(&dicts, list);

	return list;
}

static void dict_init_cache_list_free(struct dict_init_cache_list *list)
{
	i_assert(list->refcount == 0);

	DLLIST_REMOVE(&dicts, list);
	dict_deinit(&list->dict);
	i_free(list->dict_name);
	i_free(list);
}

static struct dict_init_cache_list *dict_init_cache_find(const char *dict_name)
{
	struct dict_init_cache_list *listp = dicts, *next = NULL, *match = NULL;
	unsigned int ref0_count = 0;

	while (listp != NULL) {
                next = listp->next;
		if (match != NULL) {
			/* already found the dict. we're just going through
			   the rest of them to drop 0 refcounts */
		} else if (strcmp(dict_name, listp->dict_name) == 0)
			match = listp;

		if (listp->refcount == 0 && listp != match) {
			if (listp->destroy_time <= ioloop_time ||
			    ref0_count >= DICT_CACHE_MAX_COUNT - 1)
				dict_init_cache_list_free(listp);
			else
				ref0_count++;
		}
                listp = next;
	}
	return match;
}

int dict_init_cache_get(const char *dict_name, const char *uri,
			const struct dict_settings *set,
			struct dict **dict_r, const char **error_r)
{
	struct dict_init_cache_list *match;
	int ret = 0;

	match = dict_init_cache_find(dict_name);
	if (match == NULL) {
		if (dict_init(uri, set, dict_r, error_r) < 0)
			return -1;
		match = dict_init_cache_add(dict_name, *dict_r);
	} else {
		match->refcount++;
		*dict_r = match->dict;
	}
	i_assert(match->dict != NULL);
	return ret;
}

static void destroy_unrefed(void)
{
	struct dict_init_cache_list *listp, *next = NULL;
	bool seen_ref0 = FALSE;

	for (listp = dicts; listp != NULL; listp = next) {
		next = listp->next;

		i_assert(listp->refcount >= 0);
		if (listp->refcount > 0)
			;
		else if (listp->destroy_time <= ioloop_time)
			dict_init_cache_list_free(listp);
		else
			seen_ref0 = TRUE;
	}

	if (!seen_ref0 && to_dict != NULL)
		timeout_remove(&to_dict);
}

static void dict_removal_timeout(void *context ATTR_UNUSED)
{
	destroy_unrefed();
}

void dict_init_cache_unref(struct dict **_dict)
{
	struct dict *dict = *_dict;
	struct dict_init_cache_list *listp;

	if (dict == NULL)
		return;

	*_dict = NULL;
	for (listp = dicts; listp != NULL; listp = listp->next) {
		if (listp->dict == dict)
			break;
	}

	i_assert(listp != NULL && listp->dict == dict);
	i_assert(listp->refcount > 0);

	listp->refcount--;
	listp->destroy_time = ioloop_time + DICT_CACHE_TIMEOUT_SECS;

	if (to_dict == NULL) {
		to_dict = timeout_add_to(io_loop_get_root(),
					 DICT_CACHE_TIMEOUT_SECS*1000/2,
					 dict_removal_timeout, NULL);
	}
}

void dict_init_cache_wait_all(void)
{
	struct dict_init_cache_list *listp;

	for (listp = dicts; listp != NULL; listp = listp->next)
		dict_wait(listp->dict);
}

void dict_init_cache_destroy_all(void)
{
	timeout_remove(&to_dict);
	while (dicts != NULL)
		dict_init_cache_list_free(dicts);
}
