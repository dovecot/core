/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "module-context.h"
#include "eacces-error.h"
#include "mail-index-private.h"
#include "mail-index-alloc-cache.h"

#define MAIL_INDEX_ALLOC_CACHE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_index_alloc_cache_index_module)

/* How many seconds to keep index opened for reuse after it's been closed */
#define INDEX_CACHE_TIMEOUT 10
/* How many closed indexes to keep */
#define INDEX_CACHE_MAX 3

struct mail_index_alloc_cache_list {
	union mail_index_module_context module_ctx;
	struct mail_index_alloc_cache_list *next;

	struct mail_index *index;
	char *mailbox_path;
	int refcount;
	bool referenced;

	dev_t index_dir_dev;
	ino_t index_dir_ino;

	time_t destroy_time;
};

static MODULE_CONTEXT_DEFINE_INIT(mail_index_alloc_cache_index_module,
				  &mail_index_module_register);
static struct mail_index_alloc_cache_list *indexes = NULL;
static unsigned int indexes_cache_references_count = 0;
static struct timeout *to_index = NULL;

static struct mail_index_alloc_cache_list *
mail_index_alloc_cache_add(struct mail_index *index,
			   const char *mailbox_path, struct stat *st)
{
	struct mail_index_alloc_cache_list *list;

	list = i_new(struct mail_index_alloc_cache_list, 1);
	list->refcount = 1;
	list->index = index;

	list->mailbox_path = i_strdup(mailbox_path);
	list->index_dir_dev = st->st_dev;
	list->index_dir_ino = st->st_ino;

	list->next = indexes;
	indexes = list;

	MODULE_CONTEXT_SET(index, mail_index_alloc_cache_index_module, list);
	return list;
}

static void
mail_index_alloc_cache_list_unref(struct mail_index_alloc_cache_list *list)
{
	i_assert(list->referenced);
	i_assert(indexes_cache_references_count > 0);

	indexes_cache_references_count--;
	mail_index_close(list->index);
	list->referenced = FALSE;
}

static void
mail_index_alloc_cache_list_free(struct mail_index_alloc_cache_list *list)
{
	i_assert(list->refcount == 0);

	if (list->referenced)
		mail_index_alloc_cache_list_unref(list);
	mail_index_free(&list->index);
	i_free(list->mailbox_path);
	i_free(list);
}

static struct mail_index_alloc_cache_list *
mail_index_alloc_cache_find(const char *mailbox_path, const char *index_dir,
			    const struct stat *index_st)
{
	struct mail_index_alloc_cache_list **indexp, *rec, *match;
	unsigned int destroy_count;
	struct stat st;

	destroy_count = 0; match = NULL;
	for (indexp = &indexes; *indexp != NULL;) {
		rec = *indexp;

		if (match != NULL) {
			/* already found the index. we're just going through
			   the rest of them to drop 0 refcounts */
		} else if (rec->refcount == 0 && rec->index->open_count == 0) {
			/* index is already closed. don't even try to
			   reuse it. */
		} else if (index_dir != NULL && rec->index_dir_ino != 0) {
			if (index_st->st_ino == rec->index_dir_ino &&
			    CMP_DEV_T(index_st->st_dev, rec->index_dir_dev)) {
				/* make sure the directory still exists.
				   it might have been renamed and we're trying
				   to access it via its new path now. */
				if (stat(rec->index->dir, &st) < 0 ||
				    st.st_ino != index_st->st_ino ||
				    !CMP_DEV_T(st.st_dev, index_st->st_dev))
					rec->destroy_time = 0;
				else
					match = rec;
			}
		} else if (mailbox_path != NULL && rec->mailbox_path != NULL &&
			   index_dir == NULL && rec->index_dir_ino == 0) {
			if (strcmp(mailbox_path, rec->mailbox_path) == 0)
				match = rec;
		}

		if (rec->refcount == 0 && rec != match) {
			if (rec->destroy_time <= ioloop_time ||
			    destroy_count >= INDEX_CACHE_MAX) {
				*indexp = rec->next;
				mail_index_alloc_cache_list_free(rec);
				continue;
			} else {
				destroy_count++;
			}
		}

                indexp = &(*indexp)->next;
	}
	return match;
}

struct mail_index *
mail_index_alloc_cache_get(struct event *parent_event, const char *mailbox_path,
			   const char *index_dir, const char *prefix)
{
	struct mail_index_alloc_cache_list *match;
	struct stat st;

	/* compare index_dir inodes so we don't break even with symlinks.
	   if index_dir doesn't exist yet or if using in-memory indexes, just
	   compare mailbox paths */
	i_zero(&st);
	if (index_dir == NULL) {
		/* in-memory indexes */
	} else if (stat(index_dir, &st) < 0) {
		if (errno == ENOENT) {
			/* it'll be created later */
		} else if (errno == EACCES) {
			i_error("%s", eacces_error_get("stat", index_dir));
		} else {
			i_error("stat(%s) failed: %m", index_dir);
		}
	}

	match = mail_index_alloc_cache_find(mailbox_path, index_dir, &st);
	if (match == NULL) {
		struct mail_index *index =
			mail_index_alloc(parent_event, index_dir, prefix);
		match = mail_index_alloc_cache_add(index, mailbox_path, &st);
	} else {
		match->refcount++;
	}
	i_assert(match->index != NULL);
	return match->index;
}

static bool destroy_unrefed(unsigned int min_destroy_count)
{
	struct mail_index_alloc_cache_list **list, *rec;
	bool destroyed = FALSE;
	bool seen_ref0 = FALSE;

	for (list = &indexes; *list != NULL;) {
		rec = *list;

		if (rec->refcount == 0 &&
		    (min_destroy_count > 0 || rec->destroy_time <= ioloop_time)) {
			*list = rec->next;
			destroyed = TRUE;
			mail_index_alloc_cache_list_free(rec);
			if (min_destroy_count > 0)
				min_destroy_count--;
		} else {
			if (rec->refcount == 0)
				seen_ref0 = TRUE;
			if (min_destroy_count > 0 &&
			    rec->index->open_count == 1 &&
			    rec->referenced) {
				/* we're the only one keeping this index open.
				   we might be here, because the caller is
				   deleting this mailbox and wants its indexes
				   to be closed. so close it. */
				destroyed = TRUE;
				mail_index_alloc_cache_list_unref(rec);
			}
			list = &(*list)->next;
		}
	}

	if (!seen_ref0 && to_index != NULL)
		timeout_remove(&to_index);
	return destroyed;
}

static void ATTR_NULL(1)
index_removal_timeout(void *context ATTR_UNUSED)
{
	destroy_unrefed(0);
}

void mail_index_alloc_cache_unref(struct mail_index **_index)
{
	struct mail_index *index = *_index;
	struct mail_index_alloc_cache_list *list, **listp;

	*_index = NULL;
	list = NULL;
	for (listp = &indexes; *listp != NULL; listp = &(*listp)->next) {
		if ((*listp)->index == index) {
			list = *listp;
			break;
		}
	}

	i_assert(list != NULL);
	i_assert(list->refcount > 0);

	list->refcount--;
	list->destroy_time = ioloop_time + INDEX_CACHE_TIMEOUT;

	if (list->refcount == 0 && index->open_count == 0) {
		/* index was already closed. don't even try to cache it. */
		*listp = list->next;
		mail_index_alloc_cache_list_free(list);
	} else if (to_index == NULL) {
		/* Add to root ioloop in case we got here from an inner
		   ioloop which gets destroyed too early. */
		to_index = timeout_add_to(io_loop_get_root(),
					  INDEX_CACHE_TIMEOUT*1000/2,
					  index_removal_timeout, (void *)NULL);
	}
}

void mail_index_alloc_cache_destroy_unrefed(void)
{
	destroy_unrefed(UINT_MAX);
}

void mail_index_alloc_cache_index_opened(struct mail_index *index)
{
	struct mail_index_alloc_cache_list *list =
		MAIL_INDEX_ALLOC_CACHE_CONTEXT(index);
	struct stat st;

	if (list != NULL && list->index_dir_ino == 0 &&
	    !MAIL_INDEX_IS_IN_MEMORY(index)) {
		/* newly created index directory. update its stat. */
		if (stat(index->dir, &st) == 0) {
			list->index_dir_ino = st.st_ino;
			list->index_dir_dev = st.st_dev;
		}
	}
}

void mail_index_alloc_cache_index_closing(struct mail_index *index)
{
	struct mail_index_alloc_cache_list *list =
		MAIL_INDEX_ALLOC_CACHE_CONTEXT(index);

	i_assert(index->open_count > 0);
	if (index->open_count > 1 || list == NULL)
		return;

	if (list->referenced) {
		/* we're closing our referenced index */
		return;
	}
	while (indexes_cache_references_count > INDEX_CACHE_MAX) {
		if (!destroy_unrefed(1)) {
			/* our cache is full already, don't keep more */
			return;
		}
	}
	/* keep the index referenced for caching */
	indexes_cache_references_count++;
	list->referenced = TRUE;
	index->open_count++;
}
