/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "ioloop.h"
#include "mail-index.h"
#include "index-storage.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define DEFAULT_NEVER_CACHE_FIELDS "imap.envelope"

/* How many seconds to keep index opened for reuse after it's been closed */
#define INDEX_CACHE_TIMEOUT 10
/* How many closed indexes to keep */
#define INDEX_CACHE_MAX 3

#define LOCK_NOTIFY_INTERVAL 30

struct index_list {
	struct index_list *next;

	struct mail_index *index;
	char *mailbox_path;
	int refcount;

	dev_t index_dir_dev;
	ino_t index_dir_ino;

	time_t destroy_time;
};

static struct index_list *indexes = NULL;
static struct timeout *to_index = NULL;
static int index_storage_refcount = 0;

void index_storage_init(struct index_storage *storage __attr_unused__)
{
	index_storage_refcount++;
}

void index_storage_deinit(struct index_storage *storage)
{
	i_free(storage->storage.error);

	if (--index_storage_refcount > 0)
		return;

        index_storage_destroy_unrefed();
}

static void index_storage_add(struct mail_index *index,
			      const char *mailbox_path, struct stat *st)
{
	struct index_list *list;

	list = i_new(struct index_list, 1);
	list->refcount = 1;
	list->index = index;

	list->mailbox_path = i_strdup(mailbox_path);
	list->index_dir_dev = st->st_dev;
	list->index_dir_ino = st->st_ino;

	list->next = indexes;
	indexes = list;
}

static void index_list_free(struct index_list *list)
{
	mail_index_free(list->index);
	i_free(list->mailbox_path);
	i_free(list);
}

struct mail_index *
index_storage_alloc(const char *index_dir, const char *mailbox_path,
		    const char *prefix)
{
	struct index_list **list, *rec;
	struct mail_index *index;
	struct stat st;
	int destroy_count;

	if (index_dir == NULL || stat(index_dir, &st) < 0)
		memset(&st, 0, sizeof(st));

	/* compare index_dir inodes so we don't break even with symlinks.
	   for in-memory indexes compare just mailbox paths */
	destroy_count = 0; index = NULL;
	for (list = &indexes; *list != NULL;) {
		rec = *list;

		if ((index_dir != NULL && st.st_ino == rec->index_dir_ino &&
		     CMP_DEV_T(st.st_dev, rec->index_dir_dev)) ||
		    (index_dir == NULL && st.st_ino == 0 &&
		     strcmp(mailbox_path, rec->mailbox_path) == 0)) {
			rec->refcount++;
			index = rec->index;
		}

		if (rec->refcount == 0) {
			if (rec->destroy_time <= ioloop_time ||
			    destroy_count >= INDEX_CACHE_MAX) {
				*list = rec->next;
				index_list_free(rec);
				continue;
			} else {
				destroy_count++;
			}
		}

                list = &(*list)->next;
	}

	if (index == NULL) {
		index = mail_index_alloc(index_dir, prefix);
		index_storage_add(index, mailbox_path, &st);
	}

	return index;
}

static void destroy_unrefed(int all)
{
	struct index_list **list, *rec;

	for (list = &indexes; *list != NULL;) {
		rec = *list;

		if (rec->refcount == 0 &&
		    (all || rec->destroy_time <= ioloop_time)) {
			*list = rec->next;
			index_list_free(rec);
		} else {
			list = &(*list)->next;
		}
	}

	if (indexes == NULL && to_index != NULL) {
		timeout_remove(to_index);
		to_index = NULL;
	}
}

static void index_removal_timeout(void *context __attr_unused__)
{
	destroy_unrefed(FALSE);
}

void index_storage_unref(struct mail_index *index)
{
	struct index_list *list;

	for (list = indexes; list != NULL; list = list->next) {
		if (list->index == index)
			break;
	}

	i_assert(list != NULL);
	i_assert(list->refcount > 0);

	list->refcount--;
	list->destroy_time = ioloop_time + INDEX_CACHE_TIMEOUT;
	if (to_index == NULL)
		to_index = timeout_add(1000, index_removal_timeout, NULL);
}

void index_storage_destroy_unrefed(void)
{
	destroy_unrefed(TRUE);
}

static void set_cache_decisions(const char *set, const char *fields,
				enum mail_cache_decision_type dec)
{
	const char *const *arr;
	int i;

	if (fields == NULL || *fields == '\0')
		return;

	for (arr = t_strsplit_spaces(fields, " ,"); *arr != NULL; arr++) {
		for (i = 0; i < MAIL_CACHE_FIELD_COUNT; i++) {
			if (strcasecmp(cache_fields[i].name, *arr) == 0) {
				cache_fields[i].decision = dec;
				break;
			}
		}
		if (i == MAIL_CACHE_FIELD_COUNT) {
			i_error("%s: Invalid cache field name '%s', ignoring ",
				set, *arr);
		}
	}
}

static void index_cache_register_defaults(struct mail_cache *cache)
{
	const char *never_env;

	never_env = getenv("MAIL_NEVER_CACHE_FIELDS");
	if (never_env == NULL)
		never_env = DEFAULT_NEVER_CACHE_FIELDS;

	set_cache_decisions("mail_cache_fields", getenv("MAIL_CACHE_FIELDS"),
			    MAIL_CACHE_DECISION_TEMP);
	set_cache_decisions("mail_never_cache_fields", never_env,
			    MAIL_CACHE_DECISION_NO |
			    MAIL_CACHE_DECISION_FORCED);

	mail_cache_register_fields(cache, cache_fields,
				   MAIL_CACHE_FIELD_COUNT);
}

void index_storage_lock_notify(struct index_mailbox *ibox,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left)
{
	struct index_storage *storage = ibox->storage;
	const char *str;
	time_t now;

	/* if notify type changes, print the message immediately */
	now = time(NULL);
	if (ibox->last_notify_type == MAILBOX_LOCK_NOTIFY_NONE ||
	    ibox->last_notify_type == notify_type) {
		if (ibox->last_notify_type == MAILBOX_LOCK_NOTIFY_NONE &&
		    notify_type == MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE) {
			/* first override notification, show it */
		} else {
			if (now < ibox->next_lock_notify || secs_left < 15)
				return;
		}
	}

	ibox->next_lock_notify = now + LOCK_NOTIFY_INTERVAL;
        ibox->last_notify_type = notify_type;

	switch (notify_type) {
	case MAILBOX_LOCK_NOTIFY_NONE:
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT:
		str = t_strdup_printf("Mailbox is locked, will abort in "
				      "%u seconds", secs_left);
		storage->callbacks->notify_no(&ibox->box, str,
					      storage->callback_context);
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE:
		str = t_strdup_printf("Stale mailbox lock file detected, "
				      "will override in %u seconds", secs_left);
		storage->callbacks->notify_ok(&ibox->box, str,
					      storage->callback_context);
		break;
	}
}

void index_storage_lock_notify_reset(struct index_mailbox *ibox)
{
	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	ibox->last_notify_type = MAILBOX_LOCK_NOTIFY_NONE;
}

struct index_mailbox *
index_storage_mailbox_init(struct index_storage *storage, struct mailbox *box,
			   struct mail_index *index, const char *name,
			   enum mailbox_open_flags flags)
{
	struct index_mailbox *ibox;
	enum mail_index_open_flags index_flags;

	i_assert(name != NULL);

	index_flags = MAIL_INDEX_OPEN_FLAG_CREATE;
	if ((flags & MAILBOX_OPEN_FAST) != 0)
		index_flags |= MAIL_INDEX_OPEN_FLAG_FAST;
	if (getenv("MMAP_DISABLE") != NULL)
		index_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
#ifndef MMAP_CONFLICTS_WRITE
	if (getenv("MMAP_NO_WRITE") != NULL)
#endif
		index_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_NO_WRITE;
	if (getenv("FCNTL_LOCKS_DISABLE") != NULL)
		index_flags |= MAIL_INDEX_OPEN_FLAG_FCNTL_LOCKS_DISABLE;

	do {
		ibox = i_new(struct index_mailbox, 1);
		ibox->box = *box;
		ibox->storage = storage;

		ibox->box.storage = &storage->storage;
		ibox->box.name = i_strdup(name);
		ibox->readonly = (flags & MAILBOX_OPEN_READONLY) != 0;
		ibox->keep_recent = (flags & MAILBOX_OPEN_KEEP_RECENT) != 0;

		ibox->index = index;

		ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
		ibox->commit_log_file_seq = 0;
		ibox->mail_read_mmaped = getenv("MAIL_READ_MMAPED") != NULL;

		if (mail_index_open(index, index_flags) < 0)
			break;

		ibox->cache = mail_index_get_cache(index);
		index_cache_register_defaults(ibox->cache);
		ibox->view = mail_index_view_open(index);
		return ibox;
	} while (0);

	mail_storage_set_index_error(ibox);
	index_storage_mailbox_free(&ibox->box);
	return NULL;
}

void index_storage_mailbox_free(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	if (ibox->view != NULL)
		mail_index_view_close(ibox->view);

	index_mailbox_check_remove_all(ibox);
	if (ibox->index != NULL)
		index_storage_unref(ibox->index);
	i_free(ibox->path);
	i_free(ibox->control_dir);

	i_free(box->name);
	i_free(box);
}

int index_storage_is_readonly(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	return ibox->readonly;
}

int index_storage_allow_new_keywords(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	/* FIXME: return FALSE if we're full */
	return !ibox->readonly;
}

int index_storage_is_inconsistent(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	return mail_index_view_is_inconsistent(ibox->view);
}

void index_storage_set_callbacks(struct mail_storage *_storage,
				 struct mail_storage_callbacks *callbacks,
				 void *context)
{
	struct index_storage *storage = (struct index_storage *) _storage;

	*storage->callbacks = *callbacks;
	storage->callback_context = context;
}

const char *index_storage_get_last_error(struct mail_storage *storage,
					 int *syntax_error_r)
{
	*syntax_error_r = storage->syntax_error;
	return storage->error;
}

int mail_storage_set_index_error(struct index_mailbox *ibox)
{
	switch (mail_index_get_last_error(ibox->index)) {
	case MAIL_INDEX_ERROR_NONE:
	case MAIL_INDEX_ERROR_INTERNAL:
		mail_storage_set_internal_error(ibox->box.storage);
		break;
	case MAIL_INDEX_ERROR_DISKSPACE:
		mail_storage_set_error(ibox->box.storage, "Out of disk space");
		break;
	}

	if (ibox->view != NULL)
		mail_index_view_unlock(ibox->view);
	mail_index_reset_error(ibox->index);
	return FALSE;
}

int index_mailbox_fix_keywords(struct index_mailbox *ibox,
			       enum mail_flags *flags,
			       const char *keywords[],
			       unsigned int keywords_count)
{
	/*FIXME:int ret;

	ret = mail_keywords_fix_list(ibox->index, flags, keywords,
				     keywords_count);
	switch (ret) {
	case 1:
		return TRUE;
	case 0:
		mail_storage_set_error(ibox->box.storage,
			"Maximum number of different keywords exceeded");
		return FALSE;
	default:
		return mail_storage_set_index_error(ibox);
	}*/
}
