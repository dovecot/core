/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "ioloop.h"
#include "imap-parser.h"
#include "mkdir-parents.h"
#include "mail-index-private.h"
#include "index-storage.h"
#include "index-mail.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define CREATE_MODE 0770 /* umask() should limit it more */

#define DEFAULT_CACHE_FIELDS ""
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
	mail_index_free(&list->index);
	i_free(list->mailbox_path);
	i_free(list);
}

static int create_index_dir(struct mail_storage *storage, const char *name)
{
	const char *root_dir, *index_dir;

	root_dir = mailbox_list_get_path(storage->list, name,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = mailbox_list_get_path(storage->list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	if (strcmp(index_dir, root_dir) == 0 || *index_dir == '\0')
		return 0;

	if (mkdir_parents(index_dir, CREATE_MODE) < 0 && errno != EEXIST) {
		mail_storage_set_critical(storage, "mkdir(%s) failed: %m",
					  index_dir);
		return -1;
	}

	return 0;
}

static const char *
get_index_dir(struct mail_storage *storage, const char *name,
	      enum mailbox_open_flags flags, struct stat *st_r)
{
	const char *index_dir;

	index_dir = (flags & MAILBOX_OPEN_NO_INDEX_FILES) != 0 ? "" :
		mailbox_list_get_path(storage->list, name,
				      MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*index_dir == '\0') {
		/* disabled */
		return NULL;
	}

	if (stat(index_dir, st_r) < 0) {
		if (errno == ENOENT) {
			/* try to create it */
			if (create_index_dir(storage, name) < 0)
				return NULL;
			if (stat(index_dir, st_r) == 0)
				return index_dir;
		}

		mail_storage_set_critical(storage, "stat(%s) failed: %m",
					  index_dir);
		return NULL;
	}
	return index_dir;
}

struct mail_index *
index_storage_alloc(struct mail_storage *storage, const char *name,
		    enum mailbox_open_flags flags, const char *prefix)
{
	struct index_list **list, *rec;
	struct mail_index *index;
	struct stat st, st2;
	const char *index_dir, *mailbox_path;
	int destroy_count;

	mailbox_path = mailbox_list_get_path(storage->list, name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = get_index_dir(storage, name, flags, &st);

	if (index_dir == NULL)
		memset(&st, 0, sizeof(st));

	/* compare index_dir inodes so we don't break even with symlinks.
	   for in-memory indexes compare just mailbox paths */
	destroy_count = 0; index = NULL;
	for (list = &indexes; *list != NULL;) {
		rec = *list;

		if (index_dir != NULL) {
			if (index == NULL && st.st_ino == rec->index_dir_ino &&
			    CMP_DEV_T(st.st_dev, rec->index_dir_dev)) {
				/* make sure the directory still exists.
				   it might have been renamed and we're trying
				   to access it via its new path now. */
				if (stat(rec->index->dir, &st2) < 0 ||
				    st2.st_ino != st.st_ino ||
				    !CMP_DEV_T(st2.st_dev, st.st_dev))
					rec->destroy_time = 0;
				else {
					rec->refcount++;
					index = rec->index;
				}
			}
		} else {
			if (index == NULL && st.st_ino == 0 &&
			    strcmp(mailbox_path, rec->mailbox_path) == 0) {
				rec->refcount++;
				index = rec->index;
			}
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

static void destroy_unrefed(bool all)
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

	if (indexes == NULL && to_index != NULL)
		timeout_remove(&to_index);
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
	if (to_index == NULL) {
		to_index = timeout_add(INDEX_CACHE_TIMEOUT*1000/2,
				       index_removal_timeout, NULL);
	}
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
		for (i = 0; i < MAIL_INDEX_CACHE_FIELD_COUNT; i++) {
			if (strcasecmp(global_cache_fields[i].name,
				       *arr) == 0) {
				global_cache_fields[i].decision = dec;
				break;
			}
		}
		if (i == MAIL_INDEX_CACHE_FIELD_COUNT) {
			i_error("%s: Invalid cache field name '%s', ignoring ",
				set, *arr);
		}
	}
}

static void index_cache_register_defaults(struct index_mailbox *ibox)
{
	static bool initialized = FALSE;
	struct mail_cache *cache = ibox->cache;
	const char *cache_env, *never_env, *env;

	if (!initialized) {
		initialized = TRUE;

		cache_env = getenv("MAIL_CACHE_FIELDS");
		if (cache_env == NULL)
			cache_env = DEFAULT_CACHE_FIELDS;
		never_env = getenv("MAIL_NEVER_CACHE_FIELDS");
		if (never_env == NULL)
			never_env = DEFAULT_NEVER_CACHE_FIELDS;

		set_cache_decisions("mail_cache_fields", cache_env,
				    MAIL_CACHE_DECISION_TEMP);
		set_cache_decisions("mail_never_cache_fields", never_env,
				    MAIL_CACHE_DECISION_NO |
				    MAIL_CACHE_DECISION_FORCED);

		env = getenv("MAIL_CACHE_MIN_MAIL_COUNT");
		if (env != NULL)
			ibox->mail_cache_min_mail_count = atoi(env);
	}

	ibox->cache_fields = i_malloc(sizeof(global_cache_fields));
	memcpy(ibox->cache_fields, global_cache_fields,
	       sizeof(global_cache_fields));
	mail_cache_register_fields(cache, ibox->cache_fields,
				   MAIL_INDEX_CACHE_FIELD_COUNT);
}

void index_storage_lock_notify(struct index_mailbox *ibox,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left)
{
	struct mail_storage *storage = ibox->box.storage;
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
		if (storage->callbacks->notify_no == NULL)
			break;

		str = t_strdup_printf("Mailbox is locked, will abort in "
				      "%u seconds", secs_left);
		storage->callbacks->notify_no(&ibox->box, str,
					      storage->callback_context);
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE:
		if (storage->callbacks->notify_ok == NULL)
			break;

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

void index_storage_mailbox_open(struct index_mailbox *ibox)
{
	struct mail_storage *storage = ibox->storage;
	enum mail_index_open_flags index_flags = 0;
	int ret;

	i_assert(!ibox->box.opened);

	if (!ibox->move_to_memory)
		index_flags |= MAIL_INDEX_OPEN_FLAG_CREATE;
#ifndef MMAP_CONFLICTS_WRITE
	if ((storage->flags & MAIL_STORAGE_FLAG_MMAP_DISABLE) != 0)
#endif
		index_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	if ((storage->flags & MAIL_STORAGE_FLAG_DOTLOCK_USE_EXCL) != 0)
		index_flags |= MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL;
	if ((storage->flags & MAIL_STORAGE_FLAG_NFS_FLUSH_INDEX) != 0)
		index_flags |= MAIL_INDEX_OPEN_FLAG_NFS_FLUSH;
	if ((storage->flags & MAIL_STORAGE_FLAG_FSYNC_DISABLE) != 0) {
		index_flags |= MAIL_INDEX_OPEN_FLAG_FSYNC_DISABLE;
		ibox->fsync_disable = TRUE;
	}

	ret = mail_index_open(ibox->index, index_flags, storage->lock_method);
	if (ret <= 0 || ibox->move_to_memory) {
		if (mail_index_move_to_memory(ibox->index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now. */
			index_flags |= MAIL_INDEX_OPEN_FLAG_CREATE;
			ret = mail_index_open(ibox->index, index_flags,
					      storage->lock_method);
			if (ret <= 0)
				i_panic("in-memory index creation failed");
		}
	}

	ibox->cache = mail_index_get_cache(ibox->index);
	index_cache_register_defaults(ibox);
	ibox->view = mail_index_view_open(ibox->index);
	ibox->keyword_names = mail_index_get_keywords(ibox->index);

	MODULE_CONTEXT_SET_FULL(ibox->view, mail_storage_mail_index_module,
				ibox, &ibox->view_module_ctx);

	ibox->box.opened = TRUE;
}

void index_storage_mailbox_init(struct index_mailbox *ibox, const char *name,
				enum mailbox_open_flags flags,
				bool move_to_memory)
{
	struct mail_storage *storage = ibox->storage;

	i_assert(name != NULL);

	ibox->box.storage = storage;
	ibox->box.name = p_strdup(ibox->box.pool, name);
	array_create(&ibox->box.module_contexts,
		     ibox->box.pool, sizeof(void *), 5);

	ibox->open_flags = flags;
	ibox->readonly = (flags & MAILBOX_OPEN_READONLY) != 0;
	ibox->keep_recent = (flags & MAILBOX_OPEN_KEEP_RECENT) != 0;
	ibox->keep_locked = (flags & MAILBOX_OPEN_KEEP_LOCKED) != 0;
	ibox->move_to_memory = move_to_memory;

	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	ibox->commit_log_file_seq = 0;

	ibox->md5hdr_ext_idx =
		mail_index_ext_register(ibox->index, "header-md5", 0, 16, 1);

	if ((flags & MAILBOX_OPEN_FAST) == 0)
		index_storage_mailbox_open(ibox);
}

int index_storage_mailbox_close(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	if (ibox->view != NULL)
		mail_index_view_close(&ibox->view);

	index_mailbox_check_remove_all(ibox);
	if (ibox->index != NULL)
		index_storage_unref(ibox->index);
	if (array_is_created(&ibox->recent_flags))
		array_free(&ibox->recent_flags);
	i_free(ibox->cache_fields);

	pool_unref(box->pool);
	return 0;
}

bool index_storage_is_readonly(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	return ibox->readonly;
}

bool index_storage_allow_new_keywords(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	/* FIXME: return FALSE if we're full */
	return !ibox->readonly;
}

bool index_storage_is_inconsistent(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	return mail_index_view_is_inconsistent(ibox->view) ||
		ibox->mailbox_deleted;
}

void mail_storage_set_index_error(struct index_mailbox *ibox)
{
	mail_storage_set_internal_error(ibox->box.storage);
	mail_index_reset_error(ibox->index);
}

int index_mailbox_keyword_is_valid(struct index_mailbox *ibox,
				   const char *keyword, const char **error_r)
{
	unsigned int i, idx;

	/* if it already exists, skip validity checks */
	if (mail_index_keyword_lookup(ibox->index, keyword, &idx))
		return TRUE;

	if (*keyword == '\0') {
		*error_r = "Empty keywords not allowed";
		return FALSE;
	}

	/* these are IMAP-specific restrictions, but for now IMAP is all we
	   care about */
	for (i = 0; keyword[i] != '\0'; i++) {
		if (IS_ATOM_SPECIAL((unsigned char)keyword[i])) {
			*error_r = "Invalid characters in keyword";
			return FALSE;
		}
		if ((unsigned char)keyword[i] >= 0x80) {
			*error_r = "8bit characters in keyword";
			return FALSE;
		}
	}
	if (i > ibox->box.storage->keyword_max_len) {
		*error_r = "Keyword length too long";
		return FALSE;
	}
	return TRUE;
}

static struct mail_keywords *
index_keywords_create_skip(struct index_transaction_context *t,
			   const char *const keywords[])
{
	ARRAY_DEFINE(valid_keywords, const char *);
	struct mail_keywords *kw;
	const char *error;

	t_push();
	t_array_init(&valid_keywords, 32);
	for (; *keywords != NULL; keywords++) {
		if (index_mailbox_keyword_is_valid(t->ibox, *keywords, &error))
			array_append(&valid_keywords, keywords, 1);
	}
	(void)array_append_space(&valid_keywords); /* NULL-terminate */
	kw = mail_index_keywords_create(t->trans, keywords);
	t_pop();
	return kw;
}

int index_keywords_create(struct mailbox_transaction_context *_t,
			  const char *const keywords[],
			  struct mail_keywords **keywords_r, bool skip_invalid)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	const char *error;
	unsigned int i;

	for (i = 0; keywords[i] != NULL; i++) {
		if (!index_mailbox_keyword_is_valid(t->ibox, keywords[i],
						    &error)) {
			if (skip_invalid) {
				/* found invalid keywords, do this the slow
				   way */
				*keywords_r =
					index_keywords_create_skip(t, keywords);
				return 0;
			}
			mail_storage_set_error(t->ibox->box.storage,
					       MAIL_ERROR_PARAMS, error);
			return -1;
		}
	}

	*keywords_r = mail_index_keywords_create(t->trans, keywords);
	return 0;
}

void index_keywords_free(struct mailbox_transaction_context *t __attr_unused__,
			 struct mail_keywords *keywords)
{
	mail_index_keywords_free(&keywords);
}
