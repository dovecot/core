/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"
#include "index-storage.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define LOCK_NOTIFY_INTERVAL 30

struct index_list {
	struct index_list *next;

	struct mail_index *index;
	int refcount;
};

static struct index_list *indexes = NULL;

void index_storage_add(struct mail_index *index)
{
	struct index_list *list;

	list = i_new(struct index_list, 1);
	list->refcount = 1;
	list->index = index;

	list->next = indexes;
	indexes = list;
}

struct mail_index *index_storage_lookup_ref(const char *path)
{
	struct index_list *list;
	struct stat st1, st2;

	if (stat(path, &st1) < 0)
		return NULL;

	/* compare inodes so we don't break even with symlinks */
	for (list = indexes; list != NULL; list = list->next) {
		if (stat(list->index->dir, &st2) == 0) {
			if (st1.st_ino == st2.st_ino &&
			    st1.st_dev == st2.st_dev) {
				list->refcount++;
				return list->index;
			}
		}
	}

	return NULL;
}

void index_storage_unref(struct mail_index *index)
{
	struct index_list **list, *rec;

	for (list = &indexes; *list != NULL; list = &(*list)->next) {
		rec = *list;

		if (rec->index == index) {
			if (--rec->refcount == 0) {
				index->free(index);
				*list = rec->next;
				i_free(rec);
			}
			return;
		}
	}

	i_unreached();
}

static enum mail_data_field get_data_fields(const char *fields)
{
	static const char *field_names[] = {
		"Location",
		"Envelope",
		"Body",
		"Bodystructure",
		"MD5",
		"MessagePart",
		NULL
	};

	const char *const *arr;
	enum mail_data_field ret;
	int i;

	if (fields == NULL || *fields == '\0')
		return 0;

	ret = 0;
	for (arr = t_strsplit(fields, " ,"); *arr != NULL; arr++) {
		if (*arr == '\0')
			continue;

		for (i = 0; field_names[i] != NULL; i++) {
			if (strcasecmp(field_names[i], *arr) == 0) {
				ret |= 1 << i;
				break;
			}
		}
		if (field_names[i] == NULL) {
			i_error("Invalid cache field name '%s', ignoring ",
				*arr);
		}
	}

	return ret;
}

static enum mail_data_field get_default_cache_fields(void)
{
	static enum mail_data_field ret = 0;
	static int ret_set = FALSE;

	if (ret_set)
		return ret;

	ret = get_data_fields(getenv("MAIL_CACHE_FIELDS"));
	ret_set = TRUE;
	return ret;
}

static enum mail_data_field get_never_cache_fields(void)
{
	static enum mail_data_field ret = 0;
	static int ret_set = FALSE;

	if (ret_set)
		return ret;

	ret = get_data_fields(getenv("MAIL_NEVER_CACHE_FIELDS"));
	ret_set = TRUE;
	return ret;
}

static void lock_notify(enum mail_lock_notify_type notify_type,
			unsigned int secs_left, void *context)
{
	struct index_mailbox *ibox = context;
	struct mail_storage *storage = ibox->box.storage;
	const char *str;
	time_t now;

	if ((secs_left % 15) != 0) {
		/* update alarm() so that we get back here around the same
		   time we want the next notify. also try to use somewhat
		   rounded times. this affects only fcntl() locking, dotlock
		   and flock() calls should be calling us constantly */
		alarm(secs_left%15);
	}

	now = time(NULL);
	if (now < ibox->next_lock_notify || secs_left < 15)
		return;

	ibox->next_lock_notify = now + LOCK_NOTIFY_INTERVAL;

	switch (notify_type) {
	case MAIL_LOCK_NOTIFY_MAILBOX_ABORT:
		str = t_strdup_printf("Mailbox is locked, will abort in "
				      "%u seconds", secs_left);
		storage->callbacks->notify_no(&ibox->box, str,
					      storage->callback_context);
		break;
	case MAIL_LOCK_NOTIFY_MAILBOX_OVERRIDE:
		str = t_strdup_printf("Stale mailbox lock file detected, "
				      "will override in %u seconds", secs_left);
		storage->callbacks->notify_ok(&ibox->box, str,
					      storage->callback_context);
		break;
	case MAIL_LOCK_NOTIFY_INDEX_ABORT:
		str = t_strdup_printf("Mailbox index is locked, will abort in "
				      "%u seconds", secs_left);
		storage->callbacks->notify_no(&ibox->box, str,
					      storage->callback_context);
		break;
	}
}

int index_storage_lock(struct index_mailbox *ibox,
		       enum mail_lock_type lock_type)
{
	int ret;

	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;

	/* we have to set/reset this every time, because the same index
	   may be used by multiple IndexMailboxes. */
	ibox->index->set_lock_notify_callback(ibox->index, lock_notify, ibox);
	ret = ibox->index->set_lock(ibox->index, lock_type);
	ibox->index->set_lock_notify_callback(ibox->index, NULL, NULL);

	if (!ret)
		return mail_storage_set_index_error(ibox);

	return TRUE;
}

struct index_mailbox *
index_storage_init(struct mail_storage *storage, struct mailbox *box,
		   struct mail_index *index, const char *name,
		   int readonly, int fast)
{
	struct index_mailbox *ibox;

	i_assert(name != NULL);

	do {
		ibox = i_new(struct index_mailbox, 1);
		ibox->box = *box;

		ibox->box.storage = storage;
		ibox->box.name = i_strdup(name);
		ibox->box.readonly = readonly;
		ibox->box.allow_custom_flags = TRUE;

		ibox->index = index;
		ibox->cache = imap_msgcache_alloc(&index_msgcache_iface);

		ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
		index->set_lock_notify_callback(index, lock_notify, ibox);

		if (!index->opened) {
			/* open the index first */
			index->default_cache_fields =
				get_default_cache_fields();
			index->never_cache_fields =
				get_never_cache_fields();
			if (!index->open_or_create(index, !readonly, fast))
				break;
		}

		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
			break;

		ibox->synced_messages_count =
			mail_index_get_header(index)->messages_count;

		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
			break;

		index->set_lock_notify_callback(index, NULL, NULL);

		return ibox;
	} while (0);

	mail_storage_set_index_error(ibox);
	index_storage_close(&ibox->box);
	return NULL;
}

int index_storage_close(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	index_mailbox_check_remove(ibox);
	imap_msgcache_free(ibox->cache);
	if (ibox->index != NULL)
		index_storage_unref(ibox->index);

	i_free(box->name);
	i_free(box);

	return TRUE;
}

void index_storage_set_callbacks(struct mail_storage *storage,
				 struct mail_storage_callbacks *callbacks,
				 void *context)
{
	memcpy(storage->callbacks, callbacks,
	       sizeof(struct mail_storage_callbacks));
	storage->callback_context = context;
}

int mail_storage_set_index_error(struct index_mailbox *ibox)
{
	switch (ibox->index->get_last_error(ibox->index)) {
	case MAIL_INDEX_ERROR_NONE:
	case MAIL_INDEX_ERROR_INTERNAL:
		mail_storage_set_internal_error(ibox->box.storage);
		break;
	case MAIL_INDEX_ERROR_INCONSISTENT:
		ibox->box.inconsistent = TRUE;
		break;
	case MAIL_INDEX_ERROR_DISKSPACE:
		mail_storage_set_error(ibox->box.storage, "Out of disk space");
		break;
	case MAIL_INDEX_ERROR_INDEX_LOCK_TIMEOUT:
		mail_storage_set_error(ibox->box.storage,
			"Timeout while waiting for lock to index of mailbox %s",
			ibox->box.name);
		break;
	case MAIL_INDEX_ERROR_MAILBOX_LOCK_TIMEOUT:
		mail_storage_set_error(ibox->box.storage,
			"Timeout while waiting for lock to mailbox %s",
			ibox->box.name);
		break;
	}

	index_reset_error(ibox->index);
	return FALSE;
}

int index_mailbox_fix_custom_flags(struct index_mailbox *ibox,
				   enum mail_flags *flags,
                                   const char *custom_flags[])
{
	int ret;

	ret = mail_custom_flags_fix_list(ibox->index->custom_flags,
					 flags, custom_flags,
					 MAIL_CUSTOM_FLAGS_COUNT);
	switch (ret) {
	case 1:
		return TRUE;
	case 0:
		mail_storage_set_error(ibox->box.storage,
			"Maximum number of different custom flags exceeded");
		return FALSE;
	default:
		return mail_storage_set_index_error(ibox);
	}
}

unsigned int index_storage_get_recent_count(struct mail_index *index)
{
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	unsigned int seq;

	hdr = mail_index_get_header(index);
	if (index->first_recent_uid <= 1) {
		/* all are recent */
		return hdr->messages_count;
	}

	/* get the first recent message */
	if (index->first_recent_uid >= hdr->next_uid)
		return 0;

	rec = index->lookup_uid_range(index, index->first_recent_uid,
				      hdr->next_uid - 1, &seq);
	return rec == NULL ? 0 : hdr->messages_count+1 - seq;
}
