/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"
#include "index-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct _IndexList IndexList;

struct _IndexList {
	IndexList *next;

	MailIndex *index;
	int refcount;
};

static IndexList *indexes = NULL;

void index_storage_add(MailIndex *index)
{
	IndexList *list;

	list = i_new(IndexList, 1);
	list->refcount = 1;
	list->index = index;

	list->next = indexes;
	indexes = list;
}

MailIndex *index_storage_lookup_ref(const char *path)
{
	IndexList *list;
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

void index_storage_unref(MailIndex *index)
{
	IndexList **list, *rec;

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

static MailDataField get_data_fields(const char *fields)
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

	char *const *arr;
	MailDataField ret;
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

static MailDataField get_default_cache_fields(void)
{
	static MailDataField ret = 0;
	static int ret_set = FALSE;

	if (ret_set)
		return ret;

	ret = get_data_fields(getenv("MAIL_CACHE_FIELDS"));
	ret_set = TRUE;
	return ret;
}

static MailDataField get_never_cache_fields(void)
{
	static MailDataField ret = 0;
	static int ret_set = FALSE;

	if (ret_set)
		return ret;

	ret = get_data_fields(getenv("MAIL_NEVER_CACHE_FIELDS"));
	ret_set = TRUE;
	return ret;
}

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly, int fast)
{
	IndexMailbox *ibox;
	MailIndexHeader *hdr;
	unsigned int messages;

	i_assert(name != NULL);

	do {
		if (!index->opened) {
			/* open the index first */
			index->default_cache_fields =
				get_default_cache_fields();
			index->never_cache_fields =
				get_never_cache_fields();
			if (!index->open_or_create(index, !readonly, fast))
				break;
		}

		/* Get the synced messages count */
		if (!index->set_lock(index, MAIL_LOCK_SHARED))
			break;

		hdr = mail_index_get_header(index);
		messages = hdr->messages_count;

		if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
			break;

		ibox = i_new(IndexMailbox, 1);
		ibox->box = *box;

		ibox->box.storage = storage;
		ibox->box.name = i_strdup(name);
		ibox->box.readonly = readonly;
		ibox->box.allow_custom_flags = TRUE;

		ibox->index = index;
		ibox->cache = imap_msgcache_alloc(&index_msgcache_iface);
		ibox->synced_messages_count = messages;

		return ibox;
	} while (0);

	mail_storage_set_internal_error(storage);
	index_storage_unref(index);
	return NULL;
}

int index_storage_close(Mailbox *box)
{
	IndexMailbox *ibox = (IndexMailbox *) box;

	index_mailbox_check_remove(ibox);
	imap_msgcache_free(ibox->cache);
	index_storage_unref(ibox->index);
	i_free(box->name);
	i_free(box);

	return TRUE;
}

void index_storage_set_sync_callbacks(Mailbox *box,
				      MailboxSyncCallbacks *callbacks,
				      void *context)
{
	IndexMailbox *ibox = (IndexMailbox *) box;

	memcpy(&ibox->sync_callbacks, callbacks, sizeof(MailboxSyncCallbacks));
	ibox->sync_context = context;
}

int mail_storage_set_index_error(IndexMailbox *ibox)
{
	ibox->box.inconsistent =
		ibox->index->is_inconsistency_error(ibox->index);

	if (ibox->index->is_diskspace_error(ibox->index))
		mail_storage_set_error(ibox->box.storage, "Out of disk space");
	else
		mail_storage_set_internal_error(ibox->box.storage);
	index_reset_error(ibox->index);
	return FALSE;
}

int index_mailbox_fix_custom_flags(IndexMailbox *ibox, MailFlags *flags,
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
		mail_storage_set_error(ibox->box.storage, "Maximum number of "
				       "different custom flags exceeded");
		return FALSE;
	default:
		return mail_storage_set_index_error(ibox);
	}
}

unsigned int index_storage_get_recent_count(MailIndex *index)
{
	MailIndexHeader *hdr;
	MailIndexRecord *rec;
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
