/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "index-storage.h"

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly)
{
	IndexMailbox *ibox;
	FlagsFile *flagsfile;
	const char *path;

	i_assert(name != NULL);

	/* open the index first */
	if (!index->open_or_create(index, !readonly)) {
		mail_storage_set_internal_error(storage);
		index->free(index);
		return NULL;
	}

	/* then flags file */
	path = t_strconcat(index->dir, "/", FLAGS_FILE_NAME, NULL);
	flagsfile = flags_file_open_or_create(storage, path);
	if (flagsfile == NULL) {
		index->free(index);
		return NULL;
	}

	ibox = i_new(IndexMailbox, 1);
	ibox->box = *box;

	ibox->box.storage = storage;
	ibox->box.name = i_strdup(name);
	ibox->box.readonly = readonly;

	ibox->index = index;
	ibox->flagsfile = flagsfile;
	ibox->cache = imap_msgcache_alloc(&index_msgcache_iface);

	return ibox;
}

void index_storage_close(Mailbox *box)
{
	IndexMailbox *ibox = (IndexMailbox *) box;

	flags_file_destroy(ibox->flagsfile);
	imap_msgcache_free(ibox->cache);
	ibox->index->free(ibox->index);
	i_free(box->name);
	i_free(box);
}

int mail_storage_set_index_error(IndexMailbox *ibox)
{
	ibox->box.inconsistent =
		ibox->index->is_inconsistency_error(ibox->index);
	mail_storage_set_internal_error(ibox->box.storage);
	index_reset_error(ibox->index);
	return FALSE;
}

static MailFlags get_used_flags(void *context)
{
        IndexMailbox *ibox = context;
	MailIndexRecord *rec;
	MailFlags used_flags;

	used_flags = 0;

	rec = ibox->index->lookup(ibox->index, 1);
	while (rec != NULL) {
		used_flags |= rec->msg_flags;
		rec = ibox->index->next(ibox->index, rec);
	}

	return used_flags;
}

int index_mailbox_fix_custom_flags(IndexMailbox *ibox, MailFlags *flags,
				   const char *custom_flags[])
{
	return flags_file_fix_custom_flags(ibox->flagsfile, flags,
					   custom_flags, get_used_flags, ibox);
}
