/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "index-storage.h"

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly)
{
	IndexMailbox *ibox;
	FlagsFile *flagsfile;
	const char *path, *error;

	i_assert(name != NULL);

	/* open the index first */
	if (!index->open_or_create(index, !readonly)) {
		error = index->get_last_error(index);
		if (error == NULL)
			error = "(maildir_open)";
		mail_storage_set_error(storage, "%s", error);

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
	ibox->cache = imap_msgcache_alloc();

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
	const char *error;

	error = ibox->index->get_last_error(ibox->index);
	if (error == NULL)
		error = "(no error message)";

	ibox->box.inconsistent =
		ibox->index->is_inconsistency_error(ibox->index);
	mail_storage_set_error(ibox->box.storage, "%s", error);
	return FALSE;
}

static MailFlags get_used_flags(void *user_data)
{
        IndexMailbox *ibox = user_data;
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
