/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"
#include "index-storage.h"

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly)
{
	IndexMailbox *ibox;

	i_assert(name != NULL);

	/* open the index first */
	if (!index->open_or_create(index, !readonly)) {
		mail_storage_set_internal_error(storage);
		index->free(index);
		return NULL;
	}

	ibox = i_new(IndexMailbox, 1);
	ibox->box = *box;

	ibox->box.storage = storage;
	ibox->box.name = i_strdup(name);
	ibox->box.readonly = readonly;

	ibox->index = index;
	ibox->cache = imap_msgcache_alloc(&index_msgcache_iface);

	return ibox;
}

void index_storage_close(Mailbox *box)
{
	IndexMailbox *ibox = (IndexMailbox *) box;

	imap_msgcache_free(ibox->cache);
	ibox->index->free(ibox->index);
	i_free(box->name);
	i_free(box);
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
