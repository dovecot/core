/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"

static int cache_record(MailIndex *index, MailIndexRecord *rec,
			MailField cache_fields)
{
	MailIndexUpdate *update;
	IOBuffer *inbuf;

	inbuf = index->open_mail(index, rec);
	if (inbuf == NULL)
		return FALSE;

	cache_fields &= ~rec->cached_fields;

	update = index->update_begin(index, rec);
	mail_index_update_headers(update, inbuf, cache_fields, NULL, NULL);
	return index->update_end(update);
}

int mail_index_update_cache(MailIndex *index)
{
	MailIndexRecord *rec;
	MailField cache_fields;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	cache_fields = index->header->cache_fields;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if ((rec->cached_fields & cache_fields) != cache_fields) {
			if (!cache_record(index, rec, cache_fields))
				return FALSE;
		}

		rec = index->next(index, rec);
	}

	index->header->flags &= ~MAIL_INDEX_FLAG_CACHE_FIELDS;
	return TRUE;
}
