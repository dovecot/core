/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "mail-index.h"

#include <unistd.h>

static int cache_record(MailIndex *index, MailIndexRecord *rec,
			MailDataField cache_fields)
{
	MailIndexUpdate *update;
	IBuffer *inbuf;
	time_t internal_date;
	int failed, deleted;

	inbuf = index->open_mail(index, rec, &internal_date, &deleted);
	if (inbuf == NULL)
		return deleted;

	cache_fields &= ~rec->data_fields;

	update = index->update_begin(index, rec);
	index->update_field_raw(update, DATA_HDR_INTERNAL_DATE,
				&internal_date, sizeof(internal_date));
	mail_index_update_headers(update, inbuf, cache_fields, NULL, NULL);
	failed = !index->update_end(update);

	i_buffer_unref(inbuf);
	return !failed;
}

int mail_index_update_cache(MailIndex *index)
{
	MailIndexRecord *rec;
	MailDataField cache_fields;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	cache_fields = index->header->cache_fields;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if ((rec->data_fields & cache_fields) != cache_fields) {
			if (!cache_record(index, rec, cache_fields))
				return FALSE;
		}

		rec = index->next(index, rec);
	}

	index->header->flags &= ~MAIL_INDEX_FLAG_CACHE_FIELDS;
	return TRUE;
}
