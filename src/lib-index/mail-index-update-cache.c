/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mail-index.h"

#include <unistd.h>

static int cache_record(struct mail_index *index, struct mail_index_record *rec,
			enum mail_data_field cache_fields)
{
	struct mail_index_update *update;
	struct istream *input;
	time_t internal_date;
	int failed, deleted;

	input = index->open_mail(index, rec, &internal_date, &deleted);
	if (input == NULL)
		return deleted;

	cache_fields &= ~rec->data_fields;

	update = index->update_begin(index, rec);
	index->update_field_raw(update, DATA_HDR_INTERNAL_DATE,
				&internal_date, sizeof(internal_date));
	mail_index_update_headers(update, input, cache_fields, NULL, NULL);
	failed = !index->update_end(update);

	i_stream_unref(input);
	return !failed;
}

int mail_index_update_cache(struct mail_index *index)
{
	struct mail_index_record *rec;
	enum mail_data_field cache_fields;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	cache_fields = index->header->cache_fields;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		if (((enum mail_data_field)rec->data_fields & cache_fields) !=
		    cache_fields) {
			t_push();
			if (!cache_record(index, rec, cache_fields)) {
				t_pop();
				return FALSE;
			}
			t_pop();
		}

		rec = index->next(index, rec);
	}

	index->header->flags &= ~MAIL_INDEX_FLAG_CACHE_FIELDS;
	return TRUE;
}
