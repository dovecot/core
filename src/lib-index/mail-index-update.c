/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "ioloop.h"
#include "rfc822-date.h"
#include "rfc822-tokenize.h"
#include "message-parser.h"
#include "message-part-serialize.h"
#include "message-size.h"
#include "imap-envelope.h"
#include "imap-bodystructure.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

struct _MailIndexUpdate {
	Pool pool;

	MailIndex *index;
	MailIndexRecord *rec;

	unsigned int updated_fields;
	void *fields[FIELD_TYPE_MAX_BITS];
	size_t field_sizes[FIELD_TYPE_MAX_BITS];
	size_t field_extra_sizes[FIELD_TYPE_MAX_BITS];
};

MailIndexUpdate *mail_index_update_begin(MailIndex *index, MailIndexRecord *rec)
{
	Pool pool;
	MailIndexUpdate *update;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	pool = pool_create("MailIndexUpdate", 1024, FALSE);

	update = p_new(pool, MailIndexUpdate, 1);
	update->pool = pool;
	update->index = index;
	update->rec = rec;
	return update;
}

static int mail_field_get_index(MailField field)
{
	unsigned int i, mask;

	for (i = 0, mask = 1; i < FIELD_TYPE_MAX_BITS; i++, mask <<= 1) {
		if (field == mask)
			return i;
	}

	return -1;
}

static int have_new_fields(MailIndexUpdate *update)
{
	MailField field;

	if (update->rec->cached_fields == 0) {
		/* new record */
		return TRUE;
	}

	for (field = 1; field != FIELD_TYPE_LAST; field <<= 1) {
		if ((update->updated_fields & field) &&
		    (update->rec->cached_fields & field) == 0)
			return TRUE;
	}

	return FALSE;
}

static int have_too_large_fields(MailIndexUpdate *update)
{
	MailIndexDataRecord *rec;
	unsigned int size_left;
	int index;

	size_left = update->rec->data_size;

	/* start from the first data field - it's required to exist */
	rec = mail_index_data_lookup(update->index->data, update->rec, 1);
	while (rec != NULL) {
		if (rec->full_field_size > size_left) {
			/* corrupted */
			update->index->header->flags |= MAIL_INDEX_FLAG_REBUILD;
			return TRUE;
		}
		size_left -= rec->full_field_size;

		if (rec->field & update->updated_fields) {
			/* field was changed */
			index = mail_field_get_index(rec->field);
			i_assert(index >= 0);

			if (update->field_sizes[index] +
			    update->field_extra_sizes[index] >
			    rec->full_field_size)
				return TRUE;
		}
		rec = mail_index_data_next(update->index->data,
					   update->rec, rec);
	}

	return FALSE;
}

/* Append all the data at the end of the data file and update 
   the index's data position */
static int update_by_append(MailIndexUpdate *update)
{
        MailIndexDataRecord *rec, *destrec;
	MailField field;
	uoff_t fpos;
	void *mem;
	const void *src;
	size_t max_size, pos, src_size;
	int i;

	/* allocate the old size + also the new size of all changed or added
	   fields. this is more than required, but it's much easier than
	   calculating the exact size.

	   If this calculation overflows (no matter what value), it doesn't
	   really matter as it's later checked anyway. */
	max_size = update->rec->data_size;
	for (i = 0; i < FIELD_TYPE_MAX_BITS; i++) {
		max_size += SIZEOF_MAIL_INDEX_DATA +
			update->field_sizes[i] +
			update->field_extra_sizes[i] + MEM_ALIGN_SIZE-1;
	}

	if (max_size > INT_MAX) {
		/* rec->data_size most likely corrupted */
		index_set_corrupted(update->index,
				    "data_size points outside file");
		return FALSE;
	}

	/* allocate two extra records to avoid overflows in case of bad
	   rec->full_field_size which itself fits into max_size, but
	   either the record part would make it point ouside allocate memory,
	   or the next field's record would do that */
	mem = p_malloc(update->pool, max_size + sizeof(MailIndexDataRecord)*2);
	pos = 0;

	rec = mail_index_data_lookup(update->index->data, update->rec, 1);
	for (i = 0, field = 1; field != FIELD_TYPE_LAST; i++, field <<= 1) {
		destrec = (MailIndexDataRecord *) ((char *) mem + pos);

		if (update->fields[i] != NULL) {
			/* value was modified - use it */
			destrec->full_field_size = update->field_sizes[i] +
				update->field_extra_sizes[i];
			src = update->fields[i];
			src_size = update->field_sizes[i];
		} else if (rec != NULL && rec->field == field) {
			/* use the old value */
			destrec->full_field_size = rec->full_field_size;
			src = rec->data;
			src_size = rec->full_field_size;
		} else {
			/* the field doesn't exist, jump to next */
			continue;
		}

		if (src_size > max_size || max_size - src_size < pos) {
			/* corrupted data file - old value had a field
			   larger than expected */
			index_set_corrupted(update->index,
				"full_field_size points outside data_size "
				"(field %u?)", update->index->filepath,
				rec == NULL ? 0 : rec->field);
			return FALSE;
		}
		memcpy(destrec->data, src, src_size);

		/* memory alignment fix */
		destrec->full_field_size = MEM_ALIGN(destrec->full_field_size);

		destrec->field = field;
		pos += DATA_RECORD_SIZE(destrec);

		if (rec != NULL && rec->field == field) {
			rec = mail_index_data_next(update->index->data,
						   update->rec, rec);
		}
	}

	i_assert(pos <= max_size);

	/* append the data at the end of the data file */
	fpos = mail_index_data_append(update->index->data, mem, pos);
	if (fpos == 0)
		return FALSE;

	/* update index file position - it's mmap()ed so it'll be written
	   into disk when index is unlocked. */
	update->rec->data_position = fpos;
	update->rec->data_size = pos;
	return TRUE;
}

/* Replace the modified fields in the file - assumes there's enough
   space to do it */
static void update_by_replace(MailIndexUpdate *update)
{
	MailIndexDataRecord *rec;
	int index;

	/* start from the first data field - it's required to exist */
	rec = mail_index_data_lookup(update->index->data, update->rec, 1);
	while (rec != NULL) {
		if (rec->field & update->updated_fields) {
			/* field was changed */
			index = mail_field_get_index(rec->field);
			i_assert(index >= 0);

			i_assert(update->field_sizes[index] <=
				 rec->full_field_size);

			memcpy(rec->data, update->fields[index],
			       update->field_sizes[index]);
		}
		rec = mail_index_data_next(update->index->data,
					   update->rec, rec);
	}
}

int mail_index_update_end(MailIndexUpdate *update)
{
	int failed = FALSE;

	i_assert(update->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (update->updated_fields != 0) {
		/* if any of the fields were newly added, or have grown larger
		   than their old max. size, we need to move the record to end
		   of file. */
		if (have_new_fields(update) || have_too_large_fields(update))
			failed = !update_by_append(update);
		else
			update_by_replace(update);

		if (!failed) {
			/* update cached fields mask */
			update->rec->cached_fields |= update->updated_fields;
		}
	}

	pool_unref(update->pool);
	return !failed;
}

static void update_field_full(MailIndexUpdate *update, MailField field,
			      const void *value, size_t size,
			      size_t extra_space)
{
	int index;

	index = mail_field_get_index(field);
	i_assert(index >= 0);

	update->updated_fields |= field;
	update->field_sizes[index] = size;
	update->field_extra_sizes[index] = extra_space;
	update->fields[index] = p_malloc(update->pool, size);
	memcpy(update->fields[index], value, size);
}

void mail_index_update_field(MailIndexUpdate *update, MailField field,
			     const char *value, size_t extra_space)
{
	update_field_full(update, field, value, strlen(value) + 1, extra_space);
}

void mail_index_update_field_raw(MailIndexUpdate *update, MailField field,
				 const void *value, size_t size)
{
	update_field_full(update, field, value, size, 0);
}

typedef struct {
	MailIndexUpdate *update;
	Pool envelope_pool;
	MessagePartEnvelopeData *envelope;

	MessageHeaderFunc header_func;
	void *context;
} HeaderUpdateContext;

static void update_header_func(MessagePart *part,
			       const char *name, size_t name_len,
			       const char *value, size_t value_len,
			       void *context)
{
	HeaderUpdateContext *ctx = context;

	if (part != NULL && part->parent != NULL)
		return;

	/* see if we can do anything with this field */
	if (ctx->update->index->header->cache_fields & FIELD_TYPE_ENVELOPE) {
		if (ctx->envelope_pool == NULL) {
			ctx->envelope_pool =
				pool_create("index envelope", 2048, FALSE);
		}
		imap_envelope_parse_header(ctx->envelope_pool,
					   &ctx->envelope,
					   t_strndup(name, name_len),
					   value, value_len);
	}

	if (ctx->header_func != NULL) {
		ctx->header_func(part, name, name_len,
				 value, value_len, ctx->context);
	}
}

void mail_index_update_headers(MailIndexUpdate *update, IBuffer *inbuf,
                               MailField cache_fields,
			       MessageHeaderFunc header_func, void *context)
{
	HeaderUpdateContext ctx;
	MessagePart *part;
	MessageSize hdr_size;
	Pool pool;
	const char *value;
	size_t size;
	uoff_t start_offset;

	ctx.update = update;
	ctx.envelope_pool = NULL;
	ctx.envelope = NULL;
	ctx.header_func = header_func;
	ctx.context = context;

	if (cache_fields == 0)
                cache_fields = update->index->header->cache_fields;

	if (IS_BODYSTRUCTURE_FIELD(cache_fields)) {
		/* for body / bodystructure, we need need to
		   fully parse the message. unless it's already parsed
		   and cached. */
		pool = pool_create("index message parser", 2048, FALSE);

		value = update->index->lookup_field_raw(update->index,
							update->rec,
							FIELD_TYPE_MESSAGEPART,
							&size);
		if (value == NULL)
			part = NULL;
		else {
			part = message_part_deserialize(pool, value, size);
			if (part == NULL) {
				/* corrupted, rebuild it */
				index_set_corrupted(update->index,
					"Corrupted cached MessagePart data");
			}
		}

		start_offset = inbuf->v_offset;

		if (part == NULL) {
			part = message_parse(pool, inbuf,
					     update_header_func, &ctx);
		} else {
			/* cached, construct the bodystructure using it.
			   also we need to parse the header.. */
			i_buffer_seek(inbuf, start_offset);
			message_parse_header(NULL, inbuf, NULL,
					     update_header_func, &ctx);
		}

		/* update our sizes */
		update->rec->header_size = part->header_size.physical_size;
		update->rec->body_size = part->body_size.physical_size;

		if (cache_fields & FIELD_TYPE_BODY) {
			t_push();
			i_buffer_seek(inbuf, start_offset);
			value = imap_part_get_bodystructure(pool, &part,
							    inbuf, FALSE);
			update->index->update_field(update, FIELD_TYPE_BODY,
						    value, 0);
			t_pop();
		}

		if (cache_fields & FIELD_TYPE_BODYSTRUCTURE) {
			t_push();
			i_buffer_seek(inbuf, start_offset);
			value = imap_part_get_bodystructure(pool, &part,
							    inbuf, TRUE);
			update->index->update_field(update,
						    FIELD_TYPE_BODYSTRUCTURE,
						    value, 0);
			t_pop();
		}

		if (cache_fields & FIELD_TYPE_MESSAGEPART) {
			t_push();
			value = message_part_serialize(part, &size);
			update->index->update_field_raw(update,
							FIELD_TYPE_MESSAGEPART,
							value, size);
			t_pop();
		}

		pool_unref(pool);
	} else {
		message_parse_header(NULL, inbuf, &hdr_size,
				     update_header_func, &ctx);

		update->rec->header_size = hdr_size.physical_size;
		update->rec->body_size = inbuf->v_size - inbuf->v_offset;
	}

	if (ctx.envelope != NULL) {
		t_push();
		value = imap_envelope_get_part_data(ctx.envelope);
		update->index->update_field(update, FIELD_TYPE_ENVELOPE,
					    value, 0);
		t_pop();

		pool_unref(ctx.envelope_pool);
	}
}
