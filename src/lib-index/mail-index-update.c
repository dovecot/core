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
	MailIndexDataRecordHeader data_hdr;

	unsigned int updated_fields;
	void *fields[DATA_FIELD_MAX_BITS];
	size_t field_sizes[DATA_FIELD_MAX_BITS];
	size_t field_extra_sizes[DATA_FIELD_MAX_BITS];
};

MailIndexUpdate *mail_index_update_begin(MailIndex *index, MailIndexRecord *rec)
{
	Pool pool;
	MailIndexUpdate *update;
	MailIndexDataRecordHeader *data_hdr;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	pool = pool_create("MailIndexUpdate", 1024, FALSE);

	update = p_new(pool, MailIndexUpdate, 1);
	update->pool = pool;
	update->index = index;
	update->rec = rec;

	data_hdr = mail_index_data_lookup_header(index->data, rec);
	if (data_hdr != NULL)
		memcpy(&update->data_hdr, data_hdr, sizeof(*data_hdr));
	return update;
}

static int mail_field_get_index(MailDataField field)
{
	unsigned int i, mask;

	for (i = 0, mask = 1; i < DATA_FIELD_MAX_BITS; i++, mask <<= 1) {
		if (field == mask)
			return i;
	}

	return -1;
}

static void get_changed_field_sizes(MailIndexUpdate *update,
				    size_t *min_size, size_t *max_size)
{
	int i;

	for (i = 0; i < DATA_FIELD_MAX_BITS; i++) {
		if (update->fields[i] != NULL) {
			*min_size += SIZEOF_MAIL_INDEX_DATA +
				MEM_ALIGN(update->field_sizes[i]);
			*max_size += SIZEOF_MAIL_INDEX_DATA +
				MEM_ALIGN(update->field_sizes[i] +
					  update->field_extra_sizes[i]);
		}
	}
}

static void get_data_block_sizes(MailIndexUpdate *update,
				 size_t *min_size, size_t *max_size)
{
	MailIndexDataRecord *rec;

	/* first get size of new fields */
	*min_size = *max_size = sizeof(MailIndexDataRecordHeader);
	get_changed_field_sizes(update, min_size, max_size);

	/* then the size of unchanged fields */
	rec = mail_index_data_lookup(update->index->data, update->rec, 0);
	while (rec != NULL) {
		if ((rec->field & update->updated_fields) == 0) {
			*min_size += SIZEOF_MAIL_INDEX_DATA +
				rec->full_field_size;
			*max_size += SIZEOF_MAIL_INDEX_DATA +
				rec->full_field_size;
		}

		rec = mail_index_data_next(update->index->data,
					   update->rec, rec);
	}
}

/* Append all the data at the end of the data file and update 
   the index's data position */
static int update_by_append(MailIndexUpdate *update, size_t data_size)
{
        MailIndexDataRecordHeader *dest_hdr;
        MailIndexDataRecord *rec, *destrec;
	MailDataField field;
	uoff_t fpos;
	void *mem;
	const void *src;
	size_t pos, src_size;
	int i;

	i_assert(data_size <= UINT_MAX);

	mem = p_malloc(update->pool, data_size);

	/* set header */
	dest_hdr = (MailIndexDataRecordHeader *) mem;
	pos = sizeof(MailIndexDataRecordHeader);

	memcpy(dest_hdr, &update->data_hdr, sizeof(*dest_hdr));
	dest_hdr->data_size = data_size;

	/* set fields */
	rec = mail_index_data_lookup(update->index->data, update->rec, 0);
	for (i = 0, field = 1; field != DATA_FIELD_LAST; i++, field <<= 1) {
		destrec = (MailIndexDataRecord *) ((char *) mem + pos);

		if (update->fields[i] != NULL) {
			/* value was modified - use it */
			destrec->full_field_size =
				MEM_ALIGN(update->field_sizes[i] +
					  update->field_extra_sizes[i]);
			src = update->fields[i];
			src_size = update->field_sizes[i];
		} else if (rec != NULL && rec->field == field) {
			/* use the old value */
			destrec->full_field_size = rec->full_field_size;
			src = rec->data;
			src_size = destrec->full_field_size;
		} else {
			/* the field doesn't exist, jump to next */
			continue;
		}
		i_assert((destrec->full_field_size % MEM_ALIGN_SIZE) == 0);

		/* make sure we don't overflow our buffer */
		if (src_size > data_size || data_size - src_size < pos) {
			i_panic("data file for index %s unexpectedly modified",
				update->index->filepath);
		}
		memcpy(destrec->data, src, src_size);

		destrec->field = field;
		pos += DATA_RECORD_SIZE(destrec);

		if (rec != NULL && rec->field == field) {
			rec = mail_index_data_next(update->index->data,
						   update->rec, rec);
		}
	}

	i_assert(pos == data_size);

	/* append the data at the end of the data file */
	fpos = mail_index_data_append(update->index->data, mem, pos);
	if (fpos == 0)
		return FALSE;

	/* the old data is discarded */
	(void)mail_index_data_delete(update->index->data, update->rec);

	/* update index file position - it's mmap()ed so it'll be written
	   into disk when index is unlocked. */
	update->rec->data_position = fpos;
	return TRUE;
}

/* Replace the modified fields in the file - assumes there's enough
   space to do it */
static void update_by_replace(MailIndexUpdate *update)
{
	MailIndexDataRecord *rec;
	int index;

	// FIXME: 1) this doesn't work, 2) we need to handle optimally the
	// writing of extra_space

	rec = mail_index_data_lookup(update->index->data, update->rec, 0);
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

        mail_index_data_mark_modified(update->index->data);
}

int mail_index_update_end(MailIndexUpdate *update)
{
	MailIndexDataRecordHeader *data_hdr;
	size_t min_size, max_size;
	int failed = FALSE;

	i_assert(update->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (update->updated_fields != 0) {
		/* if fields don't fit to allocated data block, we have
		   to move it to end of file */
		get_data_block_sizes(update, &min_size, &max_size);
		data_hdr = mail_index_data_lookup_header(update->index->data,
							 update->rec);

		if (data_hdr != NULL && min_size <= data_hdr->data_size)
			update_by_replace(update);
		else
			failed = !update_by_append(update, max_size);

		if (!failed) {
			/* update cached fields mask */
			update->rec->data_fields |= update->updated_fields;
		}
	}

	pool_unref(update->pool);
	return !failed;
}

static void update_field_full(MailIndexUpdate *update, MailDataField field,
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

static void update_header_field(MailIndexUpdate *update, MailDataField field,
				const void *value, size_t size)
{
	switch (field) {
	case DATA_HDR_INTERNAL_DATE:
		i_assert(size == sizeof(time_t));
		update->data_hdr.internal_date = *((time_t *) value);
		break;
	case DATA_HDR_VIRTUAL_SIZE:
		i_assert(size == sizeof(uoff_t));
		update->data_hdr.virtual_size = *((uoff_t *) value);
		break;
	case DATA_HDR_HEADER_SIZE:
		i_assert(size == sizeof(uoff_t));
		update->data_hdr.header_size = *((uoff_t *) value);
		break;
	case DATA_HDR_BODY_SIZE:
		i_assert(size == sizeof(uoff_t));
		update->data_hdr.body_size = *((uoff_t *) value);
		break;
	default:
		i_assert(0);
	}

	update->updated_fields |= field;
}

void mail_index_update_field(MailIndexUpdate *update, MailDataField field,
			     const char *value, size_t extra_space)
{
	update_field_full(update, field, value, strlen(value) + 1, extra_space);
}

void mail_index_update_field_raw(MailIndexUpdate *update, MailDataField field,
				 const void *value, size_t size)
{
	if (field >= DATA_FIELD_LAST)
		update_header_field(update, field, value, size);
	else
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
	if (ctx->update->index->header->cache_fields & DATA_FIELD_ENVELOPE) {
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
                               MailDataField cache_fields,
			       MessageHeaderFunc header_func, void *context)
{
	HeaderUpdateContext ctx;
	MessagePart *part;
	MessageSize hdr_size;
	Pool pool;
	const char *value;
	size_t size;
	uoff_t start_offset, uoff_size;

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
							DATA_FIELD_MESSAGEPART,
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
		update->index->update_field_raw(update, DATA_HDR_HEADER_SIZE,
			&part->header_size.physical_size,
			sizeof(part->header_size.physical_size));
		update->index->update_field_raw(update, DATA_HDR_BODY_SIZE,
			&part->body_size.physical_size,
			sizeof(part->body_size.physical_size));

		uoff_size = part->header_size.virtual_size +
			part->body_size.virtual_size;
		update->index->update_field_raw(update, DATA_HDR_VIRTUAL_SIZE,
						&uoff_size, sizeof(uoff_size));

		/* don't save both BODY + BODYSTRUCTURE since BODY can be
		   generated from BODYSTRUCTURE. FIXME: However that takes
		   CPU, maybe this should be configurable (I/O vs. CPU)? */
		if ((cache_fields & DATA_FIELD_BODY) &&
		    ((update->rec->data_fields | cache_fields) &
		     DATA_FIELD_BODYSTRUCTURE) == 0) {
			t_push();
			i_buffer_seek(inbuf, start_offset);
			value = imap_part_get_bodystructure(pool, &part,
							    inbuf, FALSE);
			update->index->update_field(update, DATA_FIELD_BODY,
						    value, 0);
			t_pop();
		}

		if (cache_fields & DATA_FIELD_BODYSTRUCTURE) {
			t_push();
			i_buffer_seek(inbuf, start_offset);
			value = imap_part_get_bodystructure(pool, &part,
							    inbuf, TRUE);
			update->index->update_field(update,
						    DATA_FIELD_BODYSTRUCTURE,
						    value, 0);
			t_pop();
		}

		if (cache_fields & DATA_FIELD_MESSAGEPART) {
			t_push();
			value = message_part_serialize(part, &size);
			update->index->update_field_raw(update,
							DATA_FIELD_MESSAGEPART,
							value, size);
			t_pop();
		}

		pool_unref(pool);
	} else {
		message_parse_header(NULL, inbuf, &hdr_size,
				     update_header_func, &ctx);

		update->index->update_field_raw(update, DATA_HDR_HEADER_SIZE,
			&hdr_size.physical_size,
			sizeof(hdr_size.physical_size));

		uoff_size = inbuf->v_size - inbuf->v_offset;
		update->index->update_field_raw(update, DATA_HDR_BODY_SIZE,
						&uoff_size, sizeof(uoff_size));
	}

	if (ctx.envelope != NULL) {
		t_push();
		value = imap_envelope_get_part_data(ctx.envelope);
		update->index->update_field(update, DATA_FIELD_ENVELOPE,
					    value, 0);
		t_pop();

		pool_unref(ctx.envelope_pool);
	}
}
