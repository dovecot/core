/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
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

	pool = pool_alloconly_create("MailIndexUpdate", 1024);

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

static void get_data_block_sizes(MailIndexUpdate *update,
				 size_t *min_size, size_t *max_size,
				 int *no_grown_fields)
{
	MailIndexDataRecord *rec;
	MailDataField field;
	unsigned int field_min_size;
	int i, field_exists;

	*min_size = *max_size = sizeof(MailIndexDataRecordHeader);
	*no_grown_fields = TRUE;

	rec = mail_index_data_lookup(update->index->data, update->rec, 0);
	for (i = 0, field = 1; field != DATA_FIELD_LAST; i++, field <<= 1) {
		field_exists = rec != NULL && rec->field == field;

		if (update->fields[i] != NULL) {
			/* value was modified - use it */
			field_min_size = MEM_ALIGN(update->field_sizes[i]);
			*min_size += SIZEOF_MAIL_INDEX_DATA + field_min_size;
			*max_size += SIZEOF_MAIL_INDEX_DATA +
				MEM_ALIGN(update->field_sizes[i] +
					  update->field_extra_sizes[i]);

			if (!field_exists ||
			    rec->full_field_size < field_min_size)
				*no_grown_fields = FALSE;
		} else if (field_exists) {
			/* use the old value */
			*min_size += SIZEOF_MAIL_INDEX_DATA +
				rec->full_field_size;
			*max_size += SIZEOF_MAIL_INDEX_DATA +
				rec->full_field_size;
		}

		if (field_exists) {
			rec = mail_index_data_next(update->index->data,
						   update->rec, rec);
		}
	}
}

static size_t get_max_align_size(size_t base, size_t extra, size_t *max_extra)
{
	size_t size;

	size = MEM_ALIGN(base);
	extra -= size - base;
	if (*max_extra < MEM_ALIGN_SIZE || extra == 0)
		return size; /* no extra / extra went into alignment */

	extra = MEM_ALIGN(extra);
	if (extra > *max_extra) {
		/* partial */
		extra = *max_extra & ~(size_t)(MEM_ALIGN_SIZE-1);
		i_assert(extra <= *max_extra);
	}

	*max_extra -= extra;
	return size + extra;
}

/* extra_size is the amount of data in data_size which can be used for
   field_extra_sizes */
static void *create_data_block(MailIndexUpdate *update, size_t data_size,
			       size_t extra_size)
{
        MailIndexDataRecordHeader *dest_hdr;
        MailIndexDataRecord *rec, *destrec;
	MailDataField field;
	Buffer *buf;
	const void *src;
	size_t src_size;
	size_t full_field_size;
	int i;

	i_assert(data_size <= UINT_MAX);

	buf = buffer_create_static_hard(update->pool, data_size);

	/* set header */
	dest_hdr = buffer_append_space(buf, sizeof(*dest_hdr));
	memcpy(dest_hdr, &update->data_hdr, sizeof(*dest_hdr));
	dest_hdr->data_size = data_size;

	/* set fields */
	rec = mail_index_data_lookup(update->index->data, update->rec, 0);
	for (i = 0, field = 1; field != DATA_FIELD_LAST; i++, field <<= 1) {
		if (update->fields[i] != NULL) {
			/* value was modified - use it */
			full_field_size =
				get_max_align_size(update->field_sizes[i],
						   update->field_extra_sizes[i],
						   &extra_size);
			src = update->fields[i];
			src_size = update->field_sizes[i];
		} else if (rec != NULL && rec->field == field) {
			/* use the old value */
			full_field_size = rec->full_field_size;
			src = rec->data;
			src_size = rec->full_field_size;
		} else {
			/* the field doesn't exist, jump to next */
			continue;
		}
		i_assert((full_field_size % MEM_ALIGN_SIZE) == 0);

		destrec = buffer_append_space(buf, SIZEOF_MAIL_INDEX_DATA +
					      full_field_size);
		destrec->field = field;
		destrec->full_field_size = full_field_size;
		memcpy(destrec->data, src, src_size);

		if (rec != NULL && rec->field == field) {
			rec = mail_index_data_next(update->index->data,
						   update->rec, rec);
		}
	}

	return buffer_free_without_data(buf);
}

/* Append all the data at the end of the data file and update 
   the index's data position */
static int update_by_append(MailIndexUpdate *update, size_t data_size,
			    size_t extra_size)
{
	void *mem;
	uoff_t fpos;

	mem = create_data_block(update, data_size, extra_size);

	/* append the data at the end of the data file */
	fpos = mail_index_data_append(update->index->data, mem, data_size);
	if (fpos == 0)
		return FALSE;

	/* the old data is discarded */
	(void)mail_index_data_delete(update->index->data, update->rec);

	/* update index file position - it's mmap()ed so it'll be written
	   into disk when index is unlocked. */
	update->rec->data_position = fpos;
	return TRUE;
}

/* Replace the whole block - assumes there's enough space to do it */
static void update_by_replace_block(MailIndexUpdate *update, size_t extra_size)
{
	MailIndexDataRecordHeader *data_hdr;
	size_t data_size;
	void *mem;

	data_hdr = mail_index_data_lookup_header(update->index->data,
						 update->rec);

	data_size = update->data_hdr.data_size;
	i_assert(data_size == data_hdr->data_size);

	mem = create_data_block(update, data_size, extra_size);
	memcpy(data_hdr, mem, data_size);

	/* clear the extra space. not really needed. */
	memset((char *) data_hdr + data_size, 0,
	       data_hdr->data_size - data_size);

        mail_index_data_mark_modified(update->index->data);
}

/* Replace the modified fields in the file - assumes there's enough
   space to do it */
static void update_by_replace_fields(MailIndexUpdate *update)
{
	MailIndexDataRecordHeader *data_hdr;
	MailIndexDataRecord *rec;
	size_t field_size;
	int index;

	/* update header */
	data_hdr = mail_index_data_lookup_header(update->index->data,
						 update->rec);
	memcpy(data_hdr, &update->data_hdr, sizeof(*data_hdr));

	rec = mail_index_data_lookup(update->index->data, update->rec, 0);
	while (rec != NULL) {
		if (rec->field & update->updated_fields) {
			/* field was changed */
			index = mail_field_get_index(rec->field);
			i_assert(index >= 0);

			field_size = update->field_sizes[index];
			i_assert(field_size <= rec->full_field_size);

			memcpy(rec->data, update->fields[index], field_size);

			/* clear the extra space. not really needed. */
			memset(rec->data + field_size, 0,
			       rec->full_field_size - field_size);
		}

		rec = mail_index_data_next(update->index->data,
					   update->rec, rec);
	}

        mail_index_data_mark_modified(update->index->data);
}

int mail_index_update_end(MailIndexUpdate *update)
{
	MailIndexDataRecordHeader *data_hdr;
	size_t min_size, max_size, extra_size;
	int no_grown_fields, failed = FALSE;

	i_assert(update->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (update->updated_fields != 0) {
		/* if fields don't fit to allocated data block, we have
		   to move it to end of file */
		get_data_block_sizes(update, &min_size, &max_size,
				     &no_grown_fields);
		extra_size = max_size - min_size;

		data_hdr = mail_index_data_lookup_header(update->index->data,
							 update->rec);

		if (no_grown_fields)
			update_by_replace_fields(update);
		else if (data_hdr != NULL && min_size <= data_hdr->data_size)
			update_by_replace_block(update, extra_size);
		else {
			if (!update_by_append(update, max_size, extra_size))
				failed = TRUE;
		}

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
				const void *value, size_t size __attr_unused__)
{
	switch (field) {
	case DATA_HDR_INTERNAL_DATE:
		i_assert(size == sizeof(time_t));
		update->data_hdr.internal_date = *((const time_t *) value);
		break;
	case DATA_HDR_VIRTUAL_SIZE:
		i_assert(size == sizeof(uoff_t));
		update->data_hdr.virtual_size = *((const uoff_t *) value);
		break;
	case DATA_HDR_HEADER_SIZE:
		i_assert(size == sizeof(uoff_t));
		update->data_hdr.header_size = *((const uoff_t *) value);
		break;
	case DATA_HDR_BODY_SIZE:
		i_assert(size == sizeof(uoff_t));
		update->data_hdr.body_size = *((const uoff_t *) value);
		break;
	default:
                i_unreached();
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
				pool_alloconly_create("index envelope", 2048);
		}
		t_push();
		imap_envelope_parse_header(ctx->envelope_pool,
					   &ctx->envelope,
					   t_strndup(name, name_len),
					   value, value_len);
		t_pop();
	}

	if (ctx->header_func != NULL) {
		ctx->header_func(part, name, name_len,
				 value, value_len, ctx->context);
	}
}

void mail_index_update_headers(MailIndexUpdate *update, IStream *input,
                               MailDataField cache_fields,
			       MessageHeaderFunc header_func, void *context)
{
	HeaderUpdateContext ctx;
	MessagePart *part;
	MessageSize hdr_size, body_size;
	Pool pool;
	Buffer *buf;
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
		pool = pool_alloconly_create("index message parser", 2048);

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

		start_offset = input->v_offset;

		if (part == NULL) {
			part = message_parse(pool, input,
					     update_header_func, &ctx);
		} else {
			/* cached, construct the bodystructure using it.
			   also we need to parse the header.. */
			i_stream_seek(input, start_offset);
			message_parse_header(NULL, input, NULL,
					     update_header_func, &ctx);
		}

		/* save sizes */
		hdr_size = part->header_size;
		body_size = part->body_size;

		/* don't save both BODY + BODYSTRUCTURE since BODY can be
		   generated from BODYSTRUCTURE. FIXME: However that takes
		   CPU, maybe this should be configurable (I/O vs. CPU)? */
		if ((cache_fields & DATA_FIELD_BODY) &&
		    ((update->rec->data_fields | cache_fields) &
		     DATA_FIELD_BODYSTRUCTURE) == 0) {
			t_push();
			i_stream_seek(input, start_offset);
			value = imap_part_get_bodystructure(pool, &part,
							    input, FALSE);
			update->index->update_field(update, DATA_FIELD_BODY,
						    value, 0);
			t_pop();
		}

		if (cache_fields & DATA_FIELD_BODYSTRUCTURE) {
			t_push();
			i_stream_seek(input, start_offset);
			value = imap_part_get_bodystructure(pool, &part,
							    input, TRUE);
			update->index->update_field(update,
						    DATA_FIELD_BODYSTRUCTURE,
						    value, 0);
			t_pop();
		}

		if (cache_fields & DATA_FIELD_MESSAGEPART) {
			t_push();
			buf = buffer_create_dynamic(data_stack_pool, 2048,
						    (size_t)-1);
			message_part_serialize(part, buf);

			value = buffer_get_data(buf, &size);
			update->index->update_field_raw(update,
							DATA_FIELD_MESSAGEPART,
							value, size);
			t_pop();
		}

		pool_unref(pool);
	} else {
		message_parse_header(NULL, input, &hdr_size,
				     update_header_func, &ctx);

		body_size.physical_size = input->v_limit - input->v_offset;
		if (body_size.physical_size == 0)
                        body_size.virtual_size = 0;
		else if (update->data_hdr.virtual_size == 0)
			body_size.virtual_size = (uoff_t)-1;
		else {
			body_size.virtual_size =
				update->data_hdr.virtual_size -
				hdr_size.virtual_size;
		}
	}

	if (ctx.envelope != NULL) {
		t_push();
		value = imap_envelope_get_part_data(ctx.envelope);
		update->index->update_field(update, DATA_FIELD_ENVELOPE,
					    value, 0);
		t_pop();

		pool_unref(ctx.envelope_pool);
	}

	/* update physical sizes */
	update->index->update_field_raw(update, DATA_HDR_HEADER_SIZE,
					&hdr_size.physical_size,
					sizeof(hdr_size.physical_size));
	update->index->update_field_raw(update, DATA_HDR_BODY_SIZE,
					&body_size.physical_size,
					sizeof(body_size.physical_size));

	/* update virtual size if we know it */
	if (body_size.virtual_size != (uoff_t)-1) {
		uoff_t virtual_size;

		virtual_size = hdr_size.virtual_size + body_size.virtual_size;
		update->index->update_field_raw(update, DATA_HDR_VIRTUAL_SIZE,
						&virtual_size,
						sizeof(virtual_size));
	}


	/* update binary flags. */
	if (hdr_size.virtual_size == hdr_size.physical_size)
		update->rec->index_flags |= INDEX_MAIL_FLAG_BINARY_HEADER;
	if (body_size.virtual_size == body_size.physical_size)
		update->rec->index_flags |= INDEX_MAIL_FLAG_BINARY_BODY;
}
