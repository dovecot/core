/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-modseq.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"

static bool
keyword_lookup(struct mail_index_sync_map_ctx *ctx,
	       const char *keyword_name, unsigned int *idx_r)
{
	struct mail_index_map *map = ctx->view->map;
	const unsigned int *idx_map;
	unsigned int i, count, keyword_idx;

	if (array_is_created(&map->keyword_idx_map) &&
	    mail_index_keyword_lookup(ctx->view->index, keyword_name,
				      &keyword_idx)) {
		/* FIXME: slow. maybe create index -> file mapping as well */
		idx_map = array_get(&map->keyword_idx_map, &count);
		for (i = 0; i < count; i++) {
			if (idx_map[i] == keyword_idx) {
				*idx_r = i;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static buffer_t *
keywords_get_header_buf(struct mail_index_map *map,
			const struct mail_index_ext *ext,
			unsigned int new_count, unsigned int *keywords_count_r,
			size_t *rec_offset_r, size_t *name_offset_root_r,
			size_t *name_offset_r)
{
	buffer_t *buf;
	const struct mail_index_keyword_header *kw_hdr;
	const struct mail_index_keyword_header_rec *kw_rec;
	const char *name;
	struct mail_index_keyword_header new_kw_hdr;
	uint32_t offset;

	kw_hdr = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
	kw_rec = (const void *)(kw_hdr + 1);
	name = (const char *)(kw_rec + kw_hdr->keywords_count);

	if (kw_hdr->keywords_count == 0)
		return NULL;

	i_assert((size_t)(name - (const char *)kw_hdr) < ext->hdr_size);

	new_kw_hdr = *kw_hdr;
	new_kw_hdr.keywords_count += new_count;
	*keywords_count_r = new_kw_hdr.keywords_count;

	offset = kw_rec[kw_hdr->keywords_count-1].name_offset;
	offset += strlen(name + offset) + 1;

	buf = buffer_create_dynamic(pool_datastack_create(), 512);
	buffer_append(buf, &new_kw_hdr, sizeof(new_kw_hdr));
	buffer_append(buf, kw_rec, sizeof(*kw_rec) * kw_hdr->keywords_count);
	*rec_offset_r = buf->used;
	buffer_write(buf, buf->used + sizeof(*kw_rec) * new_count,
		     name, offset);
	*name_offset_root_r = buf->used;
	*name_offset_r = offset;
	return buf;
}

static void keywords_ext_register(struct mail_index_sync_map_ctx *ctx,
				  uint32_t ext_map_idx, uint32_t reset_id,
				  uint32_t hdr_size, uint32_t keywords_count)
{
	buffer_t ext_intro_buf;
	struct mail_transaction_ext_intro *u;
	unsigned char ext_intro_data[sizeof(*u) +
				     sizeof(MAIL_INDEX_EXT_KEYWORDS)-1];

	i_assert(keywords_count > 0);

	buffer_create_data(&ext_intro_buf, ext_intro_data,
			   sizeof(ext_intro_data));

	u = buffer_append_space_unsafe(&ext_intro_buf, sizeof(*u));
	u->ext_id = ext_map_idx;
	u->reset_id = reset_id;
	u->hdr_size = hdr_size;
	u->record_size = (keywords_count + CHAR_BIT - 1) / CHAR_BIT;
	if ((u->record_size % 4) != 0) {
		/* since we aren't properly aligned anyway,
		   reserve one extra byte for future */
		u->record_size++;
	}
	u->record_align = 1;

	if (ext_map_idx == (uint32_t)-1) {
		u->name_size = strlen(MAIL_INDEX_EXT_KEYWORDS);
		buffer_append(&ext_intro_buf, MAIL_INDEX_EXT_KEYWORDS,
			      u->name_size);
	}

	ctx->internal_update = TRUE;
	if (mail_index_sync_ext_intro(ctx, u) < 0)
		i_panic("Keyword extension growing failed");
	ctx->internal_update = FALSE;
}

static void
keywords_header_add(struct mail_index_sync_map_ctx *ctx,
		    const char *keyword_name, unsigned int *keyword_idx_r)
{
	struct mail_index_map *map;
        const struct mail_index_ext *ext = NULL;
	struct mail_index_keyword_header *kw_hdr;
	struct mail_index_keyword_header_rec kw_rec;
	uint32_t ext_map_idx;
	buffer_t *buf = NULL;
	size_t keyword_len, rec_offset, name_offset, name_offset_root;
	unsigned int keywords_count;

	/* if we crash in the middle of writing the header, the
	   keywords are more or less corrupted. avoid that by
	   making sure the header is updated atomically. */
	map = mail_index_sync_get_atomic_map(ctx);

	if (!mail_index_map_lookup_ext(map, MAIL_INDEX_EXT_KEYWORDS,
				       &ext_map_idx))
		ext_map_idx = (uint32_t)-1;
	else {
		/* update existing header */
		ext = array_idx(&map->extensions, ext_map_idx);
		buf = keywords_get_header_buf(map, ext, 1, &keywords_count,
					      &rec_offset, &name_offset_root,
					      &name_offset);
	}

	if (buf == NULL) {
		/* create new / replace broken header */
		const unsigned int initial_keywords_count = 1;

		buf = buffer_create_dynamic(pool_datastack_create(), 512);
		kw_hdr = buffer_append_space_unsafe(buf, sizeof(*kw_hdr));
		kw_hdr->keywords_count = initial_keywords_count;

                keywords_count = kw_hdr->keywords_count;
		rec_offset = buf->used;
		name_offset_root = rec_offset +
			initial_keywords_count * sizeof(kw_rec);
		name_offset = 0;
	}

	/* add the keyword */
	memset(&kw_rec, 0, sizeof(kw_rec));
	kw_rec.name_offset = name_offset;

	keyword_len = strlen(keyword_name) + 1;
	buffer_write(buf, rec_offset, &kw_rec, sizeof(kw_rec));
	buffer_write(buf, name_offset_root, keyword_name, keyword_len);

	rec_offset += sizeof(kw_rec);
	kw_rec.name_offset += keyword_len;
	name_offset_root += keyword_len;

	if ((buf->used % 4) != 0)
		buffer_append_zero(buf, 4 - (buf->used % 4));

	if (ext == NULL || buf->used > ext->hdr_size ||
	    (uint32_t)ext->record_size * CHAR_BIT < keywords_count) {
		/* if we need to grow the buffer, add some padding */
		buffer_append_zero(buf, 128);
		keywords_ext_register(ctx, ext_map_idx,
				      ext == NULL ? 0 : ext->reset_id,
				      buf->used, keywords_count);

		/* map may have changed */
		map = ctx->view->map;

		if (!mail_index_map_lookup_ext(map, MAIL_INDEX_EXT_KEYWORDS,
					       &ext_map_idx))
			i_unreached();
		ext = array_idx(&map->extensions, ext_map_idx);

		i_assert(ext->hdr_size == buf->used);
	}

	buffer_copy(map->hdr_copy_buf, ext->hdr_offset, buf, 0, buf->used);
	map->hdr_base = map->hdr_copy_buf->data;

	if (mail_index_map_parse_keywords(map) < 0)
		i_panic("Keyword update corrupted keywords header");

	*keyword_idx_r = keywords_count - 1;
	i_assert(*keyword_idx_r / CHAR_BIT < ext->record_size);
}

static int
keywords_update_records(struct mail_index_sync_map_ctx *ctx,
			const struct mail_index_ext *ext,
			unsigned int keyword_idx, enum modify_type type,
			uint32_t uid1, uint32_t uid2)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_record *rec;
	unsigned char *data, data_mask;
	unsigned int data_offset;
	uint32_t seq1, seq2;

	i_assert(keyword_idx != (unsigned int)-1);

	if (!mail_index_lookup_seq_range(view, uid1, uid2, &seq1, &seq2))
		return 1;

	mail_index_sync_write_seq_update(ctx, seq1, seq2);
	mail_index_modseq_update_keyword(ctx->modseq_ctx, keyword_idx,
					  seq1, seq2);

	data_offset = keyword_idx / CHAR_BIT;
	data_mask = 1 << (keyword_idx % CHAR_BIT);

	i_assert(data_offset < ext->record_size);
	data_offset += ext->record_offset;

	i_assert(data_offset >= sizeof(struct mail_index_record));

	switch (type) {
	case MODIFY_ADD:
		for (seq1--; seq1 < seq2; seq1++) {
			rec = MAIL_INDEX_MAP_IDX(view->map, seq1);
			data = PTR_OFFSET(rec, data_offset);
			*data |= data_mask;
		}
		break;
	case MODIFY_REMOVE:
		data_mask = ~data_mask;
		for (seq1--; seq1 < seq2; seq1++) {
			rec = MAIL_INDEX_MAP_IDX(view->map, seq1);
			data = PTR_OFFSET(rec, data_offset);
			*data &= data_mask;
		}
		break;
	default:
		i_unreached();
	}
	return 1;
}

int mail_index_sync_keywords(struct mail_index_sync_map_ctx *ctx,
			     const struct mail_transaction_header *hdr,
			     const struct mail_transaction_keyword_update *rec)
{
	struct mail_index_view *view = ctx->view;
	const char *keyword_name;
	const struct mail_index_ext *ext;
	const uint32_t *uid, *end;
	uint32_t seqset_offset, ext_map_idx;
	unsigned int keyword_idx;
	int ret;

	seqset_offset = sizeof(*rec) + rec->name_size;
	if ((seqset_offset % 4) != 0)
		seqset_offset += 4 - (seqset_offset % 4);
	i_assert(seqset_offset < hdr->size);

	uid = CONST_PTR_OFFSET(rec, seqset_offset);
	end = CONST_PTR_OFFSET(rec, hdr->size);

	keyword_name = t_strndup(rec + 1, rec->name_size);
	if (*keyword_name == '\0') {
		mail_index_sync_set_corrupted(ctx,
					      "Trying to use empty keyword");
		return -1;
	}
	if (!keyword_lookup(ctx, keyword_name, &keyword_idx))
		keywords_header_add(ctx, keyword_name, &keyword_idx);

	/* if the keyword wasn't found, the "keywords" extension was created.
	   if it was found, the record size should already be correct, but
	   in case it isn't just fix it ourself. */
	if (!mail_index_map_lookup_ext(view->map, MAIL_INDEX_EXT_KEYWORDS,
				       &ext_map_idx))
		i_unreached();

	ext = array_idx(&view->map->extensions, ext_map_idx);
	if (keyword_idx / CHAR_BIT >= ext->record_size) {
		if (rec->modify_type == MODIFY_REMOVE) {
			/* nothing to do */
			return 1;
		}

		/* grow the record size */
		keywords_ext_register(ctx, ext_map_idx, ext->reset_id,
				      ext->hdr_size,
				      array_count(&view->map->keyword_idx_map));
		if (!mail_index_map_lookup_ext(view->map,
					       MAIL_INDEX_EXT_KEYWORDS,
					       &ext_map_idx))
			i_unreached();
		ext = array_idx(&view->map->extensions, ext_map_idx);
	}

	while (uid+2 <= end) {
		ret = keywords_update_records(ctx, ext, keyword_idx,
					      rec->modify_type,
					      uid[0], uid[1]);
		if (ret <= 0)
			return ret;

		uid += 2;
	}

	return 1;
}

int
mail_index_sync_keywords_reset(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_header *hdr,
			       const struct mail_transaction_keyword_reset *r)
{
	struct mail_index_map *map = ctx->view->map;
	struct mail_index_record *rec;
	const struct mail_index_ext *ext;
	const struct mail_transaction_keyword_reset *end;
	uint32_t ext_map_idx, seq1, seq2;

	if (!mail_index_map_lookup_ext(map, MAIL_INDEX_EXT_KEYWORDS,
				       &ext_map_idx)) {
		/* nothing to do */
		return 1;
	}

	ext = array_idx(&map->extensions, ext_map_idx);
	end = CONST_PTR_OFFSET(r, hdr->size);
	for (; r != end; r++) {
		if (!mail_index_lookup_seq_range(ctx->view, r->uid1, r->uid2,
						 &seq1, &seq2))
			continue;

		mail_index_sync_write_seq_update(ctx, seq1, seq2);
		mail_index_modseq_reset_keywords(ctx->modseq_ctx, seq1, seq2);
		for (seq1--; seq1 < seq2; seq1++) {
			rec = MAIL_INDEX_MAP_IDX(map, seq1);
			memset(PTR_OFFSET(rec, ext->record_offset),
			       0, ext->record_size);
		}
	}
	return 1;
}
